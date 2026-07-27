package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"github.com/beshkenadze/agentvault/internal/backend/agefile"
	"github.com/beshkenadze/agentvault/internal/client"
	"github.com/beshkenadze/agentvault/internal/sopsplugin"
)

// pluginTimeout bounds one decryption through the plugin. Exceeding it is a FAILURE, not a
// slow machine: the thing being ruled out is a plugin that blocks waiting for a human, and
// a blocked plugin stalls sops, which stalls `helm secrets`, with no way for an agent to
// recover. Generous enough (30s) that a cold daemon autostart never trips it.
const pluginTimeout = 30 * time.Second

// exeName gives a binary the suffix Windows needs. age resolves plugins with
// exec.LookPath, which on Windows consults PATHEXT — an extension-less age-plugin-av is
// simply not found there. Nothing else in this file is platform-specific, so it CAN supply
// Windows evidence, but only when someone runs it on Windows; `make cross-test` compiles
// for windows/amd64 and does not execute, so that platform stays unverified.
func exeName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// buildAndSeed stands up the whole real chain: it builds the REAL avd and the REAL
// age-plugin-av, puts the plugin on PATH under the name age discovers it by, seeds one SOPS
// identity per entry in ids through the REAL Store, and points the environment at the
// daemon so the plugin's own socket lookup finds it. Nothing here is a stub except the
// presence check (AV_TEST_AUTH=allow), which stands in for Touch ID.
//
// It returns the socket path (so a test can drive the session's lock state directly) and
// the RECIPIENT of each seeded identity — public keys, the only half of a stored identity
// that ever leaves the daemon.
func buildAndSeed(t *testing.T, ids map[string]sopsplugin.Tier) (sockPath string, recipients map[string]*age.X25519Recipient) {
	t.Helper()

	// The socket lives under XDG_RUNTIME_DIR and a unix socket path is capped at ~104
	// bytes, so the temp dir has to be SHORT — macOS's default /var/folders/... blows the
	// limit before the test can say anything useful. internal/client/e2e_test.go pins /tmp
	// for the same reason. Windows uses a named pipe with no such cap, and has no /tmp.
	base := "/tmp"
	if runtime.GOOS == "windows" {
		base = ""
	}
	dir, err := os.MkdirTemp(base, "avp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	avd := filepath.Join(dir, exeName("avd"))
	if out, buildErr := exec.Command("go", "build", "-o", avd, "github.com/beshkenadze/agentvault/cmd/avd").CombinedOutput(); buildErr != nil {
		t.Fatalf("build avd: %v\n%s", buildErr, out)
	}

	// The plugin is built under the name age DISCOVERS it by, derived from PluginName
	// rather than spelled out — the same single source main.go uses. A rename that reached
	// only one of the two would surface as "no identity matched", never as a missing file.
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pluginBin := filepath.Join(binDir, exeName("age-plugin-"+sopsplugin.PluginName))
	if out, buildErr := exec.Command("go", "build", "-o", pluginBin, ".").CombinedOutput(); buildErr != nil {
		t.Fatalf("build age-plugin-av: %v\n%s", buildErr, out)
	}

	// The VAULT's identity, distinct from the SOPS identities stored inside it. The test
	// holds it in plaintext so it can seed through the Store; avd loads the same file.
	vaultID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	idPath := filepath.Join(dir, "id.txt")
	if err := os.WriteFile(idPath, []byte(vaultID.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(dir, "vault.age")
	vf, err := os.Create(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := agefile.EncryptVault(vf, vaultID.Recipient(), map[string]string{}); err != nil {
		vf.Close()
		t.Fatal(err)
	}
	if err := vf.Close(); err != nil {
		t.Fatal(err)
	}

	// Seeded through the REAL Store, so the entries are byte-for-byte what `av sops` writes
	// and what the daemon's FindByRecipient scans. A hand-rolled envelope here could pass
	// while production disagreed about the stored format.
	be := agefile.New(agefile.Static{ID: vaultID}, vaultPath)
	store := sopsplugin.NewStore(be, be)
	recipients = make(map[string]*age.X25519Recipient, len(ids))
	for name, tier := range ids {
		key, keyErr := age.GenerateX25519Identity()
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		if putErr := store.Put(name, key, tier); putErr != nil {
			// SECURITY: name and tier only. key is a private key and is in scope here.
			t.Fatalf("seed sops identity %q (tier %s): %v", name, tier, putErr)
		}
		recipients[name] = key.Recipient()
	}

	t.Setenv("AV_AVD_PATH", avd)
	t.Setenv("XDG_RUNTIME_DIR", dir) // both this process and the spawned plugin resolve the socket under it
	t.Setenv("AV_AGE_IDENTITY", idPath)
	t.Setenv("AV_AGE_VAULT", vaultPath)
	t.Setenv("AV_TEST_AUTH", "allow") // stub presence: unlock without a real Touch ID
	// PATH is how age finds the plugin at all — this is the discovery mechanism under test,
	// not test plumbing.
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	sockPath = filepath.Join(dir, "agentvault", "avd.sock")
	t.Cleanup(func() {
		_ = exec.Command("pkill", "-f", avd).Run()
		_ = os.Remove(sockPath)
		_ = os.Remove(sockPath + ".lock")
	})
	return sockPath, recipients
}

// encryptTo age-encrypts payload to r through the ORDINARY age API — no plugin, no
// AgentVault, on the write side. That is the property the whole design rests on: SOPS files
// keep their normal age1... recipients, so Flux, CI, and teammates decrypt them unchanged
// and only the developer's identity string changes.
func encryptTo(t *testing.T, r *age.X25519Recipient, payload string) []byte {
	t.Helper()
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return ct.Bytes()
}

// decryptThroughPlugin decrypts ct with one AGE-PLUGIN-AV-1... identity per recipient in
// rs, which makes age exec the real age-plugin-av off PATH and speak identity-v1 to it. It
// is the full production path minus sops itself.
//
// rs is variadic because the ORDER and COUNT are the subject of a test: age tries
// identities in sequence and gives up on the first hard error, so passing two models a
// keys.txt with two AgentVault pointers — the ordinary personal-key-plus-team-key setup
// `av sops import` produces — and proves the first one's refusal does not decide the file.
//
// The wait is BOUNDED. A plugin that blocks on a presence prompt is the failure mode this
// binary exists to avoid, and an unbounded wait would report it as a hung test suite ten
// minutes later instead of as the bug it is.
func decryptThroughPlugin(t *testing.T, ct []byte, rs ...*age.X25519Recipient) (string, error) {
	t.Helper()

	// Every UI callback errors. The plugin must never interact — that is the point of
	// threading AV_NO_PROMPT — so an unexpected prompt becomes a named failure here rather
	// than a silent hang or an opaque "fail" stanza.
	ui := &plugin.ClientUI{
		DisplayMessage: func(name, message string) error {
			return fmt.Errorf("unexpected message from plugin %q: %s", name, message)
		},
		RequestValue: func(name, _ string, _ bool) (string, error) {
			return "", fmt.Errorf("unexpected value request from plugin %q", name)
		},
		Confirm: func(name, _, _, _ string) (bool, error) {
			return false, fmt.Errorf("unexpected confirmation request from plugin %q", name)
		},
	}
	ids := make([]age.Identity, 0, len(rs))
	for _, r := range rs {
		id, err := plugin.NewIdentity(sopsplugin.EncodeIdentity(r), ui)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}

	type outcome struct {
		text string
		err  error
	}
	// Buffered: on a timeout this goroutine is abandoned, and it must not block forever on
	// a send nobody will receive.
	done := make(chan outcome, 1)
	go func() {
		out, decErr := age.Decrypt(bytes.NewReader(ct), ids...)
		if decErr != nil {
			done <- outcome{err: decErr}
			return
		}
		b, readErr := io.ReadAll(out)
		done <- outcome{text: string(b), err: readErr}
	}()
	select {
	case res := <-done:
		return res.text, res.err
	case <-time.After(pluginTimeout):
		t.Fatalf("age-plugin-av did not return within %s: a blocked plugin stalls sops, and through sops, helm", pluginTimeout)
		return "", nil
	}
}

// TestAgePluginAvEndToEnd is Task 1's spike pointed at the production chain: a real avd, a
// real age-plugin-av found on PATH by filename, an identity seeded through the real Store,
// and a file encrypted to a plain age1... recipient by ordinary age.
//
// The subtests run in order and each sets the session state it needs (Lock/Unlock) instead
// of inheriting one, so any of them can be run alone with -run.
//
// SECURITY: no assertion here may print the per-file key. It never reaches this test —
// age.Decrypt consumes it internally — and nothing below reconstructs it.
func TestAgePluginAvEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: builds avd and age-plugin-av, spawns the real daemon")
	}
	sock, recipients := buildAndSeed(t, map[string]sopsplugin.Tier{
		"e2e":  sopsplugin.TierNormal,
		"team": sopsplugin.TierNormal, // the second pointer of an ordinary two-key keys.txt
		"prod": sopsplugin.TierDangerous,
	})
	cl := client.New(sock)

	const payload = "sops payload"
	normalCT := encryptTo(t, recipients["e2e"], payload)

	// A LOCKED vault under AV_NO_PROMPT. One of the two situations that arrive as
	// CodeLocked, and the one where "run av unlock" is the right advice.
	t.Run("locked vault relays the daemon's lock message", func(t *testing.T) {
		if err := cl.Lock(); err != nil {
			t.Fatalf("lock: %v", err)
		}
		t.Setenv("AV_NO_PROMPT", "1")

		_, err := decryptThroughPlugin(t, normalCT, recipients["e2e"])
		if err == nil {
			t.Fatal("a locked vault must not decrypt")
		}
		// The daemon's message, verbatim under the prefix — asserted in full rather than by
		// keyword so that this and the dangerous-tier subtest below pin two DIFFERENT
		// strings. A substituted message that satisfied both would be exactly the bug: one
		// text for two situations that need opposite responses.
		//
		// It carries the ADVICE, which is the half decision 6 promises and the half a
		// relayed ErrLocked ("vault locked: authorization not available") does not have.
		// The plugin still invents nothing; the daemon says it, because on this path the
		// daemon's string is what the human reads.
		const want = `AgentVault: sops unwrap: vault locked — ask a human to run "av unlock"`
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("locked error = %q, want it to carry %q", err, want)
		}
	})

	// The load-bearing case: a file with ORDINARY age1... recipients decrypts through the
	// plugin, with the private key never leaving avd.
	t.Run("decrypts a standard age1 file through the daemon", func(t *testing.T) {
		if err := cl.Unlock(); err != nil {
			t.Fatalf("unlock: %v", err)
		}
		got, err := decryptThroughPlugin(t, normalCT, recipients["e2e"])
		if err != nil {
			t.Fatalf("decrypt through age-plugin-av: %v", err)
		}
		if got != payload {
			t.Fatalf("got %q, want %q", got, payload)
		}
	})

	// The DANGEROUS-tier situation, which also arrives as CodeLocked and where "run av
	// unlock" is a lie: the session is open (the subtest unlocks it) and only the fresh
	// per-file check is missing. This is the assertion a substituted message swallows, and
	// with it the human loops — unlock, retry, identical error.
	t.Run("dangerous tier under no_prompt relays the tier message", func(t *testing.T) {
		if err := cl.Unlock(); err != nil {
			t.Fatalf("unlock: %v", err)
		}
		t.Setenv("AV_NO_PROMPT", "1")

		dangerCT := encryptTo(t, recipients["prod"], payload)
		text, err := decryptThroughPlugin(t, dangerCT, recipients["prod"])
		if err == nil {
			t.Fatalf("a dangerous-tier identity under AV_NO_PROMPT must not decrypt (got %q)", text)
		}
		const want = `AgentVault: sops unwrap "prod": dangerous-tier identity needs a fresh presence check, and this caller set no_prompt`
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("dangerous-tier error = %q, want it to carry %q", err, want)
		}
		// The substitution guard. A hard-coded lock message would still contain the word
		// "locked" while saying nothing true about this path.
		if strings.Contains(err.Error(), "vault locked") {
			t.Fatalf("dangerous-tier error was rendered as a locked vault: %q", err)
		}
	})

	// THE MULTI-KEY CASE, and the one that decides whether an ordinary two-key keys.txt
	// works at all. `av sops import` writes one pointer per key, so a developer with a
	// personal key and a team key has two — and any given file is encrypted to one of them.
	//
	// age tries identities in order and advances ONLY on age.ErrIncorrectIdentity; every
	// other error aborts the decrypt outright. So the first pointer's "no stanza in this
	// file was encrypted to it" must arrive as a fall-through, not as a hard error. Before
	// CodeNoMatch it arrived as CodeBadRequest, the plugin relayed it as a hard error, and
	// this file was simply unreadable.
	//
	// The file is encrypted to "team" ALONE, so "e2e" has to refuse it and age has to keep
	// going. Order is explicit rather than incidental: with the working key first, a
	// regression here would never be reached.
	t.Run("two keys.txt pointers decrypt a file encrypted to only the second", func(t *testing.T) {
		if err := cl.Unlock(); err != nil {
			t.Fatalf("unlock: %v", err)
		}
		teamCT := encryptTo(t, recipients["team"], payload)

		got, err := decryptThroughPlugin(t, teamCT, recipients["e2e"], recipients["team"])
		if err != nil {
			t.Fatalf("a two-pointer keys.txt failed to decrypt a file encrypted to the second key: %v", err)
		}
		if got != payload {
			t.Fatalf("got %q, want %q", got, payload)
		}
	})

	// The other half of CodeNoMatch, and the mangled-keys.txt case: a pointer naming a key
	// this vault does not hold. Unlike the subtest above it is a property of the POINTER,
	// not of the file — it refuses every file identically — so it must not veto the pointers
	// beside it either.
	//
	// The second assertion records what that costs, because it is a real loss and not an
	// oversight: with the stale pointer ALONE, the daemon's message naming the missing
	// recipient no longer reaches the user. age's identity loop discards the error it falls
	// through on, so nothing the plugin returns on this path can be displayed. The user sees
	// age's generic text and recovers with `av sops ls`.
	t.Run("a stale pointer falls through instead of vetoing the others", func(t *testing.T) {
		if err := cl.Unlock(); err != nil {
			t.Fatalf("unlock: %v", err)
		}
		stranger, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}

		got, err := decryptThroughPlugin(t, normalCT, stranger.Recipient(), recipients["e2e"])
		if err != nil {
			t.Fatalf("a stale keys.txt pointer aborted a decrypt the live pointer could serve: %v", err)
		}
		if got != payload {
			t.Fatalf("got %q, want %q", got, payload)
		}

		// Alone, it fails — and as age's own "no identity matched", not as the daemon's
		// message. This is the diagnostic the fall-through trades away, asserted so the
		// trade stays deliberate rather than becoming a surprise.
		strangerCT := encryptTo(t, stranger.Recipient(), payload)
		_, err = decryptThroughPlugin(t, strangerCT, stranger.Recipient())
		if err == nil {
			t.Fatal("an identity this vault holds no key for must not decrypt")
		}
		var noMatch *age.NoIdentityMatchError
		if !errors.As(err, &noMatch) {
			t.Fatalf("error = %q, want age's NoIdentityMatchError — a fall-through, not a relayed refusal", err)
		}
		if strings.Contains(err.Error(), "no stored SOPS identity") {
			t.Fatalf("error = %q: the daemon's message reached the user, so this was NOT a fall-through", err)
		}
	})
}
