package main

import (
	"bytes"
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

// decryptThroughPlugin decrypts ct with an AGE-PLUGIN-AV-1... identity naming r, which
// makes age exec the real age-plugin-av off PATH and speak identity-v1 to it. It is the
// full production path minus sops itself.
//
// The wait is BOUNDED. A plugin that blocks on a presence prompt is the failure mode this
// binary exists to avoid, and an unbounded wait would report it as a hung test suite ten
// minutes later instead of as the bug it is.
func decryptThroughPlugin(t *testing.T, ct []byte, r *age.X25519Recipient) (string, error) {
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
	id, err := plugin.NewIdentity(sopsplugin.EncodeIdentity(r), ui)
	if err != nil {
		t.Fatal(err)
	}

	type outcome struct {
		text string
		err  error
	}
	// Buffered: on a timeout this goroutine is abandoned, and it must not block forever on
	// a send nobody will receive.
	done := make(chan outcome, 1)
	go func() {
		out, decErr := age.Decrypt(bytes.NewReader(ct), id)
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
		// The daemon's ErrLocked text, verbatim under the prefix — asserted in full rather
		// than by keyword so that this and the dangerous-tier subtest below pin two
		// DIFFERENT strings. A substituted message that satisfied both would be exactly the
		// bug: one text for two situations that need opposite responses.
		const want = "AgentVault: vault locked: authorization not available"
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

	// The mangled-keys.txt case, and the evidence for NOT parsing the identity payload
	// locally: the daemon's own message reaches the caller intact, naming the recipient
	// (a public key) the file wants.
	t.Run("unknown recipient relays the daemon's message", func(t *testing.T) {
		if err := cl.Unlock(); err != nil {
			t.Fatalf("unlock: %v", err)
		}
		stranger, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		strangerCT := encryptTo(t, stranger.Recipient(), payload)

		_, err = decryptThroughPlugin(t, strangerCT, stranger.Recipient())
		if err == nil {
			t.Fatal("an identity this vault holds no key for must not decrypt")
		}
		want := "AgentVault: sops unwrap: no stored SOPS identity for recipient " + stranger.Recipient().String()
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("unknown-recipient error = %q, want it to carry %q", err, want)
		}
	})
}
