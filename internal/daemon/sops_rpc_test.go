package daemon

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/backend/agefile"
	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/sopsplugin"
)

// sopsAuth counts every biometric the daemon spends, split by which one it was:
//
//   - unwraps: the session unwrapper — the ONE Touch ID that opens a locked session.
//   - prompts: presence.Prompt — the FRESH check a dangerous-tier identity costs per call.
//
// Both are counted because the user experiences one thing (a prompt), and the whole
// point of the tier policy is how many of them a `helm secrets template` costs. Asserting
// only "it succeeded" would let a regression that prompts per file pass forever.
type sopsAuth struct {
	mu      sync.Mutex
	prompts int
	unwraps int
	deny    bool                // when set, both seams deny (the user cancelled)
	key     *age.X25519Identity // the VAULT identity the unwrapper yields
}

func (a *sopsAuth) Prompt(string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.prompts++
	if a.deny {
		return ErrDenied
	}
	return nil
}

// unwrap stands in for the Secure Enclave unwrap: it yields the vault identity bytes,
// exactly as cmd/avd's enclave closure does, so the file backend can decrypt afterwards.
func (a *sopsAuth) unwrap() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.unwraps++
	if a.deny {
		return nil, ErrDenied
	}
	return []byte(a.key.String() + "\n"), nil
}

func (a *sopsAuth) counts() (prompts, unwraps int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.prompts, a.unwraps
}

// setDeny flips the cancel-the-prompt switch. It exists so no test writes a.deny directly:
// the daemon reads it from the goroutine serving the connection, so a bare assignment is a
// data race that -race only reports when the timing cooperates.
func (a *sopsAuth) setDeny(v bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.deny = v
}

func (a *sopsAuth) reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.prompts, a.unwraps = 0, 0
}

// sopsFixture is a daemon wired the way PRODUCTION wires it for this path: the file
// backend's IdentitySource is the SESSION (cmd/avd/main.go:405), not a static identity.
// That is load-bearing for every locked-session test here — with a static identity the
// vault stays readable while locked, and the lock-ordering assertions would prove nothing.
//
// vault is a SECOND handle on the same file with a static identity, used only to seed.
// Seeding must not depend on the lock state the test is driving.
type sopsFixture struct {
	path  string
	sess  *Session
	auth  *sopsAuth
	log   *bufLogger
	vault *agefile.Backend
}

func newSopsFixture(t *testing.T) *sopsFixture {
	t.Helper()
	vaultPath, vaultID := newAgeVault(t, map[string]string{"PLAIN": "ordinary-value"})
	auth := &sopsAuth{key: vaultID}
	sess := NewSession(15 * time.Minute).WithUnwrapper(auth.unwrap)

	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	reg := backend.NewRegistry()
	// Registered under the SAME identifier the namespace guard and the daemon's Store
	// construction key on, so a test cannot accidentally prove the guard over a backend
	// production never uses.
	reg.Register(sopsplugin.VaultBackendID, agefile.New(sess, vaultPath))
	log := &bufLogger{}
	srv.SetPresence(auth)
	srv.SetResolver(NewResolver(reg, auth, sess))
	srv.SetAudit(log)
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })

	return &sopsFixture{
		path:  path,
		sess:  sess,
		auth:  auth,
		log:   log,
		vault: agefile.New(agefile.Static{ID: vaultID}, vaultPath),
	}
}

// seed stores one SOPS identity through the REAL Store, so these tests read back exactly
// the envelope production writes rather than a hand-built copy of it that could drift.
func (f *sopsFixture) seed(t *testing.T, name string, key *age.X25519Identity, tier sopsplugin.Tier) {
	t.Helper()
	if err := sopsplugin.NewStore(f.vault, f.vault).Put(name, key, tier); err != nil {
		t.Fatalf("seed %q: %v", name, err)
	}
}

// seedJunk writes an arbitrary value into the namespace, going AROUND the daemon guard
// that now refuses exactly this (see sops_namespace.go). It reproduces a vault that
// predates the guard, or one edited by hand — the case Store.decode has to survive.
func (f *sopsFixture) seedJunk(t *testing.T, name, value string) {
	t.Helper()
	if err := f.vault.Add(sopsplugin.Namespace+name, value); err != nil {
		t.Fatalf("seed junk %q: %v", name, err)
	}
}

// open unlocks the session the way the daemon does — THROUGH the unwrapper. Session.Unlock
// alone is not enough: it opens the window but stores no key, so the file backend still
// cannot decrypt. It then zeroes the counters, so each test counts the touches ITS request
// spent rather than the fixture's setup.
func (f *sopsFixture) open(t *testing.T) {
	t.Helper()
	if err := f.sess.unlockWithUnwrapper(DefaultTTL); err != nil {
		t.Fatalf("open session: %v", err)
	}
	f.auth.reset()
}

// unwrap drives the sops_unwrap RPC over the socket.
//
// The recipient goes out as the bech32 "age1…" TEXT of the key, because that is what
// sopsplugin.EncodeIdentity puts in an AGE-PLUGIN-AV-1… pointer — and since the field is
// []byte, JSON carries it as base64-OF-ASCII. Encoding it here the same way the plugin
// will is the point: a daemon that compared raw key bytes would pass a hand-written test
// and fail every real file.
func (f *sopsFixture) unwrap(t *testing.T, r *age.X25519Recipient, stanzas []ipc.SopsStanza, noPrompt bool) ipc.Response {
	t.Helper()
	return rpcParams(t, f.path, "sops_unwrap", ipc.SopsUnwrapParams{
		Recipient: []byte(r.String()),
		Stanzas:   stanzas,
		NoPrompt:  noPrompt,
	})
}

// captureIdentity records the header stanzas age hands an identity, and the file key age
// itself derives from them. age's header parser is internal, so this is how a test gets
// REAL stanzas out of a REAL age file instead of hand-assembling a structure that only
// resembles one.
type captureIdentity struct {
	inner   age.Identity
	stanzas []*age.Stanza
	fileKey []byte
}

func (c *captureIdentity) Unwrap(ss []*age.Stanza) ([]byte, error) {
	c.stanzas = ss
	fk, err := c.inner.Unwrap(ss)
	c.fileKey = fk
	return fk, err
}

// fileKeyIdentity hands age a canned file key regardless of stanzas. It lets a test
// decrypt the real ciphertext with the key the DAEMON returned — age verifies the header
// MAC with that key, so a wrong one fails loudly. That is the assertion worth making:
// not "the bytes match" but "sops could have read the file with this".
type fileKeyIdentity struct{ key []byte }

func (f fileKeyIdentity) Unwrap([]*age.Stanza) ([]byte, error) { return f.key, nil }

// sopsFile encrypts payload to an ORDINARY age1… recipient with the real age.Encrypt —
// no plugin on the write side, which is the compatibility claim the whole design rests
// on (design doc, decision 2). It returns the ciphertext, the header stanzas, and the
// file key age derived, so a test can compare against the daemon's answer.
func sopsFile(t *testing.T, key *age.X25519Identity, payload string) (ct []byte, stanzas []ipc.SopsStanza, fileKey []byte) {
	t.Helper()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, key.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	rec := &captureIdentity{inner: key}
	if _, err := age.Decrypt(bytes.NewReader(buf.Bytes()), rec); err != nil {
		t.Fatalf("decrypt to capture stanzas: %v", err)
	}
	for _, s := range rec.stanzas {
		stanzas = append(stanzas, ipc.SopsStanza{Type: s.Type, Args: s.Args, Body: s.Body})
	}
	return buf.Bytes(), stanzas, rec.fileKey
}

// sopsResult decodes a successful sops_unwrap reply.
func sopsResult(t *testing.T, resp ipc.Response) ipc.SopsUnwrapResult {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("sops_unwrap error: %+v", resp.Error)
	}
	var res ipc.SopsUnwrapResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatal(err)
	}
	return res
}

// sopsAuditDetails is the CLOSED set of Detail strings the sops path may write — every
// literal sops_rpc.go passes to sopsAudit, plus the "denied" event's. It is restated here
// rather than imported on purpose: a new outcome has to be written down twice, which is
// the moment someone looks at whether it is a literal.
//
// SECURITY: this allowlist, not the encoding scan below it, is what makes "the audit log
// never carries key material" a real assertion. The obvious test — "the raw output must
// not contain the file key in base64 or hex" — is a BLOCKLIST of encodings, and it misses
// the formulations a leak is actually written in. `string(fileKey)` and
// `fmt.Sprintf("%s", fileKey)` slip through because a file key is 16 random bytes, so
// json.Marshal replaces the invalid UTF-8 with U+FFFD before the needle can match; `%v`
// renders `[12 34 …]` and `%q` renders `"\x12\x34…"`, neither of which is base64 or hex.
// A blocklist catches the two encodings someone would have to write deliberately and
// misses the four they would write by accident. An allowlist catches all six, and every
// encoding nobody has thought of yet: a Detail built from anything but these literals is
// not one of them, whatever it is made of.
var sopsAuditDetails = []string{
	"ok",                    // sops_unwrap: the file key was returned
	"no matching stanza",    // sops_unwrap: the identity is ours, the file is not
	"malformed stanza",      // sops_unwrap: the header is not a header
	"no presence available", // sops_unwrap: dangerous tier, and the caller set NoPrompt
	"sops unwrap",           // denied: a dangerous-tier presence check the user cancelled
}

// assertAuditDetails holds every sops event the fixture logged against that set.
func assertAuditDetails(t *testing.T, log *bufLogger) {
	t.Helper()
	for _, e := range log.all() {
		if e.Kind != "sops_unwrap" && e.Kind != "denied" {
			continue
		}
		if slices.Contains(sopsAuditDetails, e.Detail) {
			continue
		}
		// SECURITY: the offending Detail is NOT printed. If this assertion is firing, the
		// most likely reason is that it now carries key material, and a t.Fatalf is a
		// straight path from there into a CI log. Its length is enough to identify it.
		t.Fatalf("audit %q entry for %q recorded a Detail of %d bytes that is not one of %v — "+
			"an outcome outside that set is how key material reaches the log",
			e.Kind, e.Name, len(e.Detail), sopsAuditDetails)
	}
}

// TestSopsUnwrapReturnsTheFileKey: a stored identity unwraps a file encrypted to its own
// recipient by stock age, and the returned key really decrypts that file.
//
// The end-to-end shape matters. The file is produced by age.Encrypt to a plain age1…
// recipient — the same bytes `sops -e` writes — and the returned key is fed back into
// age.Decrypt, which verifies the header MAC with it. Nothing here trusts a stanza this
// test built itself.
func TestSopsUnwrapReturnsTheFileKey(t *testing.T) {
	const payload = "kind: Secret\ndata:\n  password: hunter2\n"
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	f := newSopsFixture(t)
	f.seed(t, "mykey", key, sopsplugin.TierNormal)
	f.open(t)

	ct, stanzas, want := sopsFile(t, key, payload)
	res := sopsResult(t, f.unwrap(t, key.Recipient(), stanzas, false))

	if !bytes.Equal(res.FileKey, want) {
		t.Fatalf("file key differs from the one age derived (%d vs %d bytes)", len(res.FileKey), len(want))
	}
	r, err := age.Decrypt(bytes.NewReader(ct), fileKeyIdentity{key: res.FileKey})
	if err != nil {
		t.Fatalf("the daemon's file key does not decrypt the file: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("plaintext = %q, want %q", got, payload)
	}
	// A normal-tier identity in an open session costs nothing: that is decision 5, and it
	// is what makes `helm secrets template` over thirty files bearable.
	if p, u := f.auth.counts(); p != 0 || u != 0 {
		t.Fatalf("normal-tier unwrap in an open session cost %d prompts + %d unwraps, want 0 + 0", p, u)
	}
}

// TestSopsUnwrapUnknownRecipientNeverPrompts is the guard that makes this feature usable.
//
// `kustomize build` over a monorepo hands the plugin every encrypted file it meets,
// including the ones belonging to other teams. Each of those is a sops_unwrap the vault
// has no key for. If the daemon asked for presence BEFORE deciding whether the file is
// even ours, that build would be a wall of Touch ID prompts for files it cannot read
// anyway. So: no match, no prompt, CodeNoMatch — and nothing in the audit log either,
// because there is no identity to name.
func TestSopsUnwrapUnknownRecipientNeverPrompts(t *testing.T) {
	mine, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	f := newSopsFixture(t)
	f.seed(t, "mykey", mine, sopsplugin.TierDangerous) // dangerous: prompting is one step away
	f.open(t)

	_, stanzas, _ := sopsFile(t, theirs, "someone else's secret")
	resp := f.unwrap(t, theirs.Recipient(), stanzas, false)

	// SECURITY: the result is NOT printed here or below. A result on this path means the
	// daemon handed back a file key it should have refused, and a t.Fatalf is the shortest
	// route from there into a CI log. Its length says everything the failure needs.
	if resp.Error == nil {
		t.Fatalf("unwrap with a recipient we hold no key for succeeded, returning a %d-byte result", len(resp.Result))
	}
	// CodeNoMatch, not CodeBadRequest: the caller may hold OTHER pointers, and this answer
	// must let it try them rather than end the decrypt. See ipc.CodeNoMatch.
	if resp.Error.Code != ipc.CodeNoMatch {
		t.Fatalf("code = %d, want CodeNoMatch (%d)", resp.Error.Code, ipc.CodeNoMatch)
	}
	// Naming the recipient proves the daemon actually looked, and keeps this test from
	// passing on any old code. The recipient is a public key: safe to echo, and the one
	// datum that tells a user which key the file wants.
	if !strings.Contains(resp.Error.Message, theirs.Recipient().String()) {
		t.Fatalf("message = %q, want it to name the recipient the file was encrypted to", resp.Error.Message)
	}
	if p, u := f.auth.counts(); p != 0 || u != 0 {
		t.Fatalf("a file we hold no key for cost %d prompts + %d unwraps, want 0 + 0", p, u)
	}
	if resp.Result != nil {
		t.Fatalf("a refused unwrap must return no result, got %d bytes", len(resp.Result))
	}
	for _, e := range f.log.all() {
		if e.Kind == "sops_unwrap" {
			t.Fatalf("a file we hold no key for wrote an audit entry: %+v", e)
		}
	}
}

// TestSopsUnwrapLockedUnknownRecipientCostsTheSessionOpen pins the ONE cost the ordering
// cannot avoid, so nobody has to rediscover it from a Touch ID prompt.
//
// A locked daemon cannot tell whose file it is: the vault's IdentitySource IS the session
// (cmd/avd/main.go:405), so identifying the key requires opening the session first. A
// foreign file met while locked therefore costs exactly ONE presence check — the one that
// opens the session — and every foreign file after it costs nothing, which is the whole
// point. The failure this test would catch is a regression to one check per file.
func TestSopsUnwrapLockedUnknownRecipientCostsTheSessionOpen(t *testing.T) {
	theirs, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	f := newSopsFixture(t) // left LOCKED
	_, stanzas, _ := sopsFile(t, theirs, "someone else's secret")

	for i := 0; i < 3; i++ {
		resp := f.unwrap(t, theirs.Recipient(), stanzas, false)
		if resp.Error == nil || resp.Error.Code != ipc.CodeNoMatch {
			t.Fatalf("call %d: resp.Error = %+v, want CodeNoMatch", i, resp.Error)
		}
	}
	if p, u := f.auth.counts(); p != 0 || u != 1 {
		t.Fatalf("three foreign files against a locked vault cost %d prompts + %d unwraps, want 0 + 1 — the session open, once", p, u)
	}
}

// TestSopsUnwrapRejectsAMalformedRecipient: a recipient that is not a parseable age1… key
// is a client fault, refused before any vault access and without a prompt. It is the same
// fail-fast as an unknown recipient, one layer earlier.
func TestSopsUnwrapRejectsAMalformedRecipient(t *testing.T) {
	f := newSopsFixture(t)
	f.open(t)

	resp := rpcParams(t, f.path, "sops_unwrap", ipc.SopsUnwrapParams{
		Recipient: []byte("age1-not-a-real-recipient"),
		Stanzas:   []ipc.SopsStanza{{Type: "X25519", Args: []string{"abc"}, Body: []byte("x")}},
	})
	if resp.Error == nil || resp.Error.Code != ipc.CodeBadRequest {
		t.Fatalf("resp.Error = %+v, want CodeBadRequest", resp.Error)
	}
	if !strings.Contains(resp.Error.Message, "recipient") {
		t.Fatalf("message = %q, want it to say the recipient is the problem", resp.Error.Message)
	}
	if p, u := f.auth.counts(); p != 0 || u != 0 {
		t.Fatalf("a malformed recipient cost %d prompts + %d unwraps, want 0 + 0", p, u)
	}
}

// TestSopsUnwrapLockedNoPromptIsLocked: an agent (AV_NO_PROMPT) meeting a locked vault
// gets CodeLocked immediately and faces no biometric — the exit-69 pause every other
// command gives it, rather than a machine blocking on a prompt nobody will answer.
func TestSopsUnwrapLockedNoPromptIsLocked(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	f := newSopsFixture(t)
	f.seed(t, "mykey", key, sopsplugin.TierNormal)
	// Deliberately NOT opened: the session is locked, as it is before the day's first use.

	_, stanzas, _ := sopsFile(t, key, "payload")
	resp := f.unwrap(t, key.Recipient(), stanzas, true)

	if resp.Error == nil || resp.Error.Code != ipc.CodeLocked {
		t.Fatalf("resp.Error = %+v, want CodeLocked (%d)", resp.Error, ipc.CodeLocked)
	}
	if p, u := f.auth.counts(); p != 0 || u != 0 {
		t.Fatalf("NoPrompt spent %d prompts + %d unwraps, want 0 + 0", p, u)
	}
}

// TestSopsUnwrapWrongKeyIsNoMatchNotBadRequest is the daemon half of the multi-key fix.
//
// A keys.txt with two AgentVault pointers — the personal-key-plus-team-key setup
// `av sops import` produces — sends one sops_unwrap per pointer, and for any given file
// one of them holds the wrong key. That answer must be CodeNoMatch, because age advances
// to the next identity ONLY on age.ErrIncorrectIdentity and age-plugin-av derives that
// solely from the code. As CodeBadRequest it was a hard error, so the first pointer
// decided every file and the second key's files were unreadable.
//
// It is pinned separately from the malformed-header case below because the two now differ
// by CODE and not merely by wording: this one means "try another", that one means "stop".
func TestSopsUnwrapWrongKeyIsNoMatchNotBadRequest(t *testing.T) {
	mine, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	f := newSopsFixture(t)
	f.seed(t, "mykey", mine, sopsplugin.TierNormal)
	f.open(t)

	// Stored key, well-formed header — but the file was encrypted to the OTHER key. The
	// recipient asked for is the stored one, so this reaches Unwrap rather than stopping at
	// FindByRecipient: this is the ErrIncorrectIdentity half of CodeNoMatch.
	_, stanzas, _ := sopsFile(t, theirs, "the other key's file")
	resp := f.unwrap(t, mine.Recipient(), stanzas, false)

	if resp.Error == nil {
		t.Fatalf("unwrapping another key's file succeeded, returning a %d-byte result", len(resp.Result))
	}
	if resp.Error.Code != ipc.CodeNoMatch {
		t.Fatalf("code = %d, want CodeNoMatch (%d) — as anything else, a two-pointer keys.txt cannot decrypt this file at all", resp.Error.Code, ipc.CodeNoMatch)
	}
	if !strings.Contains(resp.Error.Message, "mykey") {
		t.Fatalf("message = %q, want it to name the identity that could not unwrap", resp.Error.Message)
	}
	if strings.Contains(resp.Error.Message, mine.String()) {
		t.Fatalf("error leaked a private key: %q", resp.Error.Message)
	}
	assertAuditDetails(t, f.log)
}

// TestSopsUnwrapLockedPromptsOnceThenSucceeds: a human at a TTY meeting a locked vault
// pays ONE presence check — the unwrap that opens the session — and every file after it
// is free for the session's TTL. This is decision 5 end to end: one touch per command,
// not one per file.
func TestSopsUnwrapLockedPromptsOnceThenSucceeds(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	f := newSopsFixture(t)
	f.seed(t, "mykey", key, sopsplugin.TierNormal)

	ct, stanzas, want := sopsFile(t, key, "first file")
	res := sopsResult(t, f.unwrap(t, key.Recipient(), stanzas, false))
	if !bytes.Equal(res.FileKey, want) {
		t.Fatal("first unwrap returned the wrong file key")
	}
	if _, err := age.Decrypt(bytes.NewReader(ct), fileKeyIdentity{key: res.FileKey}); err != nil {
		t.Fatalf("the daemon's file key does not decrypt the file: %v", err)
	}
	if p, u := f.auth.counts(); p != 0 || u != 1 {
		t.Fatalf("opening a locked session cost %d prompts + %d unwraps, want 0 + 1", p, u)
	}

	// The rest of the command runs inside the session it just opened.
	_, more, want2 := sopsFile(t, key, "second file")
	res2 := sopsResult(t, f.unwrap(t, key.Recipient(), more, false))
	if !bytes.Equal(res2.FileKey, want2) {
		t.Fatal("second unwrap returned the wrong file key")
	}
	if p, u := f.auth.counts(); p != 0 || u != 1 {
		t.Fatalf("the SECOND file cost %d prompts + %d unwraps in total, want 0 + 1 — a session covers the whole command", p, u)
	}
}

// TestSopsUnwrapTierPolicy pins the tier vocabulary against prompt COUNTS, which is the
// only way to see the difference: both tiers succeed, and only the counter distinguishes
// "one touch per command" from "one touch per file".
//
//   - normal is covered by the open session — two files, zero prompts.
//   - dangerous demands a FRESH check per call — two files, two prompts. Slow on purpose:
//     a production deploy should be hard to perform absent-mindedly (decision 5).
func TestSopsUnwrapTierPolicy(t *testing.T) {
	normal, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	danger, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	f := newSopsFixture(t)
	f.seed(t, "staging", normal, sopsplugin.TierNormal)
	f.seed(t, "prod", danger, sopsplugin.TierDangerous)
	f.open(t)

	for i := 0; i < 2; i++ {
		_, stanzas, want := sopsFile(t, normal, "staging file")
		if res := sopsResult(t, f.unwrap(t, normal.Recipient(), stanzas, false)); !bytes.Equal(res.FileKey, want) {
			t.Fatalf("normal-tier unwrap %d returned the wrong file key", i)
		}
	}
	if p, u := f.auth.counts(); p != 0 || u != 0 {
		t.Fatalf("two normal-tier files cost %d prompts + %d unwraps, want 0 + 0", p, u)
	}

	f.auth.reset()
	for i := 0; i < 2; i++ {
		_, stanzas, want := sopsFile(t, danger, "prod file")
		if res := sopsResult(t, f.unwrap(t, danger.Recipient(), stanzas, false)); !bytes.Equal(res.FileKey, want) {
			t.Fatalf("dangerous-tier unwrap %d returned the wrong file key", i)
		}
	}
	if p, _ := f.auth.counts(); p != 2 {
		t.Fatalf("two dangerous-tier files cost %d prompts, want 2 — one FRESH check per file", p)
	}
}

// TestSopsUnwrapDangerousTierDeniedIsDenied: a cancelled presence check on a dangerous
// identity returns CodeDenied and no key. CodeDenied, not CodeLocked: a check ran and the
// user said no, which is a different thing from no check being available.
func TestSopsUnwrapDangerousTierDeniedIsDenied(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	f := newSopsFixture(t)
	f.seed(t, "prod", key, sopsplugin.TierDangerous)
	f.open(t)
	f.auth.setDeny(true)

	_, stanzas, _ := sopsFile(t, key, "prod file")
	resp := f.unwrap(t, key.Recipient(), stanzas, false)
	if resp.Error == nil || resp.Error.Code != ipc.CodeDenied {
		t.Fatalf("resp.Error = %+v, want CodeDenied (%d)", resp.Error, ipc.CodeDenied)
	}
	if resp.Result != nil {
		t.Fatalf("a denied unwrap must return no result, got %d bytes", len(resp.Result))
	}
	assertAuditDetails(t, f.log)
}

// TestSopsUnwrapDangerousTierNoPromptIsLocked: NoPrompt reaches the dangerous tier too.
// An open session is not enough for a dangerous identity — it needs a fresh check — and a
// caller that has told us no human is present must not be handed a biometric it cannot
// answer. Per FILE, a hang here would be thirty hangs.
//
// CodeLocked is the honest CODE: it is "authorization not available", which is exactly
// what a refused-to-ask presence check is, and it gives the agent the same exit-69 pause a
// locked vault does. Nothing was denied; nothing was asked.
//
// The MESSAGE is a separate assertion, and the sharper one. The vault is NOT locked here —
// the session is open and only the fresh per-file check is missing — so the stock
// ErrLocked text ("vault locked: authorization not available") would send a human to
// `av unlock`, a no-op on this path, after which the agent retries and gets the identical
// error. A loop, and the daemon is the only layer that knows enough to prevent it: two
// different situations return CodeLocked and nothing downstream can tell them apart.
func TestSopsUnwrapDangerousTierNoPromptIsLocked(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	f := newSopsFixture(t)
	f.seed(t, "prod", key, sopsplugin.TierDangerous)
	f.open(t) // the SESSION is open — only the fresh dangerous-tier check is missing

	_, stanzas, _ := sopsFile(t, key, "prod file")
	resp := f.unwrap(t, key.Recipient(), stanzas, true)
	if resp.Error == nil || resp.Error.Code != ipc.CodeLocked {
		t.Fatalf("resp.Error = %+v, want CodeLocked (%d)", resp.Error, ipc.CodeLocked)
	}
	if p, _ := f.auth.counts(); p != 0 {
		t.Fatalf("NoPrompt spent %d dangerous-tier prompts, want 0", p)
	}
	if strings.Contains(resp.Error.Message, "vault locked") {
		t.Fatalf("message = %q, but the vault is NOT locked — this text sends a human to `av unlock`, which changes nothing here", resp.Error.Message)
	}
	// It must name the two things that would let someone act: which identity, and that the
	// caller's own no_prompt is the reason nothing was asked.
	if !strings.Contains(resp.Error.Message, "prod") || !strings.Contains(resp.Error.Message, "no_prompt") {
		t.Fatalf("message = %q, want it to name the identity and the caller's no_prompt", resp.Error.Message)
	}
	assertAuditDetails(t, f.log)
}

// TestSopsUnwrapDangerousFromLockedCostsTwoChecks pins the one row the tier documentation
// used to leave out, so nobody rediscovers it from an unexpected second Touch ID.
//
// "dangerous costs one check per file" is true, but the FIRST dangerous file on a locked
// vault costs two: the unwrap that opens the session, then the fresh per-file check. They
// buy different things — the first a session every later file rides for free, the second
// the per-file gate the tier exists for — and it is the same two `av run` costs on a
// dangerous entry from locked. The second file costs one, which is what proves the first
// check was the session and not a double charge.
func TestSopsUnwrapDangerousFromLockedCostsTwoChecks(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	f := newSopsFixture(t)
	f.seed(t, "prod", key, sopsplugin.TierDangerous)
	// Deliberately NOT opened: this is the day's first command.

	_, stanzas, want := sopsFile(t, key, "prod file")
	if res := sopsResult(t, f.unwrap(t, key.Recipient(), stanzas, false)); !bytes.Equal(res.FileKey, want) {
		t.Fatal("the first dangerous unwrap returned the wrong file key")
	}
	if p, u := f.auth.counts(); p != 1 || u != 1 {
		t.Fatalf("the first dangerous file on a locked vault cost %d prompts + %d unwraps, want 1 + 1 — the session open, then the fresh per-file check", p, u)
	}

	_, more, want2 := sopsFile(t, key, "second prod file")
	if res := sopsResult(t, f.unwrap(t, key.Recipient(), more, false)); !bytes.Equal(res.FileKey, want2) {
		t.Fatal("the second dangerous unwrap returned the wrong file key")
	}
	if p, u := f.auth.counts(); p != 2 || u != 1 {
		t.Fatalf("the second dangerous file brought the total to %d prompts + %d unwraps, want 2 + 1 — one session, one fresh check per file", p, u)
	}
}

// TestSopsUnwrapCorruptEntryIsInternalNotUnknown: a junk entry in the namespace and a
// recipient nobody holds are DIFFERENT failures and must report differently.
//
// The distinction is the user-facing point of Task 4's tolerant scan, and CodeNoMatch
// sharpened it: "this key is not in the vault" is a FALL-THROUGH the caller answers by
// trying its next pointer, while "your vault has an entry that will not parse"
// (CodeInternal) is a hard stop that sends someone to `av sops ls`. Collapsing the two
// would make a broken vault look exactly like a foreign file — for a key sitting right
// there — and, now, would silently swallow it as age's "no identity matched".
func TestSopsUnwrapCorruptEntryIsInternalNotUnknown(t *testing.T) {
	theirs, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	_, stanzas, _ := sopsFile(t, theirs, "someone else's secret")

	clean := newSopsFixture(t)
	clean.open(t)
	cleanResp := clean.unwrap(t, theirs.Recipient(), stanzas, false)
	if cleanResp.Error == nil || cleanResp.Error.Code != ipc.CodeNoMatch {
		t.Fatalf("clean vault, unknown recipient: %+v, want CodeNoMatch", cleanResp.Error)
	}

	broken := newSopsFixture(t)
	broken.seedJunk(t, "notes", "reminder: rotate this in June")
	broken.open(t)
	brokenResp := broken.unwrap(t, theirs.Recipient(), stanzas, false)
	if brokenResp.Error == nil || brokenResp.Error.Code != ipc.CodeInternal {
		t.Fatalf("vault with a corrupt entry: %+v, want CodeInternal (%d)", brokenResp.Error, ipc.CodeInternal)
	}
	if brokenResp.Error.Code == cleanResp.Error.Code {
		t.Fatal("a corrupt entry and an unknown recipient report the same code — they must not")
	}
	if !strings.Contains(brokenResp.Error.Message, "notes") {
		t.Fatalf("message = %q, want it to name the unreadable entry", brokenResp.Error.Message)
	}
}

// TestSopsUnwrapAuditRecordsNameAndOutcomeOnly: every unwrap that reaches an identity
// leaves ONE audit entry naming it and saying how it went — and the audit output contains
// neither the file key nor the private key.
//
// The leak assertion is the Detail ALLOWLIST (see sopsAuditDetails), which holds whatever
// encoding an accident is written in. The encoding scan below it is a backstop, not the
// assertion: it is asserted against a REAL seeded key and the REAL file key this call
// returned, but it can only catch the encodings it names, and the private key is the one
// that matters there — unlike a file key, it exists as exactly one canonical text.
func TestSopsUnwrapAuditRecordsNameAndOutcomeOnly(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	f := newSopsFixture(t)
	f.seed(t, "mykey", key, sopsplugin.TierNormal)
	f.open(t)

	_, stanzas, _ := sopsFile(t, key, "audited file")
	res := sopsResult(t, f.unwrap(t, key.Recipient(), stanzas, false))

	var got []string
	named := false
	for _, e := range f.log.all() {
		got = append(got, e.Kind)
		if e.Kind != "sops_unwrap" {
			continue
		}
		named = true
		if e.Name != "mykey" {
			t.Fatalf("audit entry Name = %q, want mykey", e.Name)
		}
		if e.Tier != string(sopsplugin.TierNormal) {
			t.Fatalf("audit entry Tier = %q, want %s", e.Tier, sopsplugin.TierNormal)
		}
		if e.Detail == "" {
			t.Fatal("audit entry records no outcome")
		}
	}
	if !named {
		t.Fatalf("no sops_unwrap audit entry; kinds = %v", got)
	}
	// The assertion that actually holds: every outcome is one of a closed set of literals,
	// so no Detail can carry key material in any encoding.
	assertAuditDetails(t, f.log)

	raw := f.log.raw(t)
	// SECURITY: the private key, in the only form it exists as text. This one IS
	// exhaustive — an age identity has exactly one canonical string.
	if strings.Contains(raw, key.String()) {
		t.Fatal("audit output leaked the private key")
	}
	// The file key, in the encodings a scan CAN name: raw bytes, the base64 JSON would
	// use, and hex. Deliberately a backstop — a file key is 16 random bytes, so the raw
	// needle never survives json.Marshal's UTF-8 replacement, and `%v`/`%q` would render
	// it as neither base64 nor hex. Those four cases are the allowlist's job.
	for enc, s := range map[string]string{
		"raw":    string(res.FileKey),
		"base64": base64.StdEncoding.EncodeToString(res.FileKey),
		"hex":    hex.EncodeToString(res.FileKey),
	} {
		if strings.Contains(raw, s) {
			// SECURITY: raw holds the leak. Naming the encoding is enough to find it.
			t.Fatalf("audit output leaked the file key (%s)", enc)
		}
	}
}

// TestSopsUnwrapErrorsCarryNoKeyMaterial: the two failure messages a caller can provoke
// name the identity or the recipient — both public — and never the stored private key.
// A plugin surfaces these straight into `sops` output, which lands in CI logs.
func TestSopsUnwrapErrorsCarryNoKeyMaterial(t *testing.T) {
	mine, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	f := newSopsFixture(t)
	f.seed(t, "mykey", mine, sopsplugin.TierNormal)
	f.open(t)

	// Unknown recipient.
	_, foreign, _ := sopsFile(t, theirs, "not ours")
	unknown := f.unwrap(t, theirs.Recipient(), foreign, false)
	// Our recipient, but stanzas from a file it cannot open: the identity resolves, the
	// unwrap does not. This is a keys.txt pointing at the wrong key of two.
	mismatch := f.unwrap(t, mine.Recipient(), foreign, false)

	for _, resp := range []ipc.Response{unknown, mismatch} {
		if resp.Error == nil {
			t.Fatalf("expected an error; got a %d-byte result", len(resp.Result))
		}
		if strings.Contains(resp.Error.Message, mine.String()) || strings.Contains(resp.Error.Message, theirs.String()) {
			t.Fatalf("error leaked a private key: %q", resp.Error.Message)
		}
	}
	// CodeNoMatch: see TestSopsUnwrapWrongKeyIsNoMatchNotBadRequest for why the code, not
	// just the wording, is what a multi-pointer keys.txt depends on.
	if mismatch.Error.Code != ipc.CodeNoMatch {
		t.Fatalf("stanzas from another file: code = %d, want CodeNoMatch", mismatch.Error.Code)
	}
	if !strings.Contains(mismatch.Error.Message, "mykey") {
		t.Fatalf("message = %q, want it to name the identity that could not unwrap", mismatch.Error.Message)
	}
	assertAuditDetails(t, f.log)
}

// TestSopsUnwrapMalformedStanzaIsBadRequestNotInternal: a header that will not parse is
// the CALLER's fault and must say so.
//
// The distinction is worth a test because the easy implementation gets it backwards.
// age reports "no stanza matched this key" and "this is not a stanza" as different errors,
// and only the first is ErrIncorrectIdentity — so mapping "everything else" to
// CodeInternal tells a user with a truncated SOPS header that the daemon broke, and hands
// any client a way to mint an internal error on demand.
//
// It is CodeBadRequest and NOT CodeNoMatch, which is the second half of the same point:
// trying the next identity cannot fix a header that is not a header, so this one must stop
// the decrypt and be shown. Falling through would bury a corrupt file under age's generic
// "no identity matched" and send the user hunting for a key that was never the problem.
func TestSopsUnwrapMalformedStanzaIsBadRequestNotInternal(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	f := newSopsFixture(t)
	f.seed(t, "mykey", key, sopsplugin.TierNormal)
	f.open(t)

	// A real stanza with its recipient arg cut in half — what a truncated header looks
	// like. It is not "encrypted to someone else"; it does not decode at all.
	_, stanzas, _ := sopsFile(t, key, "payload")
	stanzas[0].Args[0] = stanzas[0].Args[0][:len(stanzas[0].Args[0])/2]

	resp := f.unwrap(t, key.Recipient(), stanzas, false)
	if resp.Error == nil || resp.Error.Code != ipc.CodeBadRequest {
		t.Fatalf("resp.Error = %+v, want CodeBadRequest (%d) — a header the caller sent is the caller's fault", resp.Error, ipc.CodeBadRequest)
	}
	if !strings.Contains(resp.Error.Message, "malformed") {
		t.Fatalf("message = %q, want it to say the stanzas are malformed rather than blame the key", resp.Error.Message)
	}
	if strings.Contains(resp.Error.Message, key.String()) {
		t.Fatalf("error leaked a private key: %q", resp.Error.Message)
	}
	assertAuditDetails(t, f.log)
}
