package daemon

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/sopsplugin"
)

// These exercise the four management RPCs behind `av sops keygen | import | ls | rm`. They
// run on the same sopsFixture as the unwrap tests (sops_rpc_test.go) — a daemon wired the
// way production wires it, with the vault's identity source being the SESSION — because
// every assertion about a locked vault here depends on that.

func (f *sopsFixture) keygen(t *testing.T, name, tier string, noPrompt bool) ipc.Response {
	t.Helper()
	return rpcParams(t, f.path, "sops_keygen", ipc.SopsKeygenParams{Name: name, Tier: tier, NoPrompt: noPrompt})
}

// put ferries a private key in, exactly as `av sops import` will: av reads the
// AGE-SECRET-KEY-1… line out of keys.txt and sends it without parsing it.
func (f *sopsFixture) put(t *testing.T, name, tier string, value []byte, noPrompt bool) ipc.Response {
	t.Helper()
	return rpcParams(t, f.path, "sops_put", ipc.SopsPutParams{Name: name, Tier: tier, Value: value, NoPrompt: noPrompt})
}

func (f *sopsFixture) list(t *testing.T, noPrompt bool) ipc.Response {
	t.Helper()
	return rpcParams(t, f.path, "sops_list", ipc.SopsListParams{NoPrompt: noPrompt})
}

func (f *sopsFixture) rm(t *testing.T, name string, noPrompt bool) ipc.Response {
	t.Helper()
	return rpcParams(t, f.path, "sops_rm", ipc.SopsRmParams{Name: name, NoPrompt: noPrompt})
}

// stored reads an identity back through the REAL Store on the static vault handle, so a
// test can compare against the key the daemon actually kept rather than one it assumed.
// It goes around the session deliberately: what is on disk must be checkable whatever lock
// state the test is driving.
func (f *sopsFixture) stored(t *testing.T, name string) sopsplugin.Identity {
	t.Helper()
	id, err := sopsplugin.NewStore(f.vault, f.vault).Get(name)
	if err != nil {
		t.Fatalf("stored %q: %v", name, err)
	}
	return id
}

// sopsInfo decodes the identity reply keygen and put share.
func sopsInfo(t *testing.T, resp ipc.Response) ipc.SopsIdentityInfo {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("error reply: %+v", resp.Error)
	}
	var info ipc.SopsIdentityInfo
	if err := json.Unmarshal(resp.Result, &info); err != nil {
		t.Fatal(err)
	}
	return info
}

func sopsListed(t *testing.T, resp ipc.Response) []ipc.SopsIdentityInfo {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("error reply: %+v", resp.Error)
	}
	var res ipc.SopsListResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatal(err)
	}
	return res.Identities
}

// assertNoKeyInReply is the security assertion every reply on this surface has to pass:
// the WHOLE response, rendered as the JSON that crosses the socket, contains the private
// key nowhere. It scans the marshaled response rather than named fields so a key smuggled
// into a message, a name or a field added later is caught without the test being taught
// about it.
//
// An age private key exists as exactly ONE canonical text, so unlike a file key this scan
// is exhaustive rather than a blocklist of encodings.
func assertNoKeyInReply(t *testing.T, resp ipc.Response, key *age.X25519Identity) {
	t.Helper()
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	// SECURITY: neither raw nor the key is printed. If this fires, raw HOLDS the leak, and
	// a t.Fatalf is the shortest path from there into a CI log.
	if strings.Contains(string(raw), key.String()) {
		t.Fatal("SECURITY: the reply carries the private key")
	}
	if strings.Contains(string(raw), "AGE-SECRET-KEY") {
		t.Fatal("SECURITY: the reply carries something shaped like an age private key")
	}
}

// TestSopsKeygenReturnsAUsablePointer is the load-bearing test for the whole split between
// av and avd: the daemon generates the key, and the reply carries the AGE-PLUGIN-AV-1…
// pointer that `av sops import`/`identity` writes into keys.txt.
//
// It matters that the pointer is DECODED back rather than merely matched against a prefix.
// av cannot check this string — it links neither age nor sopsplugin — so if the daemon
// renders a pointer that does not decode to the stored key's recipient, nothing between
// here and a failed `sops -d` will notice.
func TestSopsKeygenReturnsAUsablePointer(t *testing.T) {
	f := newSopsFixture(t)
	f.open(t)

	info := sopsInfo(t, f.keygen(t, "work", string(sopsplugin.TierDangerous), false))
	if info.Name != "work" {
		t.Fatalf("Name = %q, want work", info.Name)
	}
	if info.Tier != string(sopsplugin.TierDangerous) {
		t.Fatalf("Tier = %q, want %s", info.Tier, sopsplugin.TierDangerous)
	}

	// The key really landed in the vault, under the tier asked for.
	id := f.stored(t, "work")
	if id.Tier != sopsplugin.TierDangerous {
		t.Fatalf("stored tier = %q, want %s", id.Tier, sopsplugin.TierDangerous)
	}
	if info.Recipient != id.Key.Recipient().String() {
		t.Fatalf("reply recipient %s does not match the stored key's", info.Recipient)
	}

	r, err := sopsplugin.DecodeIdentity(info.Identity)
	if err != nil {
		t.Fatalf("the pointer the daemon returned does not decode: %v", err)
	}
	if r.String() != id.Key.Recipient().String() {
		t.Fatalf("the pointer decodes to %s, want the stored key's recipient", r)
	}
}

// TestSopsKeygenNeverReturnsThePrivateKey: the key generated inside avd stays there. This
// is asserted against the REAL stored key — read back off disk — rather than against a
// pattern, so it holds regardless of how a leak might be spelled.
func TestSopsKeygenNeverReturnsThePrivateKey(t *testing.T) {
	f := newSopsFixture(t)
	f.open(t)

	resp := f.keygen(t, "work", "", false)
	assertNoKeyInReply(t, resp, f.stored(t, "work").Key)

	// The default tier is the documented one: a caller that has not been taught about tiers
	// gets normal, not an empty string that reads back as something else later.
	if info := sopsInfo(t, resp); info.Tier != string(sopsplugin.TierNormal) {
		t.Fatalf("Tier = %q, want %s for an unspecified tier", info.Tier, sopsplugin.TierNormal)
	}
	if raw := f.log.raw(t); strings.Contains(raw, f.stored(t, "work").Key.String()) {
		t.Fatal("SECURITY: the audit log carries the generated private key")
	}
	assertAuditDetails(t, f.log)
}

// TestSopsPutStoresAnImportedKey covers the one RPC that takes key material IN: the value
// arrives as the AGE-SECRET-KEY-1… text av read out of keys.txt, and what comes back is the
// public half plus the pointer that replaces it in that file.
//
// The private key is asserted absent from the reply AND from the audit log against the
// actual key sent — the strongest form available, since this is the only path where a leak
// could echo a caller's own bytes back at it.
func TestSopsPutStoresAnImportedKey(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	f := newSopsFixture(t)
	f.open(t)

	// A trailing newline: what reading a line out of keys.txt actually yields.
	resp := f.put(t, "personal", string(sopsplugin.TierNormal), []byte(key.String()+"\n"), false)
	info := sopsInfo(t, resp)
	if info.Recipient != key.Recipient().String() {
		t.Fatalf("reply recipient %s, want %s", info.Recipient, key.Recipient())
	}
	r, err := sopsplugin.DecodeIdentity(info.Identity)
	if err != nil {
		t.Fatalf("the pointer the daemon returned does not decode: %v", err)
	}
	if r.String() != key.Recipient().String() {
		t.Fatalf("the pointer decodes to %s, want %s", r, key.Recipient())
	}
	if stored := f.stored(t, "personal"); stored.Key.String() != key.String() {
		t.Fatal("the stored key is not the one that was imported")
	}

	assertNoKeyInReply(t, resp, key)
	if raw := f.log.raw(t); strings.Contains(raw, key.String()) {
		t.Fatal("SECURITY: the audit log carries the imported private key")
	}
	assertAuditDetails(t, f.log)
}

// TestSopsPutRejectsAValueThatIsNotAKey: junk in the value slot is a client fault, refused
// with CodeBadRequest — and the message must not echo what was sent. The caller may well
// have sent a real key that merely failed to parse for a reason it will print to a log.
func TestSopsPutRejectsAValueThatIsNotAKey(t *testing.T) {
	f := newSopsFixture(t)
	f.open(t)

	const junk = "AGE-SECRET-KEY-1NOT-A-REAL-KEY-BUT-SHAPED-LIKE-ONE"
	resp := f.put(t, "personal", "", []byte(junk), false)
	if resp.Error == nil || resp.Error.Code != ipc.CodeBadRequest {
		t.Fatalf("resp.Error = %+v, want CodeBadRequest (%d)", resp.Error, ipc.CodeBadRequest)
	}
	if strings.Contains(resp.Error.Message, junk) {
		t.Fatalf("the error echoed the value back: %q", resp.Error.Message)
	}
	if !strings.Contains(resp.Error.Message, "personal") {
		t.Fatalf("message = %q, want it to name the identity being imported", resp.Error.Message)
	}
	if _, err := sopsplugin.NewStore(f.vault, f.vault).Get("personal"); err == nil {
		t.Fatal("a rejected import still wrote to the vault")
	}
}

// TestSopsImportedKeyThenUnwraps is the proof that the management surface and the unwrap
// path agree. `av sops import` stores a key through sops_put; every later `sops -d` reaches
// it through sops_unwrap, keyed by RECIPIENT. If the two disagreed about the envelope, the
// recipient derivation, or the tier, both halves would still pass their own tests and the
// feature would work for nobody.
func TestSopsImportedKeyThenUnwraps(t *testing.T) {
	const payload = "kind: Secret\ndata:\n  password: hunter2\n"
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	f := newSopsFixture(t)
	f.open(t)

	info := sopsInfo(t, f.put(t, "imported", "", []byte(key.String()), false))

	// The unwrap is keyed by the recipient the IMPORT reply reported — the string a user
	// would paste into .sops.yaml — not by key.Recipient() taken from the test's own copy.
	// That closes the loop: what the daemon told the user to encrypt to is what the daemon
	// can decrypt. A recipient reported wrong would fail here as CodeNoMatch.
	recipient, err := age.ParseX25519Recipient(info.Recipient)
	if err != nil {
		t.Fatalf("the reported recipient does not parse: %v", err)
	}
	ct, stanzas, want := sopsFile(t, key, payload) // stock age, no plugin on the write side
	res := sopsResult(t, f.unwrap(t, recipient, stanzas, false))
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
	assertAuditDetails(t, f.log)
}

// TestSopsListNeverCarriesAPrivateKey: `av sops ls` output lands in terminals, CI logs and
// screenshots. The reply carries names, tiers, recipients and pointers — and is asserted
// against BOTH seeded keys, in the order List promises.
func TestSopsListNeverCarriesAPrivateKey(t *testing.T) {
	work, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	personal, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	f := newSopsFixture(t)
	f.seed(t, "work", work, sopsplugin.TierDangerous)
	f.seed(t, "personal", personal, sopsplugin.TierNormal)
	f.open(t)

	resp := f.list(t, false)
	got := sopsListed(t, resp)
	if len(got) != 2 {
		t.Fatalf("listed %d identities, want 2", len(got))
	}
	// Sorted by name, because the vault is a map: an unsorted listing would reshuffle on
	// every `av sops ls` against an unchanged vault.
	if got[0].Name != "personal" || got[1].Name != "work" {
		t.Fatalf("listed %q then %q, want personal then work", got[0].Name, got[1].Name)
	}
	if got[0].Tier != string(sopsplugin.TierNormal) || got[1].Tier != string(sopsplugin.TierDangerous) {
		t.Fatalf("tiers = %q, %q; want normal, dangerous", got[0].Tier, got[1].Tier)
	}
	for i, key := range []*age.X25519Identity{personal, work} {
		if got[i].Recipient != key.Recipient().String() {
			t.Fatalf("%q: recipient = %s, want %s", got[i].Name, got[i].Recipient, key.Recipient())
		}
		// Every listed identity carries a working pointer, which is what lets
		// `av sops identity NAME` be a printer over this reply instead of an RPC of its own.
		r, err := sopsplugin.DecodeIdentity(got[i].Identity)
		if err != nil {
			t.Fatalf("%q: pointer does not decode: %v", got[i].Name, err)
		}
		if r.String() != key.Recipient().String() {
			t.Fatalf("%q: pointer decodes to the wrong recipient", got[i].Name)
		}
		assertNoKeyInReply(t, resp, key)
	}
	// A listing mutates nothing, so it must leave no mutation entry behind.
	for _, e := range f.log.all() {
		if strings.HasPrefix(e.Kind, "sops_") {
			t.Fatalf("a listing wrote an audit entry: %+v", e)
		}
	}
}

// TestSopsRmRemovesAndReportsAnAbsentName: rm deletes the named identity, and a name nobody
// stored is a CLEAN not-found rather than a silent success.
//
// The distinction is the whole reason Store.Remove returns ErrNotFound: this command
// destroys the only copy of a key, so "removed" over a typo would leave a user believing a
// key is gone that is still there — or that the right one went when it did not.
func TestSopsRmRemovesAndReportsAnAbsentName(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	f := newSopsFixture(t)
	f.seed(t, "work", key, sopsplugin.TierNormal)
	f.open(t)

	if resp := f.rm(t, "work", false); resp.Error != nil {
		t.Fatalf("rm of a stored identity failed: %+v", resp.Error)
	}
	if got := sopsListed(t, f.list(t, false)); len(got) != 0 {
		t.Fatalf("after rm the vault still lists %d identities", len(got))
	}

	// The same name a second time: gone is gone, and it says so.
	resp := f.rm(t, "work", false)
	if resp.Error == nil || resp.Error.Code != ipc.CodeBadRequest {
		t.Fatalf("rm of an absent name: %+v, want CodeBadRequest (%d)", resp.Error, ipc.CodeBadRequest)
	}
	if !strings.Contains(resp.Error.Message, "work") {
		t.Fatalf("message = %q, want it to name what was not found", resp.Error.Message)
	}

	// Exactly one mutation was audited: the one that happened.
	var rms int
	for _, e := range f.log.all() {
		if e.Kind == "sops_rm" {
			rms++
			if e.Name != "work" {
				t.Fatalf("audit entry Name = %q, want work", e.Name)
			}
		}
	}
	if rms != 1 {
		t.Fatalf("%d sops_rm audit entries, want 1 — a refused rm removed nothing and must log nothing", rms)
	}
	assertAuditDetails(t, f.log)
}

// TestSopsRmClearsACorruptEntry is why sops_rm does NOT validate the name it is given.
//
// A junk entry under sops/ — written by hand, or by an `av add` predating the namespace
// guard — fails `av sops ls` for every healthy key beside it (Store.List is strict on
// purpose). This RPC is the ONLY way to delete anything under that namespace, since
// `av rm sops/notes` is refused, so a name that Put would reject must still be removable or
// the user has no way back to a working listing.
func TestSopsRmClearsACorruptEntry(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	f := newSopsFixture(t)
	f.seed(t, "work", key, sopsplugin.TierNormal)
	f.seedJunk(t, "notes", "reminder: rotate this in June")
	f.open(t)

	if resp := f.list(t, false); resp.Error == nil {
		t.Fatal("a corrupt entry must fail the listing — that is the diagnostic this recovers from")
	}
	if resp := f.rm(t, "notes", false); resp.Error != nil {
		t.Fatalf("rm of a corrupt entry failed: %+v — nothing else can delete it", resp.Error)
	}
	if got := sopsListed(t, f.list(t, false)); len(got) != 1 || got[0].Name != "work" {
		t.Fatalf("after clearing the junk, listing = %+v, want just work", got)
	}
}

// TestSopsManageRejectsBadNamesAndTiersBeforeUnlocking pins the ORDERING, which is the
// reason the validation rule is exported from sopsplugin instead of left to Store.Put.
//
// The fixture is LOCKED and every call sets NoPrompt, so anything checked after the unlock
// gate comes back CodeLocked. Getting CodeBadRequest here therefore proves the check ran
// FIRST — and that matters twice over: a request that was always going to be refused must
// not cost a Touch ID, and an agent told "locked" would go ask a human to unlock, retry the
// identical broken request, and be told "locked" again forever.
func TestSopsManageRejectsBadNamesAndTiersBeforeUnlocking(t *testing.T) {
	f := newSopsFixture(t) // deliberately LOCKED

	cases := []struct {
		what string
		resp func() ipc.Response
		want string // a fragment the message must name
	}{
		{"empty name", func() ipc.Response { return f.keygen(t, "", "", true) }, "name"},
		{"name with a slash", func() ipc.Response { return f.keygen(t, "nested/name", "", true) }, "slash"},
		{"unknown tier", func() ipc.Response { return f.keygen(t, "work", "paranoid", true) }, "tier"},
		{"import: empty name", func() ipc.Response { return f.put(t, "", "", []byte("x"), true) }, "name"},
		{"import: unknown tier", func() ipc.Response { return f.put(t, "work", "normla", []byte("x"), true) }, "tier"},
	}
	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			resp := c.resp()
			if resp.Error == nil || resp.Error.Code != ipc.CodeBadRequest {
				t.Fatalf("resp.Error = %+v, want CodeBadRequest (%d) — a locked vault answering CodeLocked means the check runs too late", resp.Error, ipc.CodeBadRequest)
			}
			if !strings.Contains(resp.Error.Message, c.want) {
				t.Fatalf("message = %q, want it to name the %s", resp.Error.Message, c.want)
			}
		})
	}
	if p, u := f.auth.counts(); p != 0 || u != 0 {
		t.Fatalf("invalid requests cost %d prompts + %d unwraps, want 0 + 0", p, u)
	}
}

// TestSopsManageLockedNoPromptIsLocked: each management RPC gates on the session, so an
// agent (AV_NO_PROMPT) meeting a locked vault gets CodeLocked and no biometric — the same
// clean exit-69 pause every other command gives it.
//
// The message must name the OPERATION that was refused. Task 8 gave the sops path a bespoke
// locked message because the unwrap path's text reaches a human unedited; carrying the word
// "unwrap" over to these would have `av sops ls` report a decryption that never happened.
func TestSopsManageLockedNoPromptIsLocked(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		method string
		op     string
		call   func(f *sopsFixture) ipc.Response
	}{
		// The op word is the SUBCOMMAND's, not the method's: a person who ran `av sops
		// import` must not be told about a "put" they never typed. See sopsLockedMsg.
		{"sops_keygen", "keygen", func(f *sopsFixture) ipc.Response { return f.keygen(t, "work", "", true) }},
		{"sops_put", "import", func(f *sopsFixture) ipc.Response { return f.put(t, "work", "", []byte(key.String()), true) }},
		{"sops_list", "ls", func(f *sopsFixture) ipc.Response { return f.list(t, true) }},
		{"sops_rm", "rm", func(f *sopsFixture) ipc.Response { return f.rm(t, "work", true) }},
	}
	for _, c := range cases {
		t.Run(c.method, func(t *testing.T) {
			f := newSopsFixture(t) // deliberately LOCKED
			resp := c.call(f)
			if resp.Error == nil || resp.Error.Code != ipc.CodeLocked {
				t.Fatalf("resp.Error = %+v, want CodeLocked (%d)", resp.Error, ipc.CodeLocked)
			}
			if !strings.Contains(resp.Error.Message, c.op) {
				t.Fatalf("message = %q, want it to name the %s operation rather than another one", resp.Error.Message, c.op)
			}
			if !strings.Contains(resp.Error.Message, "av unlock") {
				t.Fatalf("message = %q, want it to name `av unlock`", resp.Error.Message)
			}
			if p, u := f.auth.counts(); p != 0 || u != 0 {
				t.Fatalf("NoPrompt spent %d prompts + %d unwraps, want 0 + 0", p, u)
			}
			// Refused, so nothing was written: the keygen case would otherwise have minted
			// and stored a key on a vault the caller was told it could not touch.
			if _, err := sopsplugin.NewStore(f.vault, f.vault).Get("work"); err == nil && c.method != "sops_rm" {
				t.Fatal("a locked-and-refused request still wrote to the vault")
			}
		})
	}
}

// TestSopsManageAuditRecordsNamesOnly: every mutation leaves ONE entry naming the identity,
// and the audit output holds no key material.
//
// The leak assertion that actually holds is assertAuditDetails' closed set of Detail
// literals — a Detail built from anything else is caught whatever encoding the accident
// used. The scan below it is asserted against a REAL key and is a backstop, not the
// assertion; see sopsAuditDetails.
func TestSopsManageAuditRecordsNamesOnly(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	f := newSopsFixture(t)
	f.open(t)

	sopsInfo(t, f.keygen(t, "generated", string(sopsplugin.TierDangerous), false))
	sopsInfo(t, f.put(t, "imported", string(sopsplugin.TierNormal), []byte(key.String()), false))
	generated := f.stored(t, "generated").Key
	if resp := f.rm(t, "generated", false); resp.Error != nil {
		t.Fatalf("rm: %+v", resp.Error)
	}

	want := map[string]string{"sops_keygen": "generated", "sops_put": "imported", "sops_rm": "generated"}
	seen := map[string]int{}
	for _, e := range f.log.all() {
		name, ok := want[e.Kind]
		if !ok {
			continue
		}
		seen[e.Kind]++
		if e.Name != name {
			t.Fatalf("%s entry Name = %q, want %q", e.Kind, e.Name, name)
		}
	}
	for kind := range want {
		if seen[kind] != 1 {
			t.Fatalf("%d %s audit entries, want 1", seen[kind], kind)
		}
	}
	assertAuditDetails(t, f.log)

	raw := f.log.raw(t)
	for _, k := range []*age.X25519Identity{key, generated} {
		// SECURITY: raw is not printed — it would hold the leak.
		if strings.Contains(raw, k.String()) {
			t.Fatal("SECURITY: the audit output leaked a private key")
		}
	}
	if strings.Contains(raw, "AGE-SECRET-KEY") {
		t.Fatal("SECURITY: the audit output contains something shaped like an age private key")
	}
}
