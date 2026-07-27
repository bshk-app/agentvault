package sopsplugin_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/backend/agefile"
	"github.com/beshkenadze/agentvault/internal/sopsplugin"
)

// fakeVault is an in-memory stand-in for the age vault, implementing both halves of the
// backend contract the Store builds on. It mirrors agefile's semantics exactly where the
// Store depends on them — ErrNotFound on a missing locator, prefix-filtered List, Remove
// reporting a no-op — so a test passing here means the same thing it would against the
// real vault. TestStoreOverTheRealVault keeps that claim honest.
type fakeVault struct{ data map[string]string }

func newFakeVault() *fakeVault { return &fakeVault{data: map[string]string{}} }

func (f *fakeVault) Resolve(loc string) (backend.Secret, error) {
	v, ok := f.data[loc]
	if !ok {
		return backend.Secret{}, backend.ErrNotFound
	}
	return backend.Secret{Value: v}, nil
}

func (f *fakeVault) List(prefix string) ([]backend.Meta, error) {
	var out []backend.Meta
	for k := range f.data {
		if strings.HasPrefix(k, prefix) {
			out = append(out, backend.Meta{Locator: k})
		}
	}
	return out, nil
}

func (f *fakeVault) Add(name, value string) error {
	f.data[name] = value
	return nil
}

func (f *fakeVault) Remove(name string) error {
	if _, ok := f.data[name]; !ok {
		return backend.ErrNotFound
	}
	delete(f.data, name)
	return nil
}

func newTestStore(t *testing.T) (*sopsplugin.Store, *fakeVault) {
	t.Helper()
	v := newFakeVault()
	return sopsplugin.NewStore(v, v), v
}

func genKey(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestPutGetRoundTrip is the base contract: what goes in comes back out, byte for byte.
// Everything else in the store is worthless if the key that returns is not the key that
// was stored — the file it was meant to decrypt would simply fail with no clue why.
func TestPutGetRoundTrip(t *testing.T) {
	s, _ := newTestStore(t)
	key := genKey(t)

	if err := s.Put("work", key, sopsplugin.TierNormal); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("work")
	if err != nil {
		t.Fatal(err)
	}
	if got.Key.String() != key.String() {
		t.Fatal("round trip changed the private key") // never print either side
	}
	if got.Name != "work" {
		t.Errorf("Name = %q, want %q", got.Name, "work")
	}
	if got.Tier != sopsplugin.TierNormal {
		t.Errorf("Tier = %q, want %q", got.Tier, sopsplugin.TierNormal)
	}
}

// TestPutPreservesTier pins the reason the stored value is an envelope rather than a bare
// key. Task 6 reads this field to decide whether a file costs its own presence check, so a
// tier that silently reverts to normal on the way through the vault would downgrade a
// dangerous identity to one-touch-per-command without anything visibly breaking.
func TestPutPreservesTier(t *testing.T) {
	s, _ := newTestStore(t)
	for _, tier := range []sopsplugin.Tier{sopsplugin.TierNormal, sopsplugin.TierDangerous} {
		t.Run(string(tier), func(t *testing.T) {
			if err := s.Put("k", genKey(t), tier); err != nil {
				t.Fatal(err)
			}
			got, err := s.Get("k")
			if err != nil {
				t.Fatal(err)
			}
			if got.Tier != tier {
				t.Fatalf("Tier = %q, want %q", got.Tier, tier)
			}
		})
	}
}

// TestPutDefaultsEmptyTier: the zero Tier is what a caller that has not been taught about
// tiers passes, and the documented default is normal. Erroring instead would make Tier a
// required argument in every future call site for no gain.
func TestPutDefaultsEmptyTier(t *testing.T) {
	s, _ := newTestStore(t)
	if err := s.Put("k", genKey(t), ""); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("k")
	if err != nil {
		t.Fatal(err)
	}
	if got.Tier != sopsplugin.TierNormal {
		t.Fatalf("Tier = %q, want %q", got.Tier, sopsplugin.TierNormal)
	}
}

// TestPutRejectsBadInput guards the write side, which is where a mistake is still cheap to
// fix. An unknown tier is rejected here rather than at read time on purpose: `av sops
// keygen NAME --tier typo` must fail at the prompt, not months later when the identity
// quietly turns out to be normal-tier.
func TestPutRejectsBadInput(t *testing.T) {
	s, v := newTestStore(t)
	key := genKey(t)

	if err := s.Put("", key, sopsplugin.TierNormal); err == nil {
		t.Error("want an error for an empty name, got nil")
	}
	if err := s.Put("k", key, "paranoid"); err == nil {
		t.Error("want an error for an unknown tier, got nil")
	} else if strings.Contains(err.Error(), key.String()) {
		t.Error("SECURITY: the error carries the private key")
	}
	// A slash does not escape the namespace — sops/nested/name is still under it — but the
	// name stops round-tripping: List trims only the prefix, so it reads back as
	// "nested/name" and `av sops ls` can no longer show one name per identity.
	if err := s.Put("nested/name", key, sopsplugin.TierNormal); err == nil {
		t.Error("want an error for a name containing a slash, got nil")
	}
	if len(v.data) != 0 {
		t.Fatalf("a rejected Put still wrote to the vault: %v", v.data)
	}
}

// TestListNeverReturnsAPrivateKey is the property the sops/ namespace exists to protect.
// List feeds `av sops ls`, whose output lands on terminals, in CI logs, and in screenshots.
// Info carries no key field today, so this assertion is about the future: it fails the
// moment somebody adds one "just for convenience", which is exactly how this class of leak
// gets introduced.
func TestListNeverReturnsAPrivateKey(t *testing.T) {
	s, _ := newTestStore(t)
	keys := map[string]*age.X25519Identity{"work": genKey(t), "personal": genKey(t)}
	for name, key := range keys {
		if err := s.Put(name, key, sopsplugin.TierDangerous); err != nil {
			t.Fatal(err)
		}
	}

	infos, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != len(keys) {
		t.Fatalf("List returned %d identities, want %d", len(infos), len(keys))
	}

	// Render the whole result the way a careless caller would and search it. %+v walks
	// every exported field, so a key added anywhere in Info is caught, not just a field
	// this test knows to look at.
	rendered := fmt.Sprintf("%+v", infos)
	if strings.Contains(rendered, "AGE-SECRET-KEY") {
		t.Fatal("SECURITY: List output contains an age private key")
	}
	for _, key := range keys {
		if strings.Contains(rendered, key.String()) {
			t.Fatal("SECURITY: List output contains a stored private key")
		}
	}

	for _, got := range infos {
		key, ok := keys[got.Name]
		if !ok {
			t.Fatalf("List returned an unknown identity %q", got.Name)
		}
		if got.Recipient != key.Recipient().String() {
			t.Errorf("%s: Recipient = %q, want %q", got.Name, got.Recipient, key.Recipient().String())
		}
		if got.Tier != sopsplugin.TierDangerous {
			t.Errorf("%s: Tier = %q, want %q", got.Name, got.Tier, sopsplugin.TierDangerous)
		}
	}
}

// TestIdentityNeverRendersItsPrivateKey is TestListNeverReturnsAPrivateKey's assertion
// pointed at the type that actually carries a key. Info cannot leak — it has no key field —
// while Identity is the struct that reaches the daemon and the audit log, so this is the
// one that had to be guarded.
//
// The leak it closes is not hypothetical: age.X25519Identity.String() IS the
// AGE-SECRET-KEY-1… text, and fmt applies Stringer to struct fields, so before Identity had
// a String method of its own, `fmt.Errorf("sops unwrap %v: %w", id, err)` — a line Task 6
// would write without a second thought — put a private key into an error string. Nothing in
// internal/daemon calls recover(), so that string reaches a crash dump too. Every verb a
// caller might reach for is checked, plus the containers fmt recurses into.
func TestIdentityNeverRendersItsPrivateKey(t *testing.T) {
	s, _ := newTestStore(t)
	key := genKey(t)
	if err := s.Put("work", key, sopsplugin.TierDangerous); err != nil {
		t.Fatal(err)
	}
	id, err := s.Get("work")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ what, rendered string }{
		{"%v", fmt.Sprintf("%v", id)},
		{"%+v", fmt.Sprintf("%+v", id)},
		{"%s", fmt.Sprintf("%s", id)},
		{"pointer", fmt.Sprintf("%v", &id)},
		{"inside a slice", fmt.Sprintf("%+v", []sopsplugin.Identity{id})},
		{"wrapped in an error", fmt.Errorf("sops unwrap %v: %w", id, errors.New("boom")).Error()},
	} {
		if strings.Contains(tc.rendered, "AGE-SECRET-KEY") || strings.Contains(tc.rendered, key.String()) {
			t.Errorf("SECURITY: %s rendered the private key", tc.what)
		}
		// The rendering also has to stay useful. If it said nothing, callers would reach
		// past it for the fields and print those instead, and the guard would buy nothing.
		if !strings.Contains(tc.rendered, "work") {
			t.Errorf("%s = %q, want it to name the identity", tc.what, tc.rendered)
		}
	}

	// %#v is the one verb a Stringer cannot intercept. It is checked rather than assumed:
	// the fix is only complete because Go renders the key as a pointer address there.
	if got := fmt.Sprintf("%#v", id); strings.Contains(got, "AGE-SECRET-KEY") || strings.Contains(got, key.String()) {
		t.Errorf("SECURITY: %%#v rendered the private key: %s", got)
	}
}

// TestListIsSorted: `av sops ls` reads this directly, and the vault is a map, so without
// an explicit sort the same vault prints in a different order on every invocation.
func TestListIsSorted(t *testing.T) {
	s, _ := newTestStore(t)
	for _, name := range []string{"zulu", "alpha", "mike"} {
		if err := s.Put(name, genKey(t), sopsplugin.TierNormal); err != nil {
			t.Fatal(err)
		}
	}
	infos, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, i := range infos {
		got = append(got, i.Name)
	}
	if want := []string{"alpha", "mike", "zulu"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("List order = %v, want %v", got, want)
	}
}

// TestFindByRecipient covers the lookup the sops_unwrap RPC performs on every file: it
// arrives holding a recipient and must find the one identity that can unwrap for it. With
// several identities stored, picking the wrong one produces a decryption failure rather
// than an error that names the mismatch, so "finds the right one" is asserted, not just
// "finds one".
func TestFindByRecipient(t *testing.T) {
	s, _ := newTestStore(t)
	want := genKey(t)
	if err := s.Put("work", want, sopsplugin.TierDangerous); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"personal", "archive"} {
		if err := s.Put(name, genKey(t), sopsplugin.TierNormal); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.FindByRecipient(want.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "work" {
		t.Fatalf("matched %q, want %q", got.Name, "work")
	}
	if got.Key.String() != want.String() {
		t.Fatal("matched identity carries the wrong private key")
	}
	// The tier travels with the match because the caller decides on presence before
	// unwrapping, and it has only this struct to decide from.
	if got.Tier != sopsplugin.TierDangerous {
		t.Errorf("Tier = %q, want %q", got.Tier, sopsplugin.TierDangerous)
	}
}

// TestFindByRecipientMatchesAcrossParsedAndEncodedForms is the trap Task 2 left behind: the
// recipient reaches the daemon as the bech32 age1… TEXT of the key, not its 32 raw bytes,
// so any comparison that assumes raw bytes silently never matches. Feeding back a recipient
// that has been round-tripped through the identity encoding — the exact path a real unwrap
// takes — proves the match survives it.
func TestFindByRecipientMatchesAcrossParsedAndEncodedForms(t *testing.T) {
	s, _ := newTestStore(t)
	key := genKey(t)
	if err := s.Put("work", key, sopsplugin.TierNormal); err != nil {
		t.Fatal(err)
	}

	// EncodeIdentity → DecodeIdentity round-trips the pointer `av sops identity` prints,
	// which is the form that reaches keys.txt. It is a verification of that ENCODING, not a
	// replay of the wire: age decodes the line on its own side and hands the plugin the
	// payload, so DecodeIdentity is the test's inverse rather than a production hop.
	wire, err := sopsplugin.DecodeIdentity(sopsplugin.EncodeIdentity(key.Recipient()))
	if err != nil {
		t.Fatal(err)
	}
	// A separately parsed recipient is a DIFFERENT pointer with the same value; matching
	// must be on the key material, never on pointer identity.
	reparsed, err := age.ParseX25519Recipient(key.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}

	for name, r := range map[string]*age.X25519Recipient{"from identity": wire, "reparsed": reparsed} {
		t.Run(name, func(t *testing.T) {
			got, err := s.FindByRecipient(r)
			if err != nil {
				t.Fatal(err)
			}
			if got.Name != "work" {
				t.Fatalf("matched %q, want %q", got.Name, "work")
			}
		})
	}
}

// TestFindByRecipientUnknown pins the error VALUE, not just that one is returned. Task 6
// maps it to CodeBadRequest and, critically, returns before spending a presence prompt: a
// `kustomize build` over a repo full of files encrypted to other people must cost zero
// touches. Any other error there would be an internal error and a different code path.
func TestFindByRecipientUnknown(t *testing.T) {
	s, _ := newTestStore(t)
	if err := s.Put("work", genKey(t), sopsplugin.TierNormal); err != nil {
		t.Fatal(err)
	}

	stranger := genKey(t)
	got, err := s.FindByRecipient(stranger.Recipient())
	if !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("err = %v, want backend.ErrNotFound", err)
	}
	if got.Key != nil {
		t.Error("want a zero Identity alongside the error")
	}
}

// TestFindByRecipientEmptyStore: no identities at all must look like no match, not like a
// broken vault. A user who has never run `av sops import` gets here on their first sops
// invocation.
func TestFindByRecipientEmptyStore(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.FindByRecipient(genKey(t).Recipient()); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("err = %v, want backend.ErrNotFound", err)
	}
}

// TestFindByRecipientSurvivesACorruptNeighbour is the cost of sharing one vault: the sops/
// namespace is not write-protected, and `av add sops/notes "reminder: rotate in June"`
// lands in it without a word from anyone. A value that is not an identity must not brick
// decryption for the keys that are — and it did, because the scan aborted on the first
// entry that failed to decode. The user-visible shape of that bug is the nasty part: `av
// sops ls` and `av sops recipient work` keep printing the healthy key while every single
// unwrap fails.
func TestFindByRecipientSurvivesACorruptNeighbour(t *testing.T) {
	s, v := newTestStore(t)
	key := genKey(t)
	if err := s.Put("work", key, sopsplugin.TierDangerous); err != nil {
		t.Fatal(err)
	}
	v.data["sops/notes"] = "reminder: rotate this in June"

	got, err := s.FindByRecipient(key.Recipient())
	if err != nil {
		t.Fatalf("a junk entry beside a healthy key broke its lookup: %v", err)
	}
	if got.Name != "work" || got.Key.String() != key.String() {
		t.Fatal("matched the wrong identity")
	}
	if got.Tier != sopsplugin.TierDangerous {
		t.Errorf("Tier = %q, want %q", got.Tier, sopsplugin.TierDangerous)
	}

	// Tolerating the junk entry must not soften the other half of the contract: with
	// nothing matched, the corrupt entry is still reported, because Task 6 maps a corrupt
	// store to an internal error and an unknown recipient to a bad request. Reporting the
	// wrong one of those is how a broken vault gets mistaken for a file that is simply
	// not ours.
	if _, err := s.FindByRecipient(genKey(t).Recipient()); err == nil {
		t.Error("want the corrupt entry reported when nothing matched")
	} else if errors.Is(err, backend.ErrNotFound) {
		t.Error("a corrupt entry was reported as a missing one")
	}
	// List stays strict either way: it is the diagnostic surface, and the place the user
	// goes to find out why. Hiding the bad entry there would leave them with no surface
	// that shows it at all.
	if _, err := s.List(); err == nil {
		t.Error("List hid the corrupt entry")
	}
}

// TestFindByRecipientNil: the daemon dispatches every connection as its own goroutine and
// nothing above it calls recover(), so a nil dereference in this path would not fail one
// request — it would take avd down for every client holding a connection. A nil recipient
// matches nothing, which is precisely what ErrNotFound already means.
func TestFindByRecipientNil(t *testing.T) {
	s, _ := newTestStore(t)
	if err := s.Put("work", genKey(t), sopsplugin.TierNormal); err != nil {
		t.Fatal(err)
	}
	got, err := s.FindByRecipient(nil)
	if !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("err = %v, want backend.ErrNotFound", err)
	}
	if got.Key != nil {
		t.Error("want a zero Identity alongside the error")
	}
}

// TestNamespaceIsolation is the other half of what the prefix buys. Ordinary secrets and
// SOPS identities share one vault, so the store must be blind to everything outside sops/
// (or `av sops ls` starts listing the user's API tokens) and must never write where an
// ordinary secret lives (or storing an identity named GITHUB_TOKEN would silently destroy
// the token of that name).
func TestNamespaceIsolation(t *testing.T) {
	s, v := newTestStore(t)
	v.data["GITHUB_TOKEN"] = "ghp_ordinary_secret"
	v.data["sopsy"] = "not in the namespace: no trailing slash"

	key := genKey(t)
	if err := s.Put("GITHUB_TOKEN", key, sopsplugin.TierNormal); err != nil {
		t.Fatal(err)
	}

	if v.data["GITHUB_TOKEN"] != "ghp_ordinary_secret" {
		t.Fatal("storing an identity overwrote the ordinary secret of the same name")
	}
	if _, ok := v.data["sops/GITHUB_TOKEN"]; !ok {
		t.Fatalf("identity was not stored under the namespace: %v", keysOf(v))
	}

	infos, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].Name != "GITHUB_TOKEN" {
		t.Fatalf("List = %+v, want only the namespaced identity", infos)
	}

	// The ordinary secret is not reachable through the store even by its exact vault key.
	for _, name := range []string{"GITHUB_TOKEN", "../GITHUB_TOKEN", "sopsy"} {
		if _, err := s.Get(name); name == "GITHUB_TOKEN" {
			// This one exists as an identity; the point is that Get returned the
			// identity, not the plain "ghp_ordinary_secret" sitting beside it.
			if err != nil {
				t.Fatalf("Get(%q): %v", name, err)
			}
		} else if !errors.Is(err, backend.ErrNotFound) {
			t.Errorf("Get(%q) err = %v, want backend.ErrNotFound", name, err)
		}
	}
}

// TestGetMissing: a name nobody stored is ErrNotFound, so `av sops recipient typo` says so
// instead of failing as something internal.
func TestGetMissing(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.Get("nope"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("err = %v, want backend.ErrNotFound", err)
	}
}

// TestRemove covers `av sops rm`, which is the destructive command in this feature:
// deleting the only copy of a key permanently destroys every file encrypted to it. The
// second call asserting ErrNotFound is what lets the command tell "deleted" apart from
// "there was nothing there", so it can never report success over a typo'd name.
func TestRemove(t *testing.T) {
	s, v := newTestStore(t)
	v.data["GITHUB_TOKEN"] = "ghp_ordinary_secret"
	if err := s.Put("work", genKey(t), sopsplugin.TierNormal); err != nil {
		t.Fatal(err)
	}

	if err := s.Remove("work"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("work"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("identity survived Remove: %v", err)
	}
	if err := s.Remove("work"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("second Remove err = %v, want backend.ErrNotFound", err)
	}
	if err := s.Remove("GITHUB_TOKEN"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("Remove reached outside the namespace: %v", err)
	}
	if v.data["GITHUB_TOKEN"] != "ghp_ordinary_secret" {
		t.Fatal("Remove deleted an ordinary secret")
	}
}

// TestReadsToleratesHandEditedEntries: the vault plaintext is JSON a human can edit after
// decrypting it, and entries written before tiers existed are bare keys. Both must still
// resolve — refusing them would lock a user out of a key that is sitting right there, which
// is a worse outcome than assuming the documented default tier.
//
// Tolerance has a direction. An UNRECOGNISED tier reads as dangerous, not normal: dangerous
// only ever costs extra presence checks, normal skips them, so a wrong guess this way is
// friction and a wrong guess the other way is a silent downgrade. The concrete case is a
// third tier shipped in a later release and then avd rolled back — the older binary must
// not read a tier it has never heard of as the cheapest one. An ABSENT or empty tier is a
// different thing entirely: that is the pre-tier format, whose documented default is normal.
func TestReadsToleratesHandEditedEntries(t *testing.T) {
	key := genKey(t)
	for _, tc := range []struct {
		name  string
		value string
		want  sopsplugin.Tier
	}{
		{"bare key, no envelope", key.String(), sopsplugin.TierNormal},
		{"envelope without a tier", fmt.Sprintf(`{"key":%q}`, key.String()), sopsplugin.TierNormal},
		{"envelope with an empty tier", fmt.Sprintf(`{"key":%q,"tier":""}`, key.String()), sopsplugin.TierNormal},
		{"envelope with an unknown tier", fmt.Sprintf(`{"key":%q,"tier":"paranoid"}`, key.String()), sopsplugin.TierDangerous},
		{"envelope with an unknown field", fmt.Sprintf(`{"key":%q,"tier":"dangerous","future":1}`, key.String()), sopsplugin.TierDangerous},
		// A trailing newline is the likeliest artefact of a hand edit of all — every
		// editor adds one — and the bare-key path was the only one rejecting it, since
		// encoding/json hands the envelope that tolerance for free.
		{"bare key with a trailing newline", key.String() + "\n", sopsplugin.TierNormal},
		{"envelope with surrounding whitespace", fmt.Sprintf("  {\"key\":%q,\"tier\":\"dangerous\"}\n", key.String()), sopsplugin.TierDangerous},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, v := newTestStore(t)
			v.data["sops/legacy"] = tc.value

			got, err := s.Get("legacy")
			if err != nil {
				t.Fatal(err)
			}
			if got.Key.String() != key.String() {
				t.Fatal("hand-edited entry decoded to the wrong private key")
			}
			if got.Tier != tc.want {
				t.Fatalf("Tier = %q, want %q", got.Tier, tc.want)
			}
			// The same entry has to survive the other two read paths, since a user who
			// hand-edited one is going to run `av sops ls` next.
			if _, err := s.List(); err != nil {
				t.Fatalf("List: %v", err)
			}
			if _, err := s.FindByRecipient(key.Recipient()); err != nil {
				t.Fatalf("FindByRecipient: %v", err)
			}
		})
	}
}

// TestCorruptEntriesErrorWithoutEchoingTheValue covers the entries that are NOT salvageable.
// Two things are asserted and both matter: the read fails loudly rather than reporting the
// identity as absent (a user whose entry got mangled must be told, not left with "no
// identity matched"), and the message names the identity and nothing else. The string being
// decoded is a private key, and age's own parse errors report the position and value of the
// first character they reject (internal/bech32/bech32.go:154,161) — never the whole key, but
// close enough to it that wrapping them buys nothing worth the exposure.
func TestCorruptEntriesErrorWithoutEchoingTheValue(t *testing.T) {
	key := genKey(t)
	for _, tc := range []struct{ name, value string }{
		{"truncated key", key.String()[:20]},
		{"not a key at all", "hunter2"},
		{"malformed envelope", `{"key": `},
		{"envelope holding a recipient", fmt.Sprintf(`{"key":%q}`, key.Recipient().String())},
		{"envelope holding nothing", `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, v := newTestStore(t)
			v.data["sops/broken"] = tc.value

			_, err := s.Get("broken")
			if err == nil {
				t.Fatal("want an error for a corrupt entry, got nil")
			}
			if errors.Is(err, backend.ErrNotFound) {
				t.Fatal("a corrupt entry must not be reported as a missing one")
			}
			if !strings.Contains(err.Error(), "broken") {
				t.Errorf("error should name the identity, got: %v", err)
			}
			if strings.Contains(err.Error(), tc.value) {
				t.Errorf("SECURITY: error echoes the stored value back: %v", err)
			}
			// The scanning paths must be just as loud: a corrupt entry that silently
			// vanished from List would look exactly like a deleted one. FindByRecipient
			// reports it here because nothing else in the store matched — see
			// TestFindByRecipientSurvivesACorruptNeighbour for why a match outranks it.
			if _, err := s.List(); err == nil {
				t.Error("List skipped a corrupt entry instead of reporting it")
			}
			if _, err := s.FindByRecipient(key.Recipient()); err == nil {
				t.Error("FindByRecipient skipped a corrupt entry instead of reporting it")
			}
		})
	}
}

// TestStoreOverTheRealVault runs the round trip through the actual encrypted vault rather
// than the fake. It is here because the envelope is JSON nested inside the vault's own JSON
// plaintext, and a quoting mistake in that nesting is invisible to an in-memory map.
func TestStoreOverTheRealVault(t *testing.T) {
	vaultID := genKey(t)
	path := filepath.Join(t.TempDir(), "vault.age")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := agefile.EncryptVault(f, vaultID.Recipient(), map[string]string{"GITHUB_TOKEN": "ghp_ordinary"}); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	b := agefile.New(agefile.Static{ID: vaultID}, path)
	s := sopsplugin.NewStore(b, b)

	key := genKey(t)
	if err := s.Put("work", key, sopsplugin.TierDangerous); err != nil {
		t.Fatal(err)
	}
	got, err := s.FindByRecipient(key.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if got.Key.String() != key.String() || got.Name != "work" || got.Tier != sopsplugin.TierDangerous {
		t.Fatal("the identity did not survive a real encrypt/decrypt round trip")
	}

	// The ordinary secret that shared the vault is untouched, and it is still reachable
	// the ordinary way — the namespace partitions the vault, it does not take it over.
	if v, err := b.Resolve("GITHUB_TOKEN"); err != nil || v.Value != "ghp_ordinary" {
		t.Fatalf("ordinary secret after Put: %q, %v", v.Value, err)
	}
	if err := s.Remove("work"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("work"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("Get after Remove: %v", err)
	}
}

func keysOf(v *fakeVault) []string {
	var out []string
	for k := range v.data {
		out = append(out, k)
	}
	return out
}
