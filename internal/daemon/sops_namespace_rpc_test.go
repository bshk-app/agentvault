package daemon

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/backend/agefile"
	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/manifest"
	"github.com/beshkenadze/agentvault/internal/sopsplugin"
)

// sopsResolve drives the resolve RPC for a ONE-ENTRY synthetic manifest pointing at ref
// — byte-for-byte the shape client.Read builds for `av read NAME`, so these tests
// exercise the exact path an ordinary read takes rather than a private back door.
func sopsResolve(t *testing.T, path, name, ref string) ipc.Response {
	t.Helper()
	const profile = "_read" // client.syntheticReadProfile
	mb, err := manifest.Synthetic(profile, name, ref, manifest.TierNormal)
	if err != nil {
		t.Fatal(err)
	}
	return rpcParams(t, path, "resolve", ipc.ResolveParams{Profile: profile, Manifest: mb})
}

// sopsLockedServer is addrmServer with the session left LOCKED and no audit sink. It
// exists for one assertion: that the namespace refusal lands BEFORE the unlock gate, so
// a doomed request never costs a presence prompt and the refusal does not vary with
// lock state.
func sopsLockedServer(t *testing.T, vaultPath string, id age.Identity) string {
	t.Helper()
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	reg := backend.NewRegistry()
	// The SAME constant the guard keys on — a "file" literal here would let this test pass
	// over a backend the guard does not protect.
	reg.Register(sopsplugin.VaultBackendID, agefile.New(agefile.Static{ID: id}, vaultPath))
	srv.SetResolver(NewResolver(reg, NewStubPresence(), NewSession(15*time.Minute)))
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	return path
}

// newSopsKey returns a fresh age private key's AGE-SECRET-KEY-1… text — the value a
// stored SOPS identity holds. Tests seed it into the vault so "the error must not carry
// a value" is asserted against a real key, not a placeholder.
func newSopsKey(t *testing.T) string {
	t.Helper()
	k, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return k.String()
}

// TestResolveRPCRefusesSopsNamespace: `av read sops/mykey` — a resolve through the
// synthetic one-entry manifest — must be refused with CodeBadRequest, return NO result,
// and name `av sops` without ever echoing the private key.
//
// This is the read half of the namespace. A SOPS private key is stored in the same vault
// as ordinary secrets, so without this guard it prints exactly like one.
func TestResolveRPCRefusesSopsNamespace(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow") // presence would allow; the refusal must not need it
	key := newSopsKey(t)
	vault, id := newAgeVault(t, map[string]string{sopsplugin.Namespace + "mykey": key})
	path, _ := addrmServer(t, vault, id)

	resp := sopsResolve(t, path, "SOPS_KEY", "av://file/"+sopsplugin.Namespace+"mykey")
	if resp.Error == nil {
		t.Fatalf("resolve of a sops/ locator succeeded; result=%s", resp.Result)
	}
	if resp.Error.Code != ipc.CodeBadRequest {
		t.Fatalf("code = %d, want CodeBadRequest (%d)", resp.Error.Code, ipc.CodeBadRequest)
	}
	if resp.Result != nil {
		t.Fatalf("refused resolve must not return a result, got %s", resp.Result)
	}
	if !strings.Contains(resp.Error.Message, "av sops") {
		t.Fatalf("message = %q, want it to point at av sops", resp.Error.Message)
	}
	if strings.Contains(resp.Error.Message, key) {
		t.Fatalf("error leaked the private key: %q", resp.Error.Message)
	}
}

// TestResolveRPCRefusesSopsNamespaceInMixedManifest: a manifest that mixes a healthy
// entry with a sops/ one — the shape a `.env` holding `KEY=av://file/sops/mykey` produces
// through `av env` — resolves NOTHING. Fail-closed: the healthy value must not come back
// alongside the refusal, or a caller could smuggle a read past the guard by batching.
func TestResolveRPCRefusesSopsNamespaceInMixedManifest(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	key := newSopsKey(t)
	vault, id := newAgeVault(t, map[string]string{
		sopsplugin.Namespace + "mykey": key,
		"PLAIN":                        "ordinary-value",
	})
	path, _ := addrmServer(t, vault, id)

	mb, err := manifest.SyntheticProfile("_env", map[string]manifest.Entry{
		"PLAIN":    {Ref: "av://file/PLAIN", Tier: manifest.TierNormal},
		"SOPS_KEY": {Ref: "av://file/" + sopsplugin.Namespace + "mykey", Tier: manifest.TierNormal},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp := rpcParams(t, path, "resolve", ipc.ResolveParams{Profile: "_env", Manifest: mb})
	if resp.Error == nil || resp.Error.Code != ipc.CodeBadRequest {
		t.Fatalf("resp.Error = %+v, want CodeBadRequest; result=%s", resp.Error, resp.Result)
	}
	if resp.Result != nil {
		t.Fatalf("a refused mixed resolve must return no values at all, got %s", resp.Result)
	}
	if strings.Contains(resp.Error.Message, key) || strings.Contains(resp.Error.Message, "ordinary-value") {
		t.Fatalf("error leaked a value: %q", resp.Error.Message)
	}
}

// TestAddRPCRefusesSopsNamespace: `av add sops/notes` must be refused AND must write
// nothing. This is the case Task 4's review found: junk stored beside a healthy identity
// broke FindByRecipient for files the healthy key could decrypt.
func TestAddRPCRefusesSopsNamespace(t *testing.T) {
	const junk = "reminder: rotate this in June"
	vault, id := newAgeVault(t, map[string]string{"A": "1"})
	path, _ := addrmServer(t, vault, id)

	resp := rpcParams(t, path, "add", ipc.AddParams{
		Backend: "file",
		Locator: sopsplugin.Namespace + "notes",
		Value:   []byte(junk),
	})
	if resp.Error == nil {
		t.Fatal("add into the sops/ namespace succeeded; it must be refused")
	}
	if resp.Error.Code != ipc.CodeBadRequest {
		t.Fatalf("code = %d, want CodeBadRequest (%d)", resp.Error.Code, ipc.CodeBadRequest)
	}
	if !strings.Contains(resp.Error.Message, "av sops") {
		t.Fatalf("message = %q, want it to point at av sops", resp.Error.Message)
	}
	if strings.Contains(resp.Error.Message, junk) {
		t.Fatalf("error leaked the value: %q", resp.Error.Message)
	}
	// The refusal is only worth anything if nothing landed in the vault.
	if _, err := fileResolve(t, vault, id, sopsplugin.Namespace+"notes"); err != backend.ErrNotFound {
		t.Fatalf("refused add still wrote the entry (resolve err = %v, want ErrNotFound)", err)
	}
}

// TestRmRPCRefusesSopsNamespace: `av rm sops/mykey` must be refused AND must leave the
// identity in place. Deleting a SOPS key destroys the only copy — an ordinary `av rm`
// must not be able to do it.
func TestRmRPCRefusesSopsNamespace(t *testing.T) {
	key := newSopsKey(t)
	vault, id := newAgeVault(t, map[string]string{sopsplugin.Namespace + "mykey": key})
	path, _ := addrmServer(t, vault, id)

	resp := rpcParams(t, path, "rm", ipc.RmParams{Backend: "file", Locator: sopsplugin.Namespace + "mykey"})
	if resp.Error == nil {
		t.Fatal("rm of a sops/ entry succeeded; it must be refused")
	}
	if resp.Error.Code != ipc.CodeBadRequest {
		t.Fatalf("code = %d, want CodeBadRequest (%d)", resp.Error.Code, ipc.CodeBadRequest)
	}
	if !strings.Contains(resp.Error.Message, "av sops") {
		t.Fatalf("message = %q, want it to point at av sops", resp.Error.Message)
	}
	if strings.Contains(resp.Error.Message, key) {
		t.Fatalf("error leaked the private key: %q", resp.Error.Message)
	}
	if got, err := fileResolve(t, vault, id, sopsplugin.Namespace+"mykey"); err != nil || got != key {
		t.Fatalf("refused rm still deleted the identity (err = %v)", err)
	}
}

// TestSopsNamespaceBoundaries pins exactly which locators the guard claims. The trap it
// exists to prevent is a prefix test against "sops" rather than sopsplugin.Namespace:
// that would swallow "sopsucker" and every other name that merely starts with the four
// letters.
//
// The two judgement calls, both following what Namespace actually matches:
//
//   - The bare name "sops" is ALLOWED. Namespace is "sops/", so Store.each's
//     List("sops/") — an exact byte-prefix scan in agefile — can never see it, and
//     Store.Put always writes "sops/"+name. A secret called "sops" cannot collide with
//     an identity, so refusing it would cost a user a name for nothing.
//   - "SOPS/mykey" is ALLOWED. Locators are byte-exact everywhere in this repo
//     (agefile.Resolve is a plain map lookup, agefile.List a byte-prefix compare), so
//     "SOPS/mykey" is a DIFFERENT entry that no Store call can reach. Refusing it would
//     invent a case-insensitivity rule the vault does not have.
func TestSopsNamespaceBoundaries(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	// The value every allowed sub-case below writes, named so the read sub-case at the end
	// can assert it comes back.
	const allowedValue = "v"
	vault, id := newAgeVault(t, map[string]string{"A": "1"})
	path, _ := addrmServer(t, vault, id)

	cases := []struct {
		locator string
		refused bool
		why     string
	}{
		{"sops/mykey", true, "an identity name inside the namespace"},
		{"sops/", true, "the namespace's own prefix — inside it, with an empty identity name"},
		{"sops/nested/name", true, "everything below the prefix is inside it"},
		{"sops", false, "bare name: Namespace is \"sops/\", so this is outside it"},
		{"sopsucker", false, "merely STARTS with sops — the classic HasPrefix bug"},
		{"sops-notes", false, "same: no slash, so not in the namespace"},
		{"SOPS/mykey", false, "locators are case-sensitive; this is a different entry"},
		{"", false, "empty locator is not the guard's business (the backend owns it)"},
	}
	for _, tc := range cases {
		t.Run(tc.locator, func(t *testing.T) {
			resp := rpcParams(t, path, "add", ipc.AddParams{
				Backend: "file",
				Locator: tc.locator,
				Value:   []byte(allowedValue),
			})
			refused := resp.Error != nil && strings.Contains(resp.Error.Message, "av sops")
			if refused != tc.refused {
				t.Fatalf("locator %q refused = %v, want %v (%s); resp.Error = %+v",
					tc.locator, refused, tc.refused, tc.why, resp.Error)
			}
			if tc.refused && resp.Error.Code != ipc.CodeBadRequest {
				t.Fatalf("locator %q: code = %d, want CodeBadRequest", tc.locator, resp.Error.Code)
			}
		})
	}

	// The table above drives `add`, but the direction that matters for a NOT-refused
	// locator is the READ path: "allowed" on a write only means the entry can be created,
	// while on a read it means the guard hands a value back. So pin the case-sensitivity
	// call where it has consequences. The write sub-case above already stored
	// "SOPS/mykey"; reading it back closes the loop — a different entry, reachable like
	// any other secret, rather than one swallowed by a case-insensitivity rule the vault
	// does not have.
	t.Run("SOPS/mykey via resolve", func(t *testing.T) {
		resp := sopsResolve(t, path, "OTHER", "av://file/SOPS/mykey")
		if resp.Error != nil {
			t.Fatalf("reading SOPS/mykey was refused: %+v", resp.Error)
		}
		var res ipc.ResolveResult
		if err := json.Unmarshal(resp.Result, &res); err != nil {
			t.Fatal(err)
		}
		if res.Values["OTHER"] != allowedValue {
			t.Fatalf("value = %q, want %q", res.Values["OTHER"], allowedValue)
		}
	})
}

// TestSopsNamespaceIsScopedToTheLocalVault pins the deliberate LIMIT of the guard: the
// reserved namespace lives in the local age vault, the only store sopsplugin.Store reads
// and writes, so a sops/-prefixed locator in ANOTHER backend is left alone.
//
// Refusing it would deny for nothing — av://1p/sops/prod/key addresses a 1Password vault
// named "sops", which cannot hold an AgentVault identity. Enforcement is kept exactly as
// wide as the thing it protects.
func TestSopsNamespaceIsScopedToTheLocalVault(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	vault, id := newAgeVault(t, map[string]string{"A": "1"})
	path, _ := addrmServer(t, vault, id) // registers a read-only "mock" backend too

	resp := sopsResolve(t, path, "OTHER", "av://mock/"+sopsplugin.Namespace+"mykey")
	// The mock backend has no such entry, so this fails — but it must fail as a plain
	// not-found, NOT as a namespace refusal. Asserting only the absence of "av sops" would
	// pass on ANY outcome, including a resolve that never happened; pinning the backend's
	// OWN error is what proves the request got past the guard and reached the backend.
	if resp.Error == nil {
		t.Fatalf("resolve of an unseeded mock locator succeeded; result=%s", resp.Result)
	}
	if strings.Contains(resp.Error.Message, "av sops") {
		t.Fatalf("a sops/ locator in another backend was refused as the reserved namespace: %q", resp.Error.Message)
	}
	if !strings.Contains(resp.Error.Message, backend.ErrNotFound.Error()) {
		t.Fatalf("message = %q, want the backend's own %q — the request must have REACHED the backend",
			resp.Error.Message, backend.ErrNotFound)
	}
}

// TestSopsNamespaceRefusedWhileLocked: the refusal lands BEFORE the unlock gate. With a
// LOCKED session an ordinary add returns CodeLocked; a sops/ add must still return
// CodeBadRequest, which proves two things at once — no presence prompt is spent on a
// request that was always going to be refused, and the refusal does not depend on lock
// state (so it cannot be probed for one).
func TestSopsNamespaceRefusedWhileLocked(t *testing.T) {
	vault, id := newAgeVault(t, map[string]string{"A": "1"})
	path := sopsLockedServer(t, vault, id)

	// Baseline: the lock gate really is armed on this server.
	if resp := rpcParams(t, path, "add", ipc.AddParams{Backend: "file", Locator: "ORDINARY", Value: []byte("v")}); resp.Error == nil || resp.Error.Code != ipc.CodeLocked {
		t.Fatalf("ordinary add on a locked session = %+v, want CodeLocked", resp.Error)
	}
	resp := rpcParams(t, path, "add", ipc.AddParams{Backend: "file", Locator: sopsplugin.Namespace + "mykey", Value: []byte("v")})
	if resp.Error == nil || resp.Error.Code != ipc.CodeBadRequest {
		t.Fatalf("sops/ add on a locked session = %+v, want CodeBadRequest (refusal must precede the unlock gate)", resp.Error)
	}
	if !strings.Contains(resp.Error.Message, "av sops") {
		t.Fatalf("message = %q, want it to point at av sops", resp.Error.Message)
	}
}
