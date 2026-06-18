package daemon

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/transport"
)

// newResolveServer starts a Server on a short socket path with a mock-backed
// Resolver injected via SetResolver, serving until the test ends. The mock
// backend maps "GH" -> "ghp_xyz"; the manifest (manifestYAML, defined in
// resolver_test.go) resolves GITHUB_TOKEN (normal-tier) through it. The session is
// unlocked unless `locked` is set, since Phase 5 normal-tier resolve requires an open
// session.
func newResolveServer(t *testing.T, locked bool) (*Server, string) {
	t.Helper()
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	reg := backend.NewRegistry()
	reg.Register("mock", mockBE{data: map[string]string{"GH": "ghp_xyz"}})
	sess := NewSession(15 * time.Minute)
	if !locked {
		sess.Unlock(15 * time.Minute) // normal-tier resolve needs an open session
	}
	srv.SetResolver(NewResolver(reg, NewStubPresence(), sess))
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	return srv, path
}

func resolveCall(t *testing.T, path string) ipc.Response {
	t.Helper()
	return resolveCallProfile(t, path, "smoke")
}

// resolveCallProfile drives the resolve method for an arbitrary profile name so a
// test can exercise the unknown-profile path.
func resolveCallProfile(t *testing.T, path, profile string) ipc.Response {
	t.Helper()
	c, err := transport.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	params, _ := json.Marshal(ipc.ResolveParams{Profile: profile, Manifest: []byte(manifestYAML)})
	if err := ipc.NewEncoder(c).Encode(ipc.Request{ID: 1, Method: "resolve", Params: params}); err != nil {
		t.Fatal(err)
	}
	var resp ipc.Response
	if err := ipc.NewDecoder(c).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestResolveRPC drives the resolve method over the socket with an unlocked
// session; the daemon must return the resolved (normal-tier) value.
func TestResolveRPC(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	_, path := newResolveServer(t, false)

	resp := resolveCall(t, path)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
	var r ipc.ResolveResult
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		t.Fatal(err)
	}
	if r.Values["GITHUB_TOKEN"] != "ghp_xyz" {
		t.Fatalf("values = %+v, want GITHUB_TOKEN=ghp_xyz", r.Values)
	}
}

// TestResolveRPCUnknownProfile drives resolve for a profile absent from the
// manifest; the daemon must reject with CodeBadRequest (client fault, not
// CodeInternal) and never return a result.
func TestResolveRPCUnknownProfile(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	_, path := newResolveServer(t, false)

	resp := resolveCallProfile(t, path, "nope")
	if resp.Error == nil || resp.Error.Code != ipc.CodeBadRequest {
		t.Fatalf("want CodeBadRequest, got error=%+v result=%s", resp.Error, resp.Result)
	}
	if resp.Result != nil {
		t.Fatalf("bad-request resolve must not return a result, got %s", resp.Result)
	}
}

// TestResolveRPCLocked drives a normal-tier resolve against a LOCKED session; the
// daemon must reject with CodeLocked (and never leak a value in the error message).
func TestResolveRPCLocked(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow") // presence would allow; normal-tier still blocked by the locked session
	_, path := newResolveServer(t, true)

	resp := resolveCall(t, path)
	if resp.Error == nil || resp.Error.Code != ipc.CodeLocked {
		t.Fatalf("want CodeLocked, got error=%+v result=%s", resp.Error, resp.Result)
	}
	if resp.Result != nil {
		t.Fatalf("locked resolve must not return a result, got %s", resp.Result)
	}
}
