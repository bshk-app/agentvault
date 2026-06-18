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
// resolver_test.go) resolves GITHUB_TOKEN through it.
func newResolveServer(t *testing.T) (*Server, string) {
	t.Helper()
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	reg := backend.NewRegistry()
	reg.Register("mock", mockBE{data: map[string]string{"GH": "ghp_xyz"}})
	srv.SetResolver(NewResolver(reg, NewStubAuthorizer(), NewSession(15*time.Minute)))
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

// TestResolveRPC drives the resolve method over the socket with the stub
// authorizer allowed; the daemon must return the resolved value.
func TestResolveRPC(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	_, path := newResolveServer(t)

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
	_, path := newResolveServer(t)

	resp := resolveCallProfile(t, path, "nope")
	if resp.Error == nil || resp.Error.Code != ipc.CodeBadRequest {
		t.Fatalf("want CodeBadRequest, got error=%+v result=%s", resp.Error, resp.Result)
	}
	if resp.Result != nil {
		t.Fatalf("bad-request resolve must not return a result, got %s", resp.Result)
	}
}

// TestResolveRPCLocked drives resolve with the stub authorizer unset; the daemon
// must reject with CodeLocked (and never leak a value in the error message).
func TestResolveRPCLocked(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "") // not allowed -> ErrLocked
	_, path := newResolveServer(t)

	resp := resolveCall(t, path)
	if resp.Error == nil || resp.Error.Code != ipc.CodeLocked {
		t.Fatalf("want CodeLocked, got error=%+v result=%s", resp.Error, resp.Result)
	}
	if resp.Result != nil {
		t.Fatalf("locked resolve must not return a result, got %s", resp.Result)
	}
}
