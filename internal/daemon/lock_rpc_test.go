package daemon

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/transport"
)

// newLockServer starts an in-process Server wired with the SAME stub presence on
// SetPresence (serves "unlock") and on the resolver (serves dangerous-tier resolve),
// over one fresh (LOCKED) session. AV_TEST_AUTH controls whether the stub allows.
func newLockServer(t *testing.T) (*Server, string) {
	t.Helper()
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	reg := backend.NewRegistry()
	reg.Register("mock", mockBE{data: map[string]string{"GH": "ghp_xyz"}})
	sess := NewSession(15 * time.Minute) // fresh => LOCKED until an unlock RPC
	presence := NewStubPresence()
	srv.SetPresence(presence)
	srv.SetResolver(NewResolver(reg, presence, sess))
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	return srv, path
}

// rpc dials, sends one request for method (no params), and returns the response.
func rpc(t *testing.T, path, method string) ipc.Response {
	t.Helper()
	c, err := transport.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := ipc.NewEncoder(c).Encode(ipc.Request{ID: 1, Method: method}); err != nil {
		t.Fatal(err)
	}
	var resp ipc.Response
	if err := ipc.NewDecoder(c).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func statusOf(t *testing.T, resp ipc.Response) ipc.StatusResult {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
	var st ipc.StatusResult
	if err := json.Unmarshal(resp.Result, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

// TestUnlockRPCAllows: with the stub allowing, "unlock" opens the session and a
// follow-up "status" reports unlocked with a positive remaining window.
func TestUnlockRPCAllows(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	_, path := newLockServer(t)

	if st := statusOf(t, rpc(t, path, "unlock")); st.Locked {
		t.Fatalf("after unlock, status must be unlocked: %+v", st)
	}
	st := statusOf(t, rpc(t, path, "status"))
	if st.Locked {
		t.Fatalf("status after unlock must be unlocked: %+v", st)
	}
	if st.RemainingSeconds <= 0 {
		t.Fatalf("unlocked status must report remaining > 0, got %d", st.RemainingSeconds)
	}
}

// TestUnlockRPCDeniedLocked: without AV_TEST_AUTH the stub denies with ErrLocked,
// so "unlock" must fail with CodeLocked and leave the session locked.
func TestUnlockRPCDeniedLocked(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "")
	_, path := newLockServer(t)

	resp := rpc(t, path, "unlock")
	if resp.Error == nil || resp.Error.Code != ipc.CodeLocked {
		t.Fatalf("want CodeLocked, got error=%+v result=%s", resp.Error, resp.Result)
	}
	if st := statusOf(t, rpc(t, path, "status")); !st.Locked {
		t.Fatalf("denied unlock must leave session locked: %+v", st)
	}
}

// TestLockRPCRelocks: unlock then lock then status must report locked.
func TestLockRPCRelocks(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	_, path := newLockServer(t)

	statusOf(t, rpc(t, path, "unlock"))
	if st := statusOf(t, rpc(t, path, "lock")); !st.Locked {
		t.Fatalf("lock reply must report locked: %+v", st)
	}
	if st := statusOf(t, rpc(t, path, "status")); !st.Locked {
		t.Fatalf("status after lock must report locked: %+v", st)
	}
}

// TestStatusRPCFreshSessionLocked: a fresh session (never unlocked) reports locked
// with zero remaining, and the StatusResult structurally carries no value field.
func TestStatusRPCFreshSessionLocked(t *testing.T) {
	_, path := newLockServer(t)

	st := statusOf(t, rpc(t, path, "status"))
	if !st.Locked || st.RemainingSeconds != 0 {
		t.Fatalf("fresh session must be locked with 0 remaining, got %+v", st)
	}
}
