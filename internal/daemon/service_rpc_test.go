package daemon

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/loginitem"
)

type fakeLoginItem struct {
	state     loginitem.State
	backend   loginitem.Backend
	enableErr error
	lastCall  string
}

func (f *fakeLoginItem) Enable() error { f.lastCall = "enable"; return f.enableErr }
func (f *fakeLoginItem) Disable() error {
	f.lastCall = "disable"
	f.state = loginitem.StateDisabled
	return nil
}
func (f *fakeLoginItem) Status() (loginitem.State, error) { return f.state, nil }
func (f *fakeLoginItem) Backend() loginitem.Backend       { return f.backend }

func serviceServer(t *testing.T, m loginitem.Manager) string {
	t.Helper()
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if m != nil {
		srv.SetLoginItem(m)
	}
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	return path
}

func TestServiceStatusRoundTrips(t *testing.T) {
	f := &fakeLoginItem{state: loginitem.StateEnabled, backend: loginitem.BackendSMAppService}
	path := serviceServer(t, f)
	resp := rpcParams(t, path, "service", ipc.ServiceParams{Action: "status"})
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
	var r ipc.ServiceResult
	json.Unmarshal(resp.Result, &r)
	if r.Backend != "smappservice" || r.State != "enabled" {
		t.Fatalf("got %+v, want smappservice/enabled", r)
	}
}

func TestServiceEnableInvokesManager(t *testing.T) {
	f := &fakeLoginItem{state: loginitem.StateRequiresApproval, backend: loginitem.BackendSMAppService}
	path := serviceServer(t, f)
	resp := rpcParams(t, path, "service", ipc.ServiceParams{Action: "enable"})
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
	if f.lastCall != "enable" {
		t.Fatalf("manager.Enable not called (lastCall=%q)", f.lastCall)
	}
	var r ipc.ServiceResult
	json.Unmarshal(resp.Result, &r)
	if r.State != "requires-approval" {
		t.Fatalf("state = %q, want requires-approval", r.State)
	}
}

func TestServiceBadActionIsBadRequest(t *testing.T) {
	path := serviceServer(t, &fakeLoginItem{})
	resp := rpcParams(t, path, "service", ipc.ServiceParams{Action: "bogus"})
	if resp.Error == nil || resp.Error.Code != ipc.CodeBadRequest {
		t.Fatalf("want CodeBadRequest, got %+v", resp.Error)
	}
}

func TestServiceNilManagerIsInternal(t *testing.T) {
	path := serviceServer(t, nil)
	resp := rpcParams(t, path, "service", ipc.ServiceParams{Action: "status"})
	if resp.Error == nil || resp.Error.Code != ipc.CodeInternal {
		t.Fatalf("want CodeInternal, got %+v", resp.Error)
	}
	_ = errors.New
}
