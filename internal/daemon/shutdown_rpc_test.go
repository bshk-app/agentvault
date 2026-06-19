package daemon

import (
	"encoding/json"
	"testing"
	"time"
)

// TestShutdownRPCRespondsOkAndFiresCallback: the "shutdown" case must (1) reply "ok" so
// the client knows the shutdown was accepted, and (2) invoke the injected teardown
// callback. The real cmd/avd callback exits the process; here we inject a RECORDING one
// (it closes a channel, never os.Exit) — that is the whole point of the injection seam.
// The callback runs in a goroutine (respond-then-exit), so we wait on the channel with a
// short timeout rather than asserting synchronously.
func TestShutdownRPCRespondsOkAndFiresCallback(t *testing.T) {
	srv, path := versionServer(t) // bare server is enough; shutdown touches no secret
	fired := make(chan struct{})
	srv.SetShutdown(func() { close(fired) })

	resp := rpc(t, path, "shutdown")
	if resp.Error != nil {
		t.Fatalf("shutdown error: %+v", resp.Error)
	}
	var ok string
	if err := json.Unmarshal(resp.Result, &ok); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ok != "ok" {
		t.Fatalf("shutdown result = %q, want ok", ok)
	}

	select {
	case <-fired:
		// callback fired — respond-then-exit ordering held (ok was already received above)
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown callback was not invoked within 2s")
	}
}

// TestShutdownRPCNoCallbackStillOk: with no callback wired (SetShutdown never called) the
// case must still reply "ok" and not panic — the nil guard holds.
func TestShutdownRPCNoCallbackStillOk(t *testing.T) {
	_, path := versionServer(t)

	resp := rpc(t, path, "shutdown")
	if resp.Error != nil {
		t.Fatalf("shutdown error: %+v", resp.Error)
	}
	var ok string
	if err := json.Unmarshal(resp.Result, &ok); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ok != "ok" {
		t.Fatalf("shutdown result = %q, want ok", ok)
	}
}
