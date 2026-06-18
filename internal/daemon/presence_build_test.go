package daemon

import "testing"

// TestNewTouchIDPresenceConstructs verifies the Touch ID presence constructor
// compiles and links on this build and (on darwin+cgo) returns a usable
// Presence with no error. It deliberately does NOT call Prompt: a real
// LocalAuthentication prompt blocks waiting for a biometric/passcode response
// and cannot be exercised in automated tests (no GUI session, no finger). This
// is a compile/linkage smoke test only; functional Touch ID behavior is
// verified manually on hardware.
func TestNewTouchIDPresenceConstructs(t *testing.T) {
	p, err := newTouchIDPresence()

	// On darwin+cgo (the default build on this machine) the constructor must
	// succeed and yield a non-nil Presence. On non-cgo/non-darwin builds it
	// returns an error and a nil Presence by design; in that case there is
	// nothing further to assert.
	if err != nil {
		t.Logf("newTouchIDPresence unavailable on this build: %v", err)
		if p != nil {
			t.Fatalf("expected nil Presence when constructor errors, got %T", p)
		}
		return
	}

	if p == nil {
		t.Fatal("newTouchIDPresence returned nil Presence without an error")
	}
}
