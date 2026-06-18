package client

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/beshkenadze/agentvault/internal/daemon"
)

// shortSocketPath returns a socket path under /tmp to stay well under the macOS
// 104-byte sun_path limit (t.TempDir() paths are too long for unix sockets).
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "avc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "avd.sock")
}

// TestPingAgainstRunningServer is the happy path: an in-process daemon is already
// listening, so the client dials it directly (no autostart) and gets "pong".
func TestPingAgainstRunningServer(t *testing.T) {
	path := shortSocketPath(t)
	srv, err := daemon.New(path)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	defer srv.Close()

	cl := New(path)
	got, err := cl.Ping()
	if err != nil {
		t.Fatal(err)
	}
	if got != "pong" {
		t.Fatalf("ping = %q, want pong", got)
	}
}

// TestClientUnlockLockStatus drives the unlock/lock/status RPCs through the client
// against an in-process daemon wired with the stub presence (AV_TEST_AUTH=allow).
func TestClientUnlockLockStatus(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	path := shortSocketPath(t)
	srv, err := daemon.New(path)
	if err != nil {
		t.Fatal(err)
	}
	presence := daemon.NewStubPresence()
	srv.SetPresence(presence)
	srv.SetResolver(daemon.NewResolver(nil, presence, daemon.NewSession(15*time.Minute)))
	go srv.Serve()
	defer srv.Close()

	cl := New(path)

	// Fresh session: locked.
	if locked, _, err := cl.Status(); err != nil || !locked {
		t.Fatalf("fresh status: locked=%v err=%v, want locked", locked, err)
	}
	// Unlock opens it; status reports unlocked with remaining > 0.
	if err := cl.Unlock(); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	locked, remaining, err := cl.Status()
	if err != nil {
		t.Fatal(err)
	}
	if locked || remaining <= 0 {
		t.Fatalf("after unlock: locked=%v remaining=%d, want unlocked with remaining>0", locked, remaining)
	}
	// Lock re-locks it.
	if err := cl.Lock(); err != nil {
		t.Fatalf("lock: %v", err)
	}
	if locked, _, err := cl.Status(); err != nil || !locked {
		t.Fatalf("after lock: locked=%v err=%v, want locked", locked, err)
	}
}
