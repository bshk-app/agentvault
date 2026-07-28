package client

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/beshkenadze/agentvault/internal/transport"
)

// TestAutostartColdPing is the cold-start integration test: no daemon is running,
// so the client must autostart the real avd binary and then succeed.
//
// It builds the real avd into a short temp dir, points AV_AVD_PATH at it, and puts both
// sides on one endpoint with AV_SOCKET_PATH. The dir is SHORT (under /tmp) so the socket
// path stays under the macOS 104-byte sun_path limit — t.TempDir() can produce paths that
// exceed it.
//
// Cleanup is mandatory: the test must leave NO avd process running and NO stray
// socket/lockfile behind (it spawned a detached daemon).
func TestAutostartColdPing(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: builds and spawns avd")
	}

	// Short base dir under /tmp keeps the socket path within sun_path limits.
	dir, err := os.MkdirTemp(shortTempBase(), "avi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	avd := filepath.Join(dir, exeName("avd"))
	build := exec.Command("go", "build", "-o", avd, "github.com/beshkenadze/agentvault/cmd/avd")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build avd: %v\n%s", err, out)
	}

	sockPath := filepath.Join(dir, "agentvault", "avd.sock")

	t.Setenv("AV_AVD_PATH", avd)
	// This test is about AUTOSTART, not about auth — Ping needs no presence check. The
	// stub is required anyway because avd's selectPresence() is fatal when it cannot
	// build a presence provider, and on Windows it never can: newTouchIDPresence in
	// internal/daemon/presence_windows.go always errors (no WinRT bridge). Without this
	// the daemon would exit on startup and the failure would read as "did not come up".
	t.Setenv("AV_TEST_AUTH", "allow")
	// One endpoint for both sides. The spawned avd inherits this env and resolves the
	// SAME path through transport.DefaultSocketPath, so client and daemon meet whatever
	// the platform default would have been.
	t.Setenv(transport.SocketPathEnv, sockPath)

	// Always tear the spawned daemon down, even on failure: kill it, then remove
	// the socket and lockfile so nothing leaks past the test.
	t.Cleanup(func() {
		killDaemon(avd)
		_ = os.Remove(sockPath)
		_ = os.Remove(sockPath + ".lock")
	})

	cl := New(sockPath)
	got, err := cl.Ping()
	if err != nil {
		t.Fatalf("cold ping: %v", err)
	}
	if got != "pong" {
		t.Fatalf("ping = %q, want pong", got)
	}
}
