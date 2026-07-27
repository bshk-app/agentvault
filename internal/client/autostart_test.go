package client

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestAutostartColdPing is the cold-start integration test: no daemon is running,
// so the client must autostart the real avd binary and then succeed.
//
// It builds the real avd into a short temp dir, points AV_AVD_PATH at it, and sets
// XDG_RUNTIME_DIR to a SHORT dir under /tmp so the resolved socket path
// (<dir>/agentvault/avd.sock) stays under the macOS 104-byte sun_path limit —
// t.TempDir() can produce paths that exceed it.
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

	avd := filepath.Join(dir, "avd")
	build := exec.Command("go", "build", "-o", avd, "github.com/beshkenadze/agentvault/cmd/avd")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build avd: %v\n%s", err, out)
	}

	t.Setenv("AV_AVD_PATH", avd)
	t.Setenv("XDG_RUNTIME_DIR", dir) // socket resolves under this short dir

	sockPath := filepath.Join(dir, "agentvault", "avd.sock")

	// Always tear the spawned daemon down, even on failure: kill it, then remove
	// the socket and lockfile so nothing leaks past the test.
	t.Cleanup(func() {
		_ = exec.Command("pkill", "-f", avd).Run()
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
