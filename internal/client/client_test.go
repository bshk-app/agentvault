package client

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/beshkenadze/agentvault/internal/daemon"
)

// shortTempBase is the parent for a temp dir that will hold a unix socket: macOS caps
// sun_path near 104 bytes and t.TempDir()'s /var/folders/... base blows it before the
// test can say anything useful. Windows uses a named pipe with no such cap and has no
// /tmp at all, so there the OS temp dir ("") is both correct and the only thing that
// exists. Same reasoning as cmd/age-plugin-av/main_test.go.
func shortTempBase() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return "/tmp"
}

// exeName gives a binary the suffix Windows needs. The client autostarts the daemon
// through exec, which on Windows consults PATHEXT — an extension-less avd is simply not
// found there ("executable file not found in %PATH%"). Same trap, and same fix, as
// cmd/age-plugin-av/main_test.go; the Makefile has documented it since the design.
func exeName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// killDaemon terminates the avd built at path — and ONLY that one. These tests spawn a
// DETACHED daemon, so leaving it running outlives the test and pins the temp dir open.
// Matching on the full binary path (unique per test) rather than on the process name is
// what keeps a concurrently-running package's daemon alive: `go test ./...` runs
// cmd/age-plugin-av at the same time, and it spawns an avd of its own.
func killDaemon(path string) {
	if runtime.GOOS != "windows" {
		_ = exec.Command("pkill", "-f", path).Run()
		return
	}
	// No pkill on Windows, and taskkill can only match an image NAME. CIM exposes the
	// full ExecutablePath, which is what makes this precise instead of a blanket kill.
	_ = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Get-CimInstance Win32_Process -Filter "Name='avd.exe'" | `+
			`Where-Object { $_.ExecutablePath -eq '`+path+`' } | `+
			`ForEach-Object { Stop-Process -Id $_.ProcessId -Force }`).Run()
}

// shortSocketPath returns a socket path under shortTempBase().
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(shortTempBase(), "avc")
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
