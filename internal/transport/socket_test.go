//go:build !windows

package transport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shortSocketPath returns a socket path under a guaranteed-short directory.
// t.TempDir() can produce paths > 104 bytes when $TMPDIR is long, which trips the
// macOS sun_path limit and makes unrelated tests fail with "bind: invalid argument".
// This keeps the path short regardless of the ambient $TMPDIR.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "avt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "avd.sock")
}

func TestListenCreates0600Socket(t *testing.T) {
	path := shortSocketPath(t)
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket mode = %o, want 600", perm)
	}
}

func TestDialConnects(t *testing.T) {
	path := shortSocketPath(t)
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()
	c, err := Dial(path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()
}

// An over-long socket path must be rejected by our explicit guard, returning a
// clear length/limit error BEFORE net.Listen would fail with a cryptic
// "bind: invalid argument" (macOS sun_path is ~104 bytes).
func TestListenRejectsTooLongPath(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "avt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	// Build a path of length >= 104 bytes by padding the filename.
	pad := 104 - len(dir) - 1 // -1 for the path separator
	if pad < 1 {
		pad = 1
	}
	path := filepath.Join(dir, strings.Repeat("x", pad)+".sock")
	if len(path) < 104 {
		path = filepath.Join(dir, strings.Repeat("x", 104)+".sock")
	}

	ln, err := Listen(path)
	if ln != nil {
		ln.Close()
	}
	if err == nil {
		t.Fatalf("expected error for path of length %d, got nil", len(path))
	}
	msg := err.Error()
	if strings.Contains(msg, "invalid argument") {
		t.Fatalf("got cryptic bind error instead of our length guard: %v", err)
	}
	if !strings.Contains(msg, "too long") && !strings.Contains(msg, "max") {
		t.Fatalf("error message should mention length/limit, got: %v", err)
	}
}

func TestDefaultSocketPathUnderRuntimeDir(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/tmp/xdg-test")
	p, err := DefaultSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	if want := "/tmp/xdg-test/agentvault/avd.sock"; p != want {
		t.Fatalf("path = %q, want %q", p, want)
	}
}
