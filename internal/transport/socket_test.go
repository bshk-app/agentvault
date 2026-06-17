package transport

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListenCreates0600Socket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "avd.sock")
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
	dir := t.TempDir()
	path := filepath.Join(dir, "avd.sock")
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
