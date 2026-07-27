package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/daemon"
)

// shortTempBase is the parent for a temp dir that will hold a unix socket: macOS caps
// sun_path near 104 bytes and t.TempDir()'s /var/folders/... base blows it. Windows uses
// a named pipe with no such cap and has no /tmp at all, so there the OS temp dir ("") is
// both correct and the only thing that exists. Same reasoning as
// cmd/age-plugin-av/main_test.go.
func shortTempBase() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return "/tmp"
}

func TestRegisterBackendsIncludesBitwarden(t *testing.T) {
	t.Setenv("AV_AGE_VAULT", "/definitely/missing/vault.age")
	t.Setenv("AV_AGE_IDENTITY", "")
	t.Setenv("AV_AGE_IDENTITY_ENCLAVE", "")

	dir, err := os.MkdirTemp(shortTempBase(), "avd-bw-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	srv, err := daemon.New(filepath.Join(dir, "avd.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	reg := backend.NewRegistry()
	sess := daemon.NewSession(daemon.DefaultTTL)
	registerBackends(
		reg,
		sess,
		srv,
		func([]byte) ([]byte, error) { return nil, nil },
		func() ([]byte, error) { return nil, backend.ErrNotFound },
		daemon.NewStubPresence(),
	)

	if _, err := reg.List("bw", ""); err != nil {
		t.Fatalf("bw backend not registered: %v", err)
	}
}
