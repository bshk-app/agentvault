package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/daemon"
)

func TestRegisterBackendsIncludesBitwarden(t *testing.T) {
	t.Setenv("AV_AGE_VAULT", "/definitely/missing/vault.age")
	t.Setenv("AV_AGE_IDENTITY", "")
	t.Setenv("AV_AGE_IDENTITY_ENCLAVE", "")

	dir, err := os.MkdirTemp("/tmp", "avd-bw-*")
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
