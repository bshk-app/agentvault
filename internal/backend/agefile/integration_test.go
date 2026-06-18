package agefile_test

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/backend/agefile"
)

// writeVault age-encrypts a name->value map to path using the exported EncryptVault
// helper (same helper the agefile package test and Phase 6's `av add` writer use).
func writeVault(t *testing.T, path string, id *age.X25519Identity, data map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := agefile.EncryptVault(f, id.Recipient(), data); err != nil {
		t.Fatal(err)
	}
}

func TestResolveThroughRegistry(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	writeVault(t, path, id, map[string]string{"GITHUB_TOKEN": "ghp_xyz"})

	reg := backend.NewRegistry()
	reg.Register("file", agefile.New(id, path))

	got, err := reg.Resolve("av://file/GITHUB_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "ghp_xyz" {
		t.Fatalf("value = %q", got.Value)
	}
}
