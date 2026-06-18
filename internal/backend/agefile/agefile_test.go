package agefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/beshkenadze/agentvault/internal/backend"
)

// writeEncrypted age-encrypts a name->value map to path for the given recipient,
// delegating the encrypt logic to the package's exported EncryptVault helper.
func writeEncrypted(t *testing.T, path string, id *age.X25519Identity, data map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := EncryptVault(f, id.Recipient(), data); err != nil {
		t.Fatal(err)
	}
}

func TestResolveAndList(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	writeEncrypted(t, path, id, map[string]string{
		"GITHUB_TOKEN":  "ghp_value",
		"STRIPE_SECRET": "sk_live_value",
	})

	b := New(id, path)

	got, err := b.Resolve("GITHUB_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "ghp_value" {
		t.Fatalf("value = %q", got.Value)
	}

	if _, err := b.Resolve("MISSING"); err != backend.ErrNotFound {
		t.Fatalf("missing key err = %v, want ErrNotFound", err)
	}

	metas, err := b.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 2 {
		t.Fatalf("got %d metas, want 2", len(metas))
	}
	// List must not expose values (Meta has no Value field — compile-time guard).
}

func TestWrongIdentityFails(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	other, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	writeEncrypted(t, path, id, map[string]string{"X": "y"})

	b := New(other, path) // wrong identity
	_, err := b.Resolve("X")
	if err == nil {
		t.Fatal("expected decryption failure with wrong identity")
	}
	// A decrypt failure must be distinguishable from a missing key, otherwise the
	// design's feared fail-open (treating "can't decrypt" as "no such secret") could
	// silently drop a secret.
	if errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("decrypt failure misreported as ErrNotFound: %v", err)
	}
}
