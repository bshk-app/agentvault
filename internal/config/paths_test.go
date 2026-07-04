//go:build !windows

package config

import (
	"path/filepath"
	"testing"
)

// TestDefaultConfigDirHonorsXDG asserts the daemon's config dir follows the
// XDG base-dir spec: $XDG_CONFIG_HOME wins when set, ~/.config otherwise. This
// is the anchor every default path hangs off, so the env precedence is the SSOT.
func TestDefaultConfigDirHonorsXDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg")
	if got, want := DefaultConfigDir(), "/tmp/xdg/agentvault"; got != want {
		t.Fatalf("with XDG_CONFIG_HOME: got %q, want %q", got, want)
	}
}

// TestDefaultConfigDirFallsBackToHome asserts the ~/.config fallback when
// XDG_CONFIG_HOME is unset — the common case on a stock macOS install.
func TestDefaultConfigDirFallsBackToHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/tmp/home")
	if got, want := DefaultConfigDir(), "/tmp/home/.config/agentvault"; got != want {
		t.Fatalf("without XDG_CONFIG_HOME: got %q, want %q", got, want)
	}
}

// TestDefaultPaths pins the well-known filenames the daemon auto-discovers and
// `av setup` writes, so the daemon and provisioner can never drift apart.
func TestDefaultPaths(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg")
	dir := filepath.Join("/tmp/xdg", "agentvault")

	cases := map[string]struct {
		got, want string
	}{
		"vault":              {DefaultVaultPath(), filepath.Join(dir, "vault.age")},
		"enclave identity":   {DefaultEnclaveIdentityPath(), filepath.Join(dir, "identity.enc")},
		"plaintext identity": {DefaultPlaintextIdentityPath(), filepath.Join(dir, "identity.txt")},
	}
	for name, c := range cases {
		if c.got != c.want {
			t.Errorf("%s path: got %q, want %q", name, c.got, c.want)
		}
	}
}
