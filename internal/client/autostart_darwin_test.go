//go:build darwin

package client

import (
	"os"
	"path/filepath"
	"testing"
)

// resolveAvdPath prefers a sibling `avd`, then a co-located AgentVault.app, then the
// cask app-bundle dirs (/Applications, ~/Applications), then falls back to PATH ("avd").
func TestResolveAvdPath_SiblingWins(t *testing.T) {
	dir := t.TempDir()
	sib := filepath.Join(dir, "avd")
	if err := os.WriteFile(sib, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := resolveAvdPath(dir, nil); got != sib {
		t.Fatalf("got %q, want sibling %q", got, sib)
	}
}

func TestResolveAvdPath_CaskBundle(t *testing.T) {
	dir := t.TempDir()
	bundled := filepath.Join(dir, "AgentVault.app", "Contents", "MacOS", "avd")
	if err := os.MkdirAll(filepath.Dir(bundled), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundled, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := resolveAvdPath(dir, nil); got != bundled {
		t.Fatalf("got %q, want bundled %q", got, bundled)
	}
}

// TestResolveAvdPath_AppBundleDir is the real cask layout: av lives elsewhere (brew
// bin, no sibling avd) and avd is found only via an app-bundle dir like /Applications.
func TestResolveAvdPath_AppBundleDir(t *testing.T) {
	appDir := t.TempDir()
	bundled := filepath.Join(appDir, "AgentVault.app", "Contents", "MacOS", "avd")
	if err := os.MkdirAll(filepath.Dir(bundled), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundled, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := resolveAvdPath(t.TempDir(), []string{appDir}); got != bundled {
		t.Fatalf("got %q, want app-bundle %q", got, bundled)
	}
}

func TestResolveAvdPath_FallsBackToPATH(t *testing.T) {
	if got := resolveAvdPath(t.TempDir(), nil); got != "avd" {
		t.Fatalf("got %q, want \"avd\"", got)
	}
}
