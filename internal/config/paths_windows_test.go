//go:build windows

package config

import (
	"path/filepath"
	"testing"
)

func TestDefaultConfigDirWindowsUsesAppData(t *testing.T) {
	t.Setenv("APPDATA", `C:\Users\me\AppData\Roaming`)
	if got, want := DefaultConfigDir(), filepath.Join(`C:\Users\me\AppData\Roaming`, "AgentVault"); got != want {
		t.Fatalf("DefaultConfigDir = %q, want %q", got, want)
	}
}
