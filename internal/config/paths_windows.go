//go:build windows

// Package config resolves AgentVault's default on-disk locations (vault + identity).
// SSOT for the zero-config store paths the daemon auto-discovers and `av setup` writes.
package config

import (
	"os"
	"path/filepath"
)

// DefaultConfigDir is %APPDATA%\AgentVault, falling back to the user config dir.
func DefaultConfigDir() string {
	if x := os.Getenv("APPDATA"); x != "" {
		return filepath.Join(x, "AgentVault")
	}
	c, err := os.UserConfigDir()
	if err == nil {
		return filepath.Join(c, "AgentVault")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "AppData", "Roaming", "AgentVault")
}

func DefaultVaultPath() string             { return filepath.Join(DefaultConfigDir(), "vault.age") }
func DefaultEnclaveIdentityPath() string   { return filepath.Join(DefaultConfigDir(), "identity.enc") }
func DefaultPlaintextIdentityPath() string { return filepath.Join(DefaultConfigDir(), "identity.txt") }
