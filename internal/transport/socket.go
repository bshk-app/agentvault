//go:build !windows

// Package transport provides AgentVault's local unix-socket listener and dialer,
// with a strict 0600 socket and a peer-credential check (see peercred_*.go).
package transport

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// DefaultSocketPath returns the daemon socket path: $AV_SOCKET_PATH if set, else
// $XDG_RUNTIME_DIR/agentvault/avd.sock if set, else <user-cache-dir>/agentvault/avd.sock
// (macOS: ~/Library/Caches/...).
func DefaultSocketPath() (string, error) {
	if p, ok := socketPathOverride(); ok {
		return p, nil
	}
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		c, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		base = c
	}
	return filepath.Join(base, "agentvault", "avd.sock"), nil
}

// Listen creates the parent dir (0700), binds a unix socket at path, and chmods it 0600.
// A stale socket file is removed first.
func Listen(path string) (net.Listener, error) {
	if len(path) >= 104 { // macOS sun_path limit (Linux 108); guard the shortest
		return nil, fmt.Errorf("socket path too long (%d bytes, max 103): %s", len(path), path)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// Re-assert 0700 in case the parent dir pre-existed with looser perms.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("chmod socket dir 0700: %w", err)
	}
	// Remove a stale socket (caller is responsible for single-instance checks).
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove stale socket: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// Dial connects to the daemon socket.
func Dial(path string) (net.Conn, error) {
	return net.Dial("unix", path)
}
