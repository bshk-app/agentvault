//go:build windows

package transport

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// DefaultSocketPath returns a filesystem-backed logical endpoint path. On Windows the
// actual IPC endpoint is a named pipe derived from this path, while the logical path's
// parent remains the daemon's runtime directory for the lockfile and audit log.
//
// $AV_SOCKET_PATH overrides it. Note that $XDG_RUNTIME_DIR does NOT apply here — it is a
// Unix convention this platform has no equivalent of — so the override is the only way to
// run an isolated instance on Windows.
func DefaultSocketPath() (string, error) {
	if p, ok := socketPathOverride(); ok {
		return p, nil
	}
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		c, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		base = c
	}
	return filepath.Join(base, "AgentVault", "avd.pipe"), nil
}

func Listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	sddl, err := currentUserPipeSDDL()
	if err != nil {
		return nil, err
	}
	return winio.ListenPipe(pipeNameFromPath(path), &winio.PipeConfig{
		SecurityDescriptor: sddl,
		InputBufferSize:    64 * 1024,
		OutputBufferSize:   64 * 1024,
	})
}

func Dial(path string) (net.Conn, error) {
	timeout := 2 * time.Second
	return winio.DialPipe(pipeNameFromPath(path), &timeout)
}

func pipeNameFromPath(path string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(path))))
	return `\\.\pipe\agentvault-` + hex.EncodeToString(sum[:16])
}

func currentUserPipeSDDL() (string, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	sid := tu.User.Sid.String()
	if sid == "" {
		return "", fmt.Errorf("current user sid is empty")
	}
	// Owner=current user. DACL permits current user full access and keeps LocalSystem /
	// Administrators for diagnostics/service tooling.
	return fmt.Sprintf("O:%sD:P(A;;GA;;;%s)(A;;GA;;;SY)(A;;GA;;;BA)", sid, sid), nil
}
