//go:build windows

package transport

import (
	"errors"
	"fmt"
	"net"
)

var errPeerUIDUnavailable = errors.New("peer uid unavailable on windows named pipes")

// PeerUID is intentionally unavailable on Windows. The production authorization boundary
// is enforced when Listen creates the named pipe with an ACL for the current user SID.
func PeerUID(c net.Conn) (uint32, error) {
	if c == nil {
		return 0, fmt.Errorf("nil conn")
	}
	return 0, errPeerUIDUnavailable
}

func checkUID(peer, self uint32) error {
	if peer != self {
		return fmt.Errorf("peer uid %d != daemon uid %d", peer, self)
	}
	return nil
}

// CheckPeer succeeds because Windows named-pipe access is constrained by the pipe's
// current-user security descriptor at connection time.
func CheckPeer(c net.Conn) error {
	if c == nil {
		return fmt.Errorf("nil conn")
	}
	return nil
}
