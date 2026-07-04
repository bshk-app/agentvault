//go:build !darwin && !linux && !windows

package transport

import (
	"errors"
	"fmt"
	"net"
)

// errPeerCredUnsupported is returned by every platform without a peer-credential
// implementation. Rather than fake-allow a connection on a platform where we cannot read
// the peer UID, the check FAILS CLOSED so a build can never silently bypass the same-UID
// guard.
var errPeerCredUnsupported = errors.New("peer-credential check unsupported on this platform")

// PeerUID is the non-darwin fallback. There is no portable way to read the peer
// UID of a unix-socket conn here, so it reports the unsupported error. The
// symbol exists on every build so callers (and tests) compile regardless of tags.
func PeerUID(c net.Conn) (uint32, error) {
	if _, ok := c.(*net.UnixConn); !ok {
		return 0, fmt.Errorf("not a unix conn: %T", c)
	}
	return 0, errPeerCredUnsupported
}

// checkUID mirrors the darwin pure helper so shared tests compile and behave
// identically: it returns an error unless peer == self.
func checkUID(peer, self uint32) error {
	if peer != self {
		return fmt.Errorf("peer uid %d != daemon uid %d", peer, self)
	}
	return nil
}

// CheckPeer FAILS CLOSED on non-darwin: it always rejects, because we cannot
// verify the peer UID on this platform and refusing is safer than allowing.
func CheckPeer(c net.Conn) error {
	return errPeerCredUnsupported
}
