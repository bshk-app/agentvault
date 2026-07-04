//go:build linux

package transport

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// PeerUID returns the UID of the process on the other end of a unix-socket conn.
func PeerUID(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("not a unix conn: %T", c)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if e != nil {
			cerr = e
			return
		}
		uid = cred.Uid
	}); err != nil {
		return 0, err
	}
	return uid, cerr
}

func checkUID(peer, self uint32) error {
	if peer != self {
		return fmt.Errorf("peer uid %d != daemon uid %d", peer, self)
	}
	return nil
}

// CheckPeer rejects a connection whose peer UID differs from this process's UID.
func CheckPeer(c net.Conn) error {
	peer, err := PeerUID(c)
	if err != nil {
		return err
	}
	return checkUID(peer, uint32(os.Getuid()))
}
