//go:build unix

package daemon

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type fileInstanceLock struct {
	f *os.File
}

func acquireInstanceLock(path string) (instanceLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lockfile: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errInstanceLocked
		}
		return nil, fmt.Errorf("flock lockfile: %w", err)
	}
	return fileInstanceLock{f: f}, nil
}

func (l fileInstanceLock) Close() error {
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	return l.f.Close()
}
