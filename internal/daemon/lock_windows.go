//go:build windows

package daemon

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

type windowsInstanceLock struct {
	f  *os.File
	ov windows.Overlapped
}

func acquireInstanceLock(path string) (instanceLock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create lock dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lockfile: %w", err)
	}
	l := windowsInstanceLock{f: f}
	err = windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		&l.ov,
	)
	if err != nil {
		_ = f.Close()
		return nil, errInstanceLocked
	}
	return l, nil
}

func (l windowsInstanceLock) Close() error {
	_ = windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, 1, 0, &l.ov)
	return l.f.Close()
}
