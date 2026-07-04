package daemon

import "errors"

// errInstanceLocked is returned by acquireInstanceLock when another avd instance already
// owns the process-wide lock for the socket path.
var errInstanceLocked = errors.New("instance already locked")

// instanceLock is the platform-specific single-instance guard held for the daemon's
// lifetime. Closing it releases the lock.
type instanceLock interface {
	Close() error
}
