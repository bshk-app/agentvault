//go:build unix

package daemon

import "syscall"

// mlock pins the page(s) backing b into RAM so the secret is never written to swap.
// On failure (commonly RLIMIT_MEMLOCK on an unprivileged process) it returns the
// error; the caller falls back to no-mlock-but-still-zeroize.
func mlock(b []byte) error { return syscall.Mlock(b) }

// munlock releases the pin taken by mlock. Best-effort; a failure is non-fatal.
func munlock(b []byte) error { return syscall.Munlock(b) }
