//go:build !unix

package daemon

// Platforms without syscall.Mlock (e.g. Windows/Plan9): no-swap pinning is
// unavailable, so mlock is a no-op. Zeroize-on-destroy still applies — the secret is
// overwritten with zeros on Lock/expiry regardless of whether the page was pinned.
func mlock(b []byte) error { return errMlockUnsupported }

func munlock(b []byte) error { return nil }
