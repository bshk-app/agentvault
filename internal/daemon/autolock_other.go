//go:build (!darwin || !cgo) && !linux

package daemon

// StartAutoLock is the fallback for builds without darwin+cgo (CGO_ENABLED=0, or
// non-macOS). Screen-lock/sleep observers require NSDistributedNotificationCenter
// / NSWorkspace via cgo on darwin; here there is nothing to observe, so this is a
// no-op returning a no-op stop. The seam exists on every build so cmd/avd can
// call StartAutoLock unconditionally.
func StartAutoLock(s *Session) (stop func()) {
	return func() {}
}
