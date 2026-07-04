//go:build !darwin && !linux && !windows

package client

import "errors"

// autostart is the fallback for platforms without a detached-launch implementation. It
// FAILS LOUDLY rather than pretending to start the daemon. The symbol exists on every
// build so client.dial compiles regardless of build tags.
func autostart(socketPath string) error {
	_ = socketPath
	return errors.New("daemon autostart unsupported on this platform")
}
