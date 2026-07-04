//go:build (!darwin || !cgo) && !linux && !windows

package daemon

import "errors"

// newTouchIDPresence is the fallback for builds without a native presence backend.
// The constructor exists on every build so callers (cmd/avd) compile regardless of
// build tags.
func newTouchIDPresence() (Presence, error) {
	return nil, errors.New("native presence unavailable on this build")
}

// NewTouchIDPresence is the exported constructor cmd/avd wires in production. On builds
// without a native backend it returns the same unavailable error, so cmd/avd fails loudly
// rather than silently running without a real presence check.
func NewTouchIDPresence() (Presence, error) { return newTouchIDPresence() }
