//go:build !darwin

// Package keystore on non-darwin platforms provides a stub Store so cmd/avd compiles and
// cross-compiles everywhere. The login keychain (and the `security` CLI) exist only on
// darwin; the real implementation lives in keystore_darwin.go. Here Store and Read always
// fail with a clear, value-free "requires macOS" error.
package keystore

import "errors"

// errUnsupported is the value-free error returned by Store/Read on non-darwin.
var errUnsupported = errors.New("keystore requires macOS")

// Store is the non-darwin stub. It carries no state; every operation errors.
type Store struct{}

// New returns the non-darwin stub store.
func New() *Store {
	return &Store{}
}

// NewWithRunner exists for API parity with the darwin build (so test/wiring code can be
// written platform-agnostically). The runner is ignored: there is no `security` here.
func NewWithRunner(_ func(args ...string) ([]byte, error)) *Store {
	return &Store{}
}

// Store always fails on non-darwin: there is no login keychain to write. The error
// carries no identity material.
func (s *Store) Store(_ []byte) error {
	return errUnsupported
}

// Read always fails on non-darwin: there is no login keychain to query.
func (s *Store) Read() ([]byte, error) {
	return nil, errUnsupported
}
