//go:build !darwin || !cgo

// Package enclave on builds without darwin+cgo provides stubs so the package and
// every caller (cmd/avd) compile and cross-compile everywhere. The Secure Enclave
// exists only on Apple hardware and is reached via cgo + Security.framework; the
// real implementation lives in enclave_darwin.go. Here every operation fails with a
// clear, value-free "secure enclave unavailable on this build" error so callers can
// fall back to the env-path (AV_AGE_IDENTITY) identity.
package enclave

import "errors"

// errUnavailable is the value-free error every stub returns. Its wording is shared
// with the darwin build so callers may branch on a single stable phrase.
var errUnavailable = errors.New("secure enclave unavailable on this build")

// EnsureKey is unavailable on this build.
func EnsureKey() error { return errUnavailable }

// Available is false on this build — the Secure Enclave needs darwin+cgo.
func Available() bool { return false }

// Wrap is unavailable on this build. It never returns plaintext.
func Wrap(_ []byte) ([]byte, error) { return nil, errUnavailable }

// Unwrap is unavailable on this build. It never returns plaintext.
func Unwrap(_ []byte) ([]byte, error) { return nil, errUnavailable }

// IsUserCanceled mirrors the darwin predicate so cmd/avd compiles and cross-compiles
// everywhere. On this build Unwrap only ever returns errUnavailable (never a Touch ID
// cancel), so there is no user-cancel to detect — it always reports false, leaving such
// a failure mapped to CodeLocked.
func IsUserCanceled(_ error) bool { return false }
