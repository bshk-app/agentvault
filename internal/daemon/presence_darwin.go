//go:build darwin && cgo

package daemon

/*
#cgo CFLAGS: -fobjc-arc
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation
#include <stdlib.h>

// av_touchid_prompt is implemented in touchid_darwin.m (compiled by cgo on
// darwin). Return codes: 0=success, 1=cancel/auth-failure, 2=policy
// unavailable/error.
int av_touchid_prompt(const char *reason);
*/
import "C"

import "unsafe"

// touchIDPresence implements Presence via macOS LocalAuthentication. Each
// Prompt is a fresh, blocking biometric (Touch ID, with device-passcode
// fallback) presence check. It requires avd to run in the user's GUI session
// so the system can present the prompt.
type touchIDPresence struct{}

// newTouchIDPresence constructs the Touch ID presence backend. It does not
// itself invoke a prompt; capability is only exercised on the first Prompt.
func newTouchIDPresence() (Presence, error) {
	return touchIDPresence{}, nil
}

// Prompt blocks until the user responds to the native LocalAuthentication
// dialog. success -> nil; user cancel/failure -> ErrDenied; policy
// unavailable/system error -> ErrLocked.
func (touchIDPresence) Prompt(reason string) error {
	cr := C.CString(reason)
	defer C.free(unsafe.Pointer(cr))

	switch C.av_touchid_prompt(cr) {
	case 0:
		return nil
	case 1:
		return ErrDenied
	default:
		return ErrLocked
	}
}
