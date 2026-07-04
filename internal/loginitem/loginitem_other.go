//go:build !darwin && !linux && !windows

package loginitem

import "errors"

// ErrUnsupported reports that login-item registration is unsupported on this platform.
var ErrUnsupported = errors.New("loginitem: unsupported on this platform")

type unsupported struct{}

func New() Manager { return unsupported{} }

func (unsupported) Enable() error          { return ErrUnsupported }
func (unsupported) Disable() error         { return ErrUnsupported }
func (unsupported) Status() (State, error) { return StateDisabled, ErrUnsupported }
func (unsupported) Backend() Backend       { return "" }
