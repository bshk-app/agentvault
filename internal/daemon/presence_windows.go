//go:build windows

package daemon

import "errors"

func newTouchIDPresence() (Presence, error) {
	return nil, errors.New("windows hello presence unavailable: native WinRT bridge not implemented")
}

func NewTouchIDPresence() (Presence, error) { return newTouchIDPresence() }
