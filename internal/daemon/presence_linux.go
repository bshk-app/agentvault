//go:build linux

package daemon

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

const polkitActionID = "app.bshk.agentvault.unlock"

type presenceRunner func(args ...string) error

type polkitPresence struct {
	run presenceRunner
}

type exitCoder interface {
	ExitCode() int
}

func newTouchIDPresence() (Presence, error) {
	return polkitPresence{run: pkcheckExec}, nil
}

func NewTouchIDPresence() (Presence, error) { return newTouchIDPresence() }

func pkcheckExec(args ...string) error {
	return exec.Command("pkcheck", args...).Run()
}

func newPolkitPresenceWithRunner(run presenceRunner) Presence {
	return polkitPresence{run: run}
}

func (p polkitPresence) Prompt(reason string) error {
	if p.run == nil {
		return ErrLocked
	}
	err := p.run(
		"--allow-user-interaction",
		"--action-id", polkitActionID,
		"--process", fmt.Sprint(os.Getpid()),
	)
	if err == nil {
		return nil
	}
	var ec exitCoder
	if errors.As(err, &ec) {
		switch ec.ExitCode() {
		case 1:
			return ErrDenied
		case 2, 3:
			return ErrLocked
		}
	}
	_ = reason
	return ErrLocked
}
