//go:build linux

package daemon

import (
	"errors"
	"testing"
)

func TestPolkitPresenceAllowsOnZeroExit(t *testing.T) {
	p := newPolkitPresenceWithRunner(func(args ...string) error { return nil })
	if err := p.Prompt("Unlock AgentVault"); err != nil {
		t.Fatalf("Prompt = %v, want nil", err)
	}
}

func TestPolkitPresenceGenericFailureLocks(t *testing.T) {
	p := newPolkitPresenceWithRunner(func(args ...string) error { return errors.New("no auth agent") })
	if err := p.Prompt("Unlock AgentVault"); !errors.Is(err, ErrLocked) {
		t.Fatalf("Prompt = %v, want ErrLocked", err)
	}
}

func TestPolkitPresenceDeniedExitMapsToDenied(t *testing.T) {
	p := newPolkitPresenceWithRunner(func(args ...string) error {
		return fakePresenceExit(1)
	})
	if err := p.Prompt("Unlock AgentVault"); !errors.Is(err, ErrDenied) {
		t.Fatalf("Prompt = %v, want ErrDenied", err)
	}
}

type fakePresenceExit int

func (e fakePresenceExit) Error() string { return "exit status" }
func (e fakePresenceExit) ExitCode() int { return int(e) }
