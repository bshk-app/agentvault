//go:build linux

// Package keystore stores AgentVault's age identity in the desktop Secret Service
// keyring via libsecret's `secret-tool` CLI.
package keystore

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/beshkenadze/agentvault/internal/backend"
)

const (
	label   = "AgentVault identity"
	service = "agentvault"
	account = "identity"
)

type runner func(input []byte, args ...string) ([]byte, error)

type Store struct {
	run runner
}

func New() *Store {
	return &Store{run: secretToolExec}
}

func NewWithRunner(run runner) *Store {
	return &Store{run: run}
}

func secretToolExec(input []byte, args ...string) ([]byte, error) {
	cmd := exec.Command("secret-tool", args...)
	if input != nil {
		cmd.Stdin = strings.NewReader(string(input))
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(string(out), "\n")), nil
}

func (s *Store) Store(identity []byte) error {
	value := []byte(strings.TrimRight(string(identity), "\n"))
	_, err := s.run(value, "store", "--label", label, "service", service, "account", account)
	if err != nil {
		return fmt.Errorf("keystore store: %w", redactExec(err))
	}
	return nil
}

func (s *Store) Read() ([]byte, error) {
	out, err := s.run(nil, "lookup", "service", service, "account", account)
	if err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("keystore read: %w", backend.ErrNotFound)
		}
		return nil, fmt.Errorf("keystore read: %w", redactExec(err))
	}
	return []byte(strings.TrimRight(string(out), "\n")), nil
}

type exitCoder interface {
	ExitCode() int
}

func isNotFound(err error) bool {
	var ec exitCoder
	if errors.As(err, &ec) && ec.ExitCode() == 1 {
		msg := strings.ToLower(err.Error())
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			msg += " " + strings.ToLower(string(ee.Stderr))
		}
		for _, phrase := range []string{
			"no such secret",
			"no matching results",
			"the name is not activatable",
		} {
			if strings.Contains(msg, phrase) {
				return true
			}
		}
	}
	return false
}

func redactExec(err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(ee.Stderr) > 0 {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(ee.Stderr)))
	}
	return err
}
