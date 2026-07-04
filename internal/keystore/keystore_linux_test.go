//go:build linux

package keystore

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type mockRunner struct {
	input []byte
	args  []string
	out   []byte
	err   error
}

func (m *mockRunner) run(input []byte, args ...string) ([]byte, error) {
	m.input = append([]byte(nil), input...)
	m.args = append([]string(nil), args...)
	return m.out, m.err
}

func TestLinuxStoreUsesSecretToolStdin(t *testing.T) {
	const identity = "AGE-SECRET-KEY-1EXAMPLE"
	m := &mockRunner{}
	s := NewWithRunner(m.run)

	if err := s.Store([]byte(identity + "\n")); err != nil {
		t.Fatal(err)
	}
	if string(m.input) != identity {
		t.Fatalf("stdin identity = %q, want trimmed identity", m.input)
	}
	want := []string{"store", "--label", label, "service", service, "account", account}
	if !reflect.DeepEqual(m.args, want) {
		t.Fatalf("args = %v, want %v", m.args, want)
	}
}

func TestLinuxReadLooksUpSecretToolItem(t *testing.T) {
	const identity = "AGE-SECRET-KEY-1EXAMPLE"
	m := &mockRunner{out: []byte(identity + "\n")}
	s := NewWithRunner(m.run)

	got, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != identity {
		t.Fatalf("identity = %q, want %q", got, identity)
	}
	want := []string{"lookup", "service", service, "account", account}
	if !reflect.DeepEqual(m.args, want) {
		t.Fatalf("args = %v, want %v", m.args, want)
	}
}

func TestLinuxStoreErrorDoesNotLeakIdentity(t *testing.T) {
	const identity = "AGE-SECRET-KEY-1EXAMPLE"
	m := &mockRunner{err: errors.New("secret service unavailable")}
	s := NewWithRunner(m.run)

	err := s.Store([]byte(identity))
	if err == nil {
		t.Fatal("expected store error")
	}
	if strings.Contains(err.Error(), identity) {
		t.Fatalf("error leaked identity: %v", err)
	}
}
