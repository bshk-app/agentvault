//go:build darwin

package keystore

import (
	"errors"
	"strings"
	"testing"

	"github.com/beshkenadze/agentvault/internal/backend"
)

// mockRunner records the args it was called with and returns canned output/error,
// standing in for the real `security` binary so the store/read logic is fully testable.
type mockRunner struct {
	gotArgs []string
	out     []byte
	err     error
}

func (m *mockRunner) run(args ...string) ([]byte, error) {
	m.gotArgs = args
	return m.out, m.err
}

func TestStoreIssuesAddGenericPasswordArgs(t *testing.T) {
	// Store must issue an UPDATING add-generic-password (-U) for service "agentvault",
	// account "identity", with the value via -w, and -T /usr/bin/security on the ACL so
	// avd's later silent Read does not pop a GUI prompt.
	const identity = "AGE-SECRET-KEY-1EXAMPLE"
	m := &mockRunner{}
	s := NewWithRunner(m.run)

	if err := s.Store([]byte(identity)); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"add-generic-password", "-U",
		"-s", "agentvault",
		"-a", "identity",
		"-w", identity,
		"-T", "/usr/bin/security",
	}
	if len(m.gotArgs) != len(want) {
		t.Fatalf("args = %v, want %v", m.gotArgs, want)
	}
	for i := range want {
		if m.gotArgs[i] != want[i] {
			t.Fatalf("args = %v, want %v", m.gotArgs, want)
		}
	}
}

func TestReadReturnsTrimmedValue(t *testing.T) {
	// `security ... -w` writes ONLY the password to stdout (trailing newline); trim it.
	const identity = "AGE-SECRET-KEY-1EXAMPLE"
	m := &mockRunner{out: []byte(identity + "\n")}
	s := NewWithRunner(m.run)

	got, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != identity {
		t.Fatalf("value = %q, want %q", got, identity)
	}

	want := []string{"find-generic-password", "-s", "agentvault", "-a", "identity", "-w"}
	if len(m.gotArgs) != len(want) {
		t.Fatalf("args = %v, want %v", m.gotArgs, want)
	}
	for i := range want {
		if m.gotArgs[i] != want[i] {
			t.Fatalf("args = %v, want %v", m.gotArgs, want)
		}
	}
}

func TestReadNotFoundMapsToErrNotFound(t *testing.T) {
	// A security-style not-found message must surface as backend.ErrNotFound (errors.Is-able)
	// so an absent identity is never confused with a transport/permission failure.
	m := &mockRunner{err: errors.New("security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.")}
	s := NewWithRunner(m.run)

	_, err := s.Read()
	if !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestReadExitStatus44MapsToErrNotFound(t *testing.T) {
	// `security` exits 44 when the item is absent; that code alone (even without the
	// stderr phrase) must map to ErrNotFound.
	m := &mockRunner{err: &fakeExit{code: 44}}
	s := NewWithRunner(m.run)

	_, err := s.Read()
	if !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestReadGenericErrorIsWrappedWithoutValue(t *testing.T) {
	// A generic security failure must NOT be ErrNotFound (fail-closed), must be wrapped,
	// and must never leak the identity. The identity is never present on the read path
	// (Read passes no value to security), but we still assert the error stays value-free
	// against the secret we would have stored, to lock in the invariant.
	const identity = "AGE-SECRET-KEY-1EXAMPLE"
	m := &mockRunner{err: errors.New("security: SecKeychainOpenError: User interaction is not allowed.")}
	s := NewWithRunner(m.run)

	_, err := s.Read()
	if err == nil {
		t.Fatal("expected error for generic security failure")
	}
	if errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("generic failure misreported as ErrNotFound: %v", err)
	}
	if strings.Contains(err.Error(), identity) {
		t.Fatalf("error leaked the value: %v", err)
	}
}

func TestStoreGenericErrorDoesNotLeakIdentity(t *testing.T) {
	// On a Store failure the error must never carry the identity bytes that were passed
	// via argv — only security's own (value-free) diagnostic.
	const identity = "AGE-SECRET-KEY-1EXAMPLE"
	m := &mockRunner{err: errors.New("security: SecAuthFailure: authorization denied.")}
	s := NewWithRunner(m.run)

	err := s.Store([]byte(identity))
	if err == nil {
		t.Fatal("expected error for generic security failure")
	}
	if strings.Contains(err.Error(), identity) {
		t.Fatalf("error leaked the identity: %v", err)
	}
}

// fakeExit emulates an *exec.ExitError carrying a given exit code, so the exit-44
// not-found path can be exercised without invoking the real `security` binary.
type fakeExit struct {
	code int
}

func (e *fakeExit) Error() string { return "exit status " + itoa(e.code) }
func (e *fakeExit) ExitCode() int { return e.code }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
