//go:build darwin

// Package keystore stores AgentVault's age IDENTITY (the private key for the local
// agefile vault) in the macOS login keychain via the `security` CLI. It is the
// "keychain tier" of the tiered identity-protection design: when the Secure Enclave is
// unavailable (e.g. the build-from-source / ad-hoc brew binary), the generated identity
// is kept as a keychain generic-password item instead of plaintext on disk.
//
// Like internal/backend/keychain, the exec runner is INJECTED (type runner) so the
// store/read LOGIC is fully unit-testable with a mock; production wires the real
// `security` binary. Isolated package so the os/exec dependency never reaches the thin
// av — only avd links it.
//
// SECURITY:
//   - Store passes the identity via argv to `security` (add-generic-password -w <bytes>).
//     This opens a brief same-UID `ps` window during the exec; under the cooperative-agent
//     threat model (any process running as this user could already read the keychain item
//     it is about to write) that is acceptable. The identity is NEVER logged and NEVER
//     embedded in an error — on failure only security's own value-free diagnostic is kept.
//   - The item is created with `-T /usr/bin/security` on its ACL so avd's later silent
//     Read via the very same `security` binary is authorized WITHOUT a GUI prompt
//     (auto-unlock is mediated separately by a Touch ID presence check, not by a keychain
//     dialog). `-A` (allow ALL applications) would also be prompt-free but is far broader;
//     `-T /usr/bin/security` scopes trust to exactly the tool we use, so it is preferred.
//   - `-U` updates an existing item in place, so re-provisioning (rotate) overwrites
//     rather than duplicating or erroring.
package keystore

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/beshkenadze/agentvault/internal/backend"
)

// service and account name the single generic-password item that holds the identity.
const (
	service = "agentvault"
	account = "identity"
)

// runner runs the `security` CLI with args and returns its stdout (or an error). It is
// injected so tests can mock `security` without the binary; production uses securityExec.
type runner func(args ...string) ([]byte, error)

// Store reads/writes the age identity through the injected `security` runner.
type Store struct {
	run runner
}

// New returns a Store that shells out to the real `security` binary.
func New() *Store {
	return &Store{run: securityExec}
}

// NewWithRunner returns a Store driven by the injected runner (for tests).
func NewWithRunner(run runner) *Store {
	return &Store{run: run}
}

// securityExec is the production runner: it runs `security <args...>` via os/exec and
// returns stdout with the trailing newline trimmed. exec.Command(...).Output() captures
// stderr in *exec.ExitError.Stderr, which Read inspects to classify not-found.
func securityExec(args ...string) ([]byte, error) {
	out, err := exec.Command("security", args...).Output()
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(string(out), "\n")), nil
}

// Store writes (or updates, via -U) the age identity into the login keychain as the
// generic-password item (service "agentvault", account "identity"). The value is passed
// with -w and the ACL is scoped to /usr/bin/security with -T so avd's later silent Read
// is prompt-free. See the package SECURITY note: the identity is on the argv for the
// duration of this exec, and never appears in an error or log.
func (s *Store) Store(identity []byte) error {
	_, err := s.run(
		"add-generic-password", "-U",
		"-s", service,
		"-a", account,
		"-w", string(identity),
		"-T", "/usr/bin/security",
	)
	if err != nil {
		// Wrap with security's (value-free) diagnostic only; never echo the identity.
		return fmt.Errorf("keystore store: %w", redactExec(err))
	}
	return nil
}

// Read returns the age identity from the keychain item, trimmed of the trailing newline
// that `security ... -w` appends. An absent item maps to backend.ErrNotFound (reused so
// callers can errors.Is it uniformly with other backends); any other failure is wrapped
// and NEVER contains a value (Read passes no value to security in the first place).
func (s *Store) Read() ([]byte, error) {
	out, err := s.run("find-generic-password", "-s", service, "-a", account, "-w")
	if err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("keystore read: %w", backend.ErrNotFound)
		}
		return nil, fmt.Errorf("keystore read: %w", redactExec(err))
	}
	return []byte(strings.TrimRight(string(out), "\n")), nil
}

// exitCoder is satisfied by *exec.ExitError; isNotFound uses it to detect security's
// "item not found" exit status 44.
type exitCoder interface {
	ExitCode() int
}

// isNotFound reports whether a `security` failure means "no such item" (→ ErrNotFound)
// rather than a permission/transport/other error. It checks the exit code (44 == item
// not found) and security's stderr (captured in *exec.ExitError.Stderr by Output()).
//
// It deliberately matches only RESOURCE-specific not-found phrasings: a broad substring
// would risk reclassifying a permission/transport error as "no identity", masking a real
// failure. A genuine not-found we miss just stays a hard error (safe); a transport error
// we wrongly call "not found" would silently hide a present identity (unsafe).
func isNotFound(err error) bool {
	var ec exitCoder
	if errors.As(err, &ec) && ec.ExitCode() == 44 {
		return true
	}

	msg := strings.ToLower(err.Error())
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		msg += " " + strings.ToLower(string(ee.Stderr))
	}
	for _, phrase := range []string{
		"could not be found in the keychain",
		"seckeychainsearchcopynext",
		"the specified item could not be found",
	} {
		if strings.Contains(msg, phrase) {
			return true
		}
	}
	return false
}

// redactExec returns an error safe to wrap: for an *exec.ExitError it surfaces security's
// stderr (diagnostics, never the value) instead of the bare "exit status N" so the wrapped
// error is actionable while staying value-free.
func redactExec(err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(ee.Stderr) > 0 {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(ee.Stderr)))
	}
	return err
}
