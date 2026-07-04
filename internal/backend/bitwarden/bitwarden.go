// Package bitwarden implements a read-only Backend backed by the Bitwarden Password
// Manager CLI (`bw`). It shells out to `bw get <object> <id-or-search> --raw
// --nointeraction`, so self-hosted instances are supported through the user's existing
// `bw config server ...` and login/unlock state.
//
// SECURITY: AgentVault does not log in, unlock, store BW_SESSION, or manage Bitwarden
// state. A resolved value is returned only in Secret.Value. Error paths include only the
// bw command context and bw diagnostics, never stdout/value.
package bitwarden

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/beshkenadze/agentvault/internal/backend"
)

// runner runs the `bw` CLI with args and returns its stdout (or an error). It is
// injected so tests can mock bw without the binary; production uses bwExec.
type runner func(args ...string) ([]byte, error)

// Backend resolves secrets through the injected bw runner.
type Backend struct {
	run runner
}

// New returns a Backend that shells out to the real `bw` binary.
func New() *Backend {
	return &Backend{run: bwExec}
}

// NewWithRunner returns a Backend driven by the injected runner (for tests).
func NewWithRunner(run runner) *Backend {
	return &Backend{run: run}
}

// bwExec is the production runner: it runs `bw <args...>` via os/exec and returns
// stdout with the trailing newline trimmed. exec.Command(...).Output() captures stderr
// in *exec.ExitError.Stderr, which Resolve inspects to classify not-found.
func bwExec(args ...string) ([]byte, error) {
	out, err := exec.Command("bw", args...).Output()
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(string(out), "\n")), nil
}

// Resolve maps the av:// locator (everything after "av://bw/") to a `bw get` call.
// The locator is "<object>/<id-or-search>", where object is one of password, username,
// uri, totp, or notes. The id/search portion is the verbatim remainder and may contain
// slashes. Full `item` JSON is deliberately unsupported in v1 because partial values
// inside the returned JSON would not be guaranteed to exact-match-redact if printed
// separately by a child process.
func (b *Backend) Resolve(locator string) (backend.Secret, error) {
	object, target, ok := strings.Cut(locator, "/")
	if !ok || object == "" || target == "" {
		return backend.Secret{}, fmt.Errorf("bitwarden: malformed locator %q (want <object>/<id-or-search>)", locator)
	}
	if !allowedObject(object) {
		return backend.Secret{}, fmt.Errorf("bitwarden: unsupported object %q (want password|username|uri|totp|notes)", object)
	}

	out, err := b.run("get", object, target, "--raw", "--nointeraction")
	if err != nil {
		if isNotFound(err) {
			return backend.Secret{}, fmt.Errorf("bw get %s %s: %w", object, target, backend.ErrNotFound)
		}
		return backend.Secret{}, fmt.Errorf("bw get %s %s: %w", object, target, redactExec(err))
	}
	return backend.Secret{Value: strings.TrimRight(string(out), "\n")}, nil
}

// List is metadata-only and not load-bearing for resolve, so v1 returns an empty list.
func (b *Backend) List(prefix string) ([]backend.Meta, error) {
	return nil, nil
}

func allowedObject(object string) bool {
	switch object {
	case "password", "username", "uri", "totp", "notes":
		return true
	default:
		return false
	}
}

// isNotFound reports whether a bw failure means "no such item/field" (→ ErrNotFound)
// rather than auth, locked-vault, multiple-match, transport, or server errors.
func isNotFound(err error) bool {
	msgs := []string{err.Error()}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		msgs = append(msgs, string(ee.Stderr))
	}
	for _, msg := range msgs {
		for _, line := range strings.Split(msg, "\n") {
			if strings.ToLower(strings.TrimSpace(line)) == "not found." {
				return true
			}
		}
	}
	return false
}

// redactExec returns an error safe to wrap: for an *exec.ExitError it surfaces bw's
// stderr diagnostics instead of the bare "exit status N" while never reading stdout.
func redactExec(err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(ee.Stderr) > 0 {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(ee.Stderr)))
	}
	return err
}

// compile-time check that Backend satisfies the interface.
var _ backend.Backend = (*Backend)(nil)
