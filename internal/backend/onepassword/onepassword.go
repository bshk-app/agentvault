// Package onepassword implements a Backend backed by the 1Password CLI (`op`). It
// shells out to `op read "op://Vault/Item/field"` to resolve a secret. The exec
// runner is INJECTED (type runner) so the resolve LOGIC is fully unit-testable with a
// mock; production wires the real `op` binary. Isolated package (like agefile) so the
// os/exec + op dependency never reaches the thin av — only avd links it.
//
// SECURITY: a resolved value is returned only in Secret.Value. No error path ever
// embeds the value: op errors carry the op:// ref and op's own (value-free) message.
//
// MANUAL: with `op` installed and signed in (`op signin`), avd registers this backend
// under "1p" and `av://1p/Vault/Item/field` resolves for real against the live vault.
// CI/subagents cannot run the real `op` (needs install + interactive sign-in), so only
// the injected-runner logic is covered by tests; the live path is verified by hand.
package onepassword

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/beshkenadze/agentvault/internal/backend"
)

// runner runs the `op` CLI with args and returns its stdout (or an error). It is
// injected so tests can mock op without the binary; production uses opExec.
type runner func(args ...string) ([]byte, error)

// Backend resolves secrets through the injected op runner.
type Backend struct {
	run runner
}

// New returns a Backend that shells out to the real `op` binary.
func New() *Backend {
	return &Backend{run: opExec}
}

// NewWithRunner returns a Backend driven by the injected runner (for tests).
func NewWithRunner(run runner) *Backend {
	return &Backend{run: run}
}

// opExec is the production runner: it runs `op <args...>` via os/exec and returns
// stdout with the trailing newline trimmed. exec.Command(...).Output() captures
// stderr in *exec.ExitError.Stderr, which Resolve inspects to classify not-found.
func opExec(args ...string) ([]byte, error) {
	out, err := exec.Command("op", args...).Output()
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(string(out), "\n")), nil
}

// Resolve maps the av:// locator (everything after "av://1p/") to an op:// reference
// and runs `op read`. The locator IS the op path body: "Vault/Item/field" →
// "op://Vault/Item/field". On success it returns the trimmed output as the value.
//
// op exits non-zero when the item/field is missing; not-found is distinguished from a
// generic failure by op's stderr ("isn't an item", "not found", "no item", etc.) so a
// missing secret maps to backend.ErrNotFound and any other failure is a wrapped error
// that NEVER contains the value.
func (b *Backend) Resolve(locator string) (backend.Secret, error) {
	ref := "op://" + locator
	out, err := b.run("read", ref)
	if err != nil {
		if isNotFound(err) {
			return backend.Secret{}, fmt.Errorf("op read %s: %w", ref, backend.ErrNotFound)
		}
		// Wrap with the ref and op's (value-free) error. The value never appears here
		// because on error op writes only diagnostics to stderr, not the secret.
		return backend.Secret{}, fmt.Errorf("op read %s: %w", ref, redactExec(err))
	}
	return backend.Secret{Value: strings.TrimRight(string(out), "\n")}, nil
}

// List is best-effort metadata only. `op item list` returns a complex per-vault JSON
// shape that is not load-bearing for resolve (the design treats List as metadata-only),
// so v1 returns an empty list — resolution does not depend on it. A future revision can
// shell out to `op item list --format=json` if listing is needed.
func (b *Backend) List(prefix string) ([]backend.Meta, error) {
	return nil, nil
}

// isNotFound reports whether an op failure means "no such item/field" (→ ErrNotFound)
// rather than a transport/auth/other error. It checks op's stderr (captured in
// *exec.ExitError.Stderr by Output()) and the error text for op's not-found phrasings.
func isNotFound(err error) bool {
	msg := strings.ToLower(err.Error())
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		msg += " " + strings.ToLower(string(ee.Stderr))
	}
	for _, phrase := range []string{
		"isn't an item",
		"isn't a field",
		"not found",
		"no item",
		"doesn't exist",
		"could not find",
		"no such",
	} {
		if strings.Contains(msg, phrase) {
			return true
		}
	}
	return false
}

// redactExec returns an error safe to wrap: for an *exec.ExitError it surfaces op's
// stderr (diagnostics, never the value) instead of the bare "exit status N" so the
// wrapped error is actionable while staying value-free.
func redactExec(err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(ee.Stderr) > 0 {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(ee.Stderr)))
	}
	return err
}

// compile-time check that Backend satisfies the interface.
var _ backend.Backend = (*Backend)(nil)
