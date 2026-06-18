package client

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/beshkenadze/agentvault/internal/redact"
)

// RunOptions configures a single `av run` invocation.
type RunOptions struct {
	Profile      string   // profile to resolve from the manifest
	ManifestPath string   // path to agentvault.yaml (default "agentvault.yaml" in cwd)
	Command      []string // child argv (the part after `--`)
}

// defaultManifestPath is the manifest looked up in the cwd when ManifestPath is empty.
const defaultManifestPath = "agentvault.yaml"

// Run is the primary av path: it resolves opts.Profile through the daemon, injects
// the resolved values into the child's environment, forks opts.Command, and masks
// the child's stdout/stderr AT THE SOURCE (layer 1) so a resolved value never
// reaches the caller's stdout/stderr — the agent sees {{AV:NAME}}.
//
// Returns the child's exit code (0 on success, the child's code on a clean
// non-zero exit). On a setup/resolve failure it returns (-1, err); the caller
// (cmd/av) maps an *ipc.RPCError's Code to a distinct exit code (P4.7).
//
// SECURITY: the StreamRedactors are flushed via Close ONLY AFTER cmd.Wait returns,
// so the overlap tail is masked rather than truncated; the child's plaintext value
// is held only transiently and the references are dropped on return.
func Run(cl *Client, opts RunOptions, stdout, stderr io.Writer) (exitCode int, err error) {
	if len(opts.Command) == 0 {
		return -1, errors.New("av run: no command given (use: av run [--profile P] -- cmd args...)")
	}

	manifestPath := opts.ManifestPath
	if manifestPath == "" {
		manifestPath = defaultManifestPath
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		// No secret in this path — only the path/OS error.
		return -1, fmt.Errorf("av run: read manifest %s: %w", manifestPath, err)
	}

	// Resolve over the socket. avd parses the manifest and resolves the backends;
	// av stays thin. On a daemon error this is a *ipc.RPCError (caller inspects Code).
	vals, err := cl.Resolve(opts.Profile, manifestBytes)
	if err != nil {
		return -1, err
	}
	// nil/empty vals means the profile issued no secrets — mask nothing, not an error.

	secrets := make([]redact.Secret, 0, len(vals))
	for name, val := range vals {
		secrets = append(secrets, redact.Secret{Name: name, Value: val})
	}
	m := redact.NewMatcher(secrets)

	cmd := exec.Command(opts.Command[0], opts.Command[1:]...)
	cmd.Env = childEnv(vals)
	cmd.Stdin = os.Stdin

	// Layer 1: wrap the child's stdio at the source. A StreamRedactor is an
	// io.Writer that masks as it forwards; its retained tail must be flushed AFTER
	// the child exits (Close below).
	outR := redact.NewStreamRedactor(m, stdout)
	errR := redact.NewStreamRedactor(m, stderr)
	cmd.Stdout = outR
	cmd.Stderr = errR

	runErr := cmd.Run()

	// Flush the overlap tails AFTER the child has finished and all its output has
	// been written through the redactors. Closing earlier would truncate output.
	flushErr := outR.Close()
	if cerr := errR.Close(); flushErr == nil {
		flushErr = cerr
	}

	// Best-effort zeroize: drop references so the values are eligible for GC. Go strings
	// are immutable, so this cannot scrub the backing bytes; av stays thin (no memguard),
	// and the env-injected child inherently needs cleartext, so this is the most av can
	// do here. The canonical at-rest protection lives in avd's session (mlock + zeroize
	// of issued values); see internal/daemon/secmem.go. Clearing maps/secrets drops the
	// last av-side references promptly.
	clear(vals)
	for i := range secrets {
		secrets[i] = redact.Secret{}
	}

	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			// Clean non-zero exit: surface the child's code, not an error.
			return ee.ExitCode(), nil
		}
		// Could not start the child (e.g. command not found) — a real error.
		return -1, fmt.Errorf("av run: %w", runErr)
	}
	if flushErr != nil {
		return -1, fmt.Errorf("av run: flush masked output: %w", flushErr)
	}
	return 0, nil
}

// childEnv returns the parent environment with each resolved NAME=value appended
// (later entries win in exec, so resolved values override any inherited same-name).
func childEnv(vals map[string]string) []string {
	env := os.Environ()
	for name, val := range vals {
		env = append(env, name+"="+val)
	}
	return env
}
