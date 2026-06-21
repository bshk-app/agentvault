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

	return runChild(vals, nil, true /* mask */, opts.Command, stdout, stderr)
}

// runChild execs command with the parent environment overlaid by literals then by the
// resolved vals (vals win), and — when mask is true — masks the resolved values in the
// child's stdout/stderr at the source (layer 1). Shared by av run (literals nil, always
// masked) and av env (literals from .env, mask = !--no-mask). Returns the child's exit
// code; (-1, err) on a start/flush failure.
func runChild(vals, literals map[string]string, mask bool, command []string, stdout, stderr io.Writer) (exitCode int, err error) {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = childEnv(vals, literals)
	cmd.Stdin = os.Stdin

	var outR, errR *redact.StreamRedactor
	if mask {
		secrets := make([]redact.Secret, 0, len(vals))
		for name, val := range vals {
			secrets = append(secrets, redact.Secret{Name: name, Value: val})
		}
		m := redact.NewMatcher(secrets)
		outR = redact.NewStreamRedactor(m, stdout)
		errR = redact.NewStreamRedactor(m, stderr)
		cmd.Stdout, cmd.Stderr = outR, errR
		defer func() {
			for i := range secrets {
				secrets[i] = redact.Secret{}
			}
		}()
	} else {
		cmd.Stdout, cmd.Stderr = stdout, stderr
	}

	runErr := cmd.Run()

	var flushErr error
	if mask {
		flushErr = outR.Close()
		if cerr := errR.Close(); flushErr == nil {
			flushErr = cerr
		}
	}
	clear(vals)

	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			return ee.ExitCode(), nil
		}
		return -1, fmt.Errorf("av: run %q: %w", command[0], runErr)
	}
	if flushErr != nil {
		return -1, fmt.Errorf("av: flush masked output: %w", flushErr)
	}
	return 0, nil
}

// childEnv returns the parent environment overlaid with literals, then vals (later
// entries win at exec, so a resolved value overrides any inherited/literal same-name).
func childEnv(vals, literals map[string]string) []string {
	env := os.Environ()
	for k, v := range literals {
		env = append(env, k+"="+v)
	}
	for k, v := range vals {
		env = append(env, k+"="+v)
	}
	return env
}
