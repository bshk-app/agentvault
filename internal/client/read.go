package client

import (
	"fmt"
	"io"
	"os"
)

// ReadOptions configures a single `av read` invocation.
type ReadOptions struct {
	Profile      string // profile to resolve from the manifest
	ManifestPath string // path to agentvault.yaml (default "agentvault.yaml" in cwd)
	Name         string // logical name of the single secret to read
}

// exitReadRefused is the distinct exit code returned when av read is asked to
// print a secret to a non-terminal (a pipe/file). It is intentionally outside
// the 0/1/2/69/77 range so the agent can branch on "refused" specifically.
const exitReadRefused = 80

// Read resolves a single logical Name from opts.Profile through the daemon and
// prints its value to out — BUT ONLY IF outIsTTY is true.
//
// SECURITY (the deliberate guard from the design): if outIsTTY is false, Read
// REFUSES — it writes NOTHING of the value to out and returns exitReadRefused
// with a clear, secret-free message. An agent reading a secret through a pipe
// gets nothing; it must use av run to inject the value instead. Passing outIsTTY
// as a parameter (rather than probing os.Stdout here) keeps the refusal branch
// fully unit-testable without a real terminal.
//
// av stays thin: it sends the raw agentvault.yaml bytes to avd, which parses and
// resolves (Resolve already enforces unlock/dangerous/audit). On a daemon error
// (locked/denied) Read returns the *ipc.RPCError so cmd/av maps its Code.
func Read(cl *Client, opts ReadOptions, out io.Writer, outIsTTY bool) (exitCode int, err error) {
	manifestPath := opts.ManifestPath
	if manifestPath == "" {
		manifestPath = defaultManifestPath
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		// No secret in this path — only the path/OS error.
		return -1, fmt.Errorf("av read: read manifest %s: %w", manifestPath, err)
	}

	// Resolve over the socket. avd parses the manifest and resolves the backends;
	// av stays thin. On a daemon error this is a *ipc.RPCError (caller inspects Code).
	vals, err := cl.Resolve(opts.Profile, manifestBytes)
	if err != nil {
		return -1, err
	}

	val, ok := vals[opts.Name]
	if !ok {
		// Absent name yields NO value (not even a hint of one).
		return exitBadRequestRead, fmt.Errorf("no such secret %q in profile %q", opts.Name, opts.Profile)
	}

	// SECURITY GUARD: refuse to emit a secret to a non-terminal. Nothing of the
	// value reaches out on this branch.
	if !outIsTTY {
		// Best-effort zeroize the reference now that we are refusing.
		clear(vals)
		return exitReadRefused, fmt.Errorf("av read refuses to print a secret to a non-terminal; use av run to inject it")
	}

	// TTY path: the value is for a human at a terminal.
	_, werr := fmt.Fprintln(out, val)
	clear(vals) // best-effort: drop the reference for GC
	if werr != nil {
		return -1, fmt.Errorf("av read: write value: %w", werr)
	}
	return 0, nil
}

// exitBadRequestRead is the exit code for a missing name (usage/bad-request).
// Kept separate from the ipc Code constants; cmd/av maps this to exitBadRequest.
const exitBadRequestRead = 2
