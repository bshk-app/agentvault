package client

import (
	"fmt"
	"io"
	"os"

	"github.com/beshkenadze/agentvault/internal/manifest"
)

// ReadOptions configures a single `av read` invocation. It addresses the secret in
// one of two modes: DIRECT (Backend set) resolves av://<Backend>/<Name> straight
// through the resolver with no on-disk manifest — symmetric with av add/av rm, so a
// value added with `av add NAME` reads back with `av read NAME`; MANIFEST (Profile
// set) resolves Name through agentvault.yaml. Exactly one mode is used (Backend wins
// if both are set; cmd/av keeps them mutually exclusive).
type ReadOptions struct {
	Profile      string // MANIFEST mode: profile to resolve from the manifest
	ManifestPath string // MANIFEST mode: path to agentvault.yaml (default "agentvault.yaml" in cwd)
	Backend      string // DIRECT mode: backend id to read av://<Backend>/<Name> from (no manifest)
	Name         string // logical name of the single secret to read
}

// syntheticReadProfile is the in-memory profile name used for a DIRECT read; it never
// touches disk and is invisible to the user.
const syntheticReadProfile = "_read"

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
	var manifestBytes []byte
	profile := opts.Profile
	if opts.Backend != "" {
		// DIRECT mode: synthesize a one-entry manifest av://<backend>/<name> and
		// resolve it through the same daemon path as a real profile — no
		// agentvault.yaml required. This makes read symmetric with av add/av rm.
		profile = syntheticReadProfile
		ref := "av://" + opts.Backend + "/" + opts.Name
		manifestBytes, err = manifest.Synthetic(profile, opts.Name, ref, manifest.TierNormal)
		if err != nil {
			return -1, fmt.Errorf("av read: build request: %w", err)
		}
	} else {
		manifestPath := opts.ManifestPath
		if manifestPath == "" {
			manifestPath = defaultManifestPath
		}
		manifestBytes, err = os.ReadFile(manifestPath)
		if err != nil {
			// No secret in this path — only the path/OS error.
			return -1, fmt.Errorf("av read: read manifest %s: %w", manifestPath, err)
		}
	}

	// Resolve over the socket. avd parses the manifest and resolves the backends;
	// av stays thin. On a daemon error this is a *ipc.RPCError (caller inspects Code).
	vals, err := cl.Resolve(profile, manifestBytes)
	if err != nil {
		return -1, err
	}

	val, ok := vals[opts.Name]
	if !ok {
		// Absent name yields NO value (not even a hint of one).
		return exitBadRequestRead, fmt.Errorf("no such secret %q", opts.Name)
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
