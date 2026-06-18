// Command av is the thin AgentVault CLI.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/beshkenadze/agentvault/internal/client"
	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/transport"
)

// Exit codes the agent (or any caller) can branch on. They are documented here so
// the Phase 6 adapter can react without parsing stderr. SECURITY: every message
// printed alongside these codes is secret-free.
//
//	0    success (av run also propagates the child's own exit code)
//	1    generic failure (setup/IO/unexpected daemon error)
//	2    bad request — usage error or CodeBadRequest (e.g. profile not found)
//	69   vault locked (CodeLocked) — a human must unlock; cf. EX_UNAVAILABLE
//	77   access denied (CodeDenied, dangerous-tier) — cf. EX_NOPERM
const (
	exitGeneric    = 1
	exitBadRequest = 2
	exitLocked     = 69
	exitDenied     = 77
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitBadRequest)
	}
	switch os.Args[1] {
	case "ping":
		runPing()
	case "run":
		runRun(os.Args[2:])
	case "scrub":
		runScrub()
	default:
		usage()
		os.Exit(exitBadRequest)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:\n  av ping\n  av run [--profile P] -- cmd args...\n  av scrub  (filters stdin -> stdout)")
}

func runPing() {
	path, err := transport.DefaultSocketPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		os.Exit(1)
	}
	out, err := client.New(path).Ping()
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		os.Exit(1)
	}
	fmt.Println(out)
}

// runRun parses `av run [--profile P] [--] cmd args...` and executes the child
// with resolved secrets injected and its output masked at the source (layer 1). On
// a daemon error it maps the *ipc.RPCError Code to a distinct, secret-free exit code
// (see the exit-code constants) so the agent can branch without parsing stderr.
func runRun(args []string) {
	profile := "smoke" // default profile; override with --profile
	cmdArgs, err := parseRunArgs(args, &profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		usage()
		os.Exit(exitBadRequest)
	}

	path, err := transport.DefaultSocketPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		os.Exit(exitGeneric)
	}
	code, err := client.Run(client.New(path), client.RunOptions{
		Profile: profile,
		Command: cmdArgs,
	}, os.Stdout, os.Stderr)
	if err != nil {
		os.Exit(exitForError(err))
	}
	os.Exit(code)
}

// exitForError maps a client error to an exit code, printing a clear, secret-free
// message to stderr. A *ipc.RPCError (from resolve) is mapped by its stable Code;
// anything else is a generic failure.
func exitForError(err error) int {
	var rpc *ipc.RPCError
	if errors.As(err, &rpc) {
		switch rpc.Code {
		case ipc.CodeLocked:
			fmt.Fprintln(os.Stderr, "av: vault locked — ask a human to unlock")
			return exitLocked
		case ipc.CodeDenied:
			fmt.Fprintln(os.Stderr, "av: access denied (dangerous-tier)")
			return exitDenied
		case ipc.CodeBadRequest:
			// rpc.Message carries names/refs only (the daemon never wraps values).
			fmt.Fprintln(os.Stderr, "av:", rpc.Message)
			return exitBadRequest
		}
	}
	fmt.Fprintln(os.Stderr, "av:", err)
	return exitGeneric
}

// runScrub streams stdin through the daemon's layer-2 redactor (session values +
// gitleaks) and writes the masked result to stdout. av stays thin: all masking is
// daemon-side.
func runScrub() {
	path, err := transport.DefaultSocketPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		os.Exit(exitGeneric)
	}
	if err := client.New(path).Scrub(os.Stdin, os.Stdout); err != nil {
		os.Exit(exitForError(err))
	}
}

// parseRunArgs extracts --profile and the child argv (everything after `--`, or
// the first non-flag token onward). It sets *profile and returns the child argv.
func parseRunArgs(args []string, profile *string) ([]string, error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return args[i+1:], nil
		case a == "--profile":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--profile needs a value")
			}
			*profile = args[i+1]
			i++
		case len(a) > 10 && a[:10] == "--profile=":
			*profile = a[10:]
		default:
			// First non-flag token begins the child argv.
			return args[i:], nil
		}
	}
	return nil, fmt.Errorf("no command given")
}
