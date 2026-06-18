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
//	80   av read refused (stdout is not a terminal — the secret would leak to a pipe)
const (
	exitGeneric     = 1
	exitBadRequest  = 2
	exitLocked      = 69
	exitDenied      = 77
	exitReadRefused = 80
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
	case "read":
		runRead(os.Args[2:])
	case "unlock":
		runUnlock()
	case "lock":
		runLock()
	case "status":
		runStatus()
	case "scrub":
		runScrub()
	default:
		usage()
		os.Exit(exitBadRequest)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:\n  av ping\n  av run [--profile P] -- cmd args...\n  av read [--profile P] NAME  (prints a secret to a TTY only; refuses a pipe)\n  av unlock\n  av lock\n  av status\n  av scrub  (filters stdin -> stdout)")
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

// runRead parses `av read [--profile P] NAME`, resolves the single logical name
// through the daemon, and prints its value — BUT ONLY to a terminal. If stdout is
// not a TTY (a pipe/file), client.Read refuses (writes nothing of the value) and
// returns exit 80, so an agent piping the output gets nothing (it must use av run).
//
// SECURITY: TTY status is computed here from the REAL os.Stdout via the stdlib
// os.ModeCharDevice (no new dependency); client.Read takes it as a parameter so
// the refusal branch is unit-testable without a terminal.
func runRead(args []string) {
	profile := "smoke" // default profile; override with --profile
	name, err := parseReadArgs(args, &profile)
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

	code, err := client.Read(client.New(path), client.ReadOptions{
		Profile: profile,
		Name:    name,
	}, os.Stdout, stdoutIsTTY())
	if err != nil {
		// A *ipc.RPCError (resolve: locked/denied/bad-request) maps via exitForError.
		// Otherwise client.Read already chose the exit code (refused=80, missing
		// name=2, IO=-1); print the secret-free message and use that code.
		var rpc *ipc.RPCError
		if errors.As(err, &rpc) {
			os.Exit(exitForError(err))
		}
		fmt.Fprintln(os.Stderr, "av:", err)
		if code <= 0 {
			code = exitGeneric
		}
		os.Exit(code)
	}
	os.Exit(code)
}

// stdoutIsTTY reports whether os.Stdout is a terminal (a character device) using
// the stdlib only (no golang.org/x/term dependency — av stays minimal). A pipe or
// a regular file is NOT a character device, so this returns false for them.
func stdoutIsTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false // on doubt, treat as non-TTY (the safe, refusing direction)
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// runUnlock issues the "unlock" RPC — the call that fires Touch ID in production —
// opening the session for the daemon's unlock TTL. On a locked/denied presence it
// maps the *ipc.RPCError Code to exit 69/77 via exitForError; on success it prints
// the remaining window from a follow-up status (secret-free).
func runUnlock() {
	cl := dialClient()
	if err := cl.Unlock(); err != nil {
		os.Exit(exitForError(err))
	}
	_, remaining, err := cl.Status()
	if err != nil {
		fmt.Println("unlocked")
		return
	}
	fmt.Printf("unlocked for %dm\n", remaining/60)
}

// runLock issues the "lock" RPC, re-locking the session and clearing issued values.
func runLock() {
	if err := dialClient().Lock(); err != nil {
		os.Exit(exitForError(err))
	}
	fmt.Println("locked")
}

// runStatus issues the "status" RPC and prints the lock state plus remaining
// seconds. It NEVER prints a value (status carries none).
func runStatus() {
	locked, remaining, err := dialClient().Status()
	if err != nil {
		os.Exit(exitForError(err))
	}
	if locked {
		fmt.Println("locked")
		return
	}
	fmt.Printf("unlocked, %ds remaining\n", remaining)
}

// dialClient resolves the default socket path and returns a client bound to it,
// exiting with a clear message on a path error (shared by unlock/lock/status).
func dialClient() *client.Client {
	path, err := transport.DefaultSocketPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		os.Exit(exitGeneric)
	}
	return client.New(path)
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

// parseReadArgs extracts --profile and the single positional NAME from
// `av read [--profile P] NAME`. Exactly one positional name is required.
func parseReadArgs(args []string, profile *string) (string, error) {
	var name string
	have := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--profile":
			if i+1 >= len(args) {
				return "", fmt.Errorf("--profile needs a value")
			}
			*profile = args[i+1]
			i++
		case len(a) > 10 && a[:10] == "--profile=":
			*profile = a[10:]
		default:
			if have {
				return "", fmt.Errorf("av read takes exactly one NAME")
			}
			name = a
			have = true
		}
	}
	if !have {
		return "", fmt.Errorf("av read needs a NAME (use: av read [--profile P] NAME)")
	}
	return name, nil
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
