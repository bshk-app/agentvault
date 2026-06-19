// Command av is the thin AgentVault CLI.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/beshkenadze/agentvault/internal/adapter"
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

// version is av's build version, overridden at build time via
// `-ldflags "-X main.version=<tag>"` (see the Makefile / release Formula). It defaults
// to "dev" for plain `go build`. `av version` prints it and compares it to avd's so a
// stale daemon (different version) is loudly flagged.
var version = "dev"

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
	case "add":
		runAdd(os.Args[2:])
	case "rm":
		runRm(os.Args[2:])
	case "init":
		runInit(os.Args[2:])
	case "setup":
		runSetup(os.Args[2:])
	case "version":
		runVersion()
	default:
		usage()
		os.Exit(exitBadRequest)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:\n  av ping\n  av run [--profile P] -- cmd args...\n  av read [--profile P] NAME  (prints a secret to a TTY only; refuses a pipe)\n  av add [--backend file] NAME  (value from stdin or a TTY prompt; NEVER an argument)\n  av rm  [--backend file] NAME\n  av setup [--rotate] [--keychain|--enclave|--require-enclave|--plaintext]  (provision the local age vault; auto-picks the best tier)\n  av init --agent claude-code|generic [--dir D] [--force]  (generate adapter files)\n  av unlock\n  av lock\n  av status\n  av scrub  (filters stdin -> stdout)\n  av version  (prints av/avd versions + active key tier)")
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
	code, err := client.Run(client.New(path).WithNoPrompt(noPrompt()), client.RunOptions{
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

	code, err := client.Read(client.New(path).WithNoPrompt(noPrompt()), client.ReadOptions{
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

// runVersion prints av's build version and, when the daemon is reachable, avd's version,
// the active key tier, and the socket path. It NEVER hard-fails on an unreachable daemon:
// version must work without a running avd (an agent debugging a broken setup), so it prints
// "avd  (not running)" + the socket path and returns 0. When reachable, an av/avd version
// mismatch is loudly flagged (suggest a service restart). av stays thin: this is pure ipc —
// no age/enclave/provision import, only the metadata VersionResult crosses the wire.
func runVersion() {
	socket, err := transport.DefaultSocketPath()
	if err != nil {
		// Even the socket path is unknown: print just the av line (still no hard-fail).
		out, _ := formatVersion(version, nil, "")
		fmt.Print(out)
		fmt.Fprintln(os.Stderr, "av:", err)
		return
	}
	// A daemon error (not running / unreachable) is NOT fatal: res stays nil and
	// formatVersion prints the "not running" note. Only the av line is guaranteed.
	res, err := client.New(socket).Version()
	if err != nil {
		out, _ := formatVersion(version, nil, socket)
		fmt.Print(out)
		return
	}
	out, _ := formatVersion(version, &res, socket)
	fmt.Print(out)
}

// formatVersion renders the `av version` block and reports whether av and avd disagree.
// It is a PURE helper (no IO, no daemon) so the formatting and mismatch logic are unit-
// testable without a daemon: res==nil means avd is unreachable (print "not running"),
// otherwise it prints avd's version + tier + Enclave note. A version mismatch appends a
// LOUD warning suggesting `brew services restart agentvault` and returns mismatch=true.
// SECURITY: every field here is metadata (versions/tier/socket) — never a secret.
func formatVersion(avVer string, res *ipc.VersionResult, socket string) (out string, mismatch bool) {
	var b strings.Builder
	fmt.Fprintf(&b, "av     %s\n", avVer)
	if res == nil {
		fmt.Fprintln(&b, "avd    (not running)")
		fmt.Fprintf(&b, "socket %s\n", socket)
		return b.String(), false
	}
	fmt.Fprintf(&b, "avd    %s\n", res.Version)
	mismatch = avVer != res.Version
	// key line: the active tier, plus a note when the Secure Enclave is NOT the protection
	// (so the user knows this is the build-from-source keychain/plaintext tier, not Enclave).
	if res.EnclaveAvailable {
		fmt.Fprintf(&b, "key    %s\n", res.Tier)
	} else {
		fmt.Fprintf(&b, "key    %s  (Enclave unavailable — unsigned build)\n", res.Tier)
	}
	fmt.Fprintf(&b, "socket %s\n", socket)
	if mismatch {
		fmt.Fprintf(&b, "\nWARNING: av (%s) and avd (%s) versions differ — restart the daemon:\n  brew services restart agentvault\n", avVer, res.Version)
	}
	return b.String(), mismatch
}

// dialClient resolves the default socket path and returns a client bound to it (carrying
// the AV_NO_PROMPT opt-out so add/rm gate cleanly for agents), exiting with a clear
// message on a path error. Shared by add/rm/unlock/lock/status; only the Resolve/Add/
// Remove RPCs read NoPrompt, so setting it on every dialClient client is harmless.
func dialClient() *client.Client {
	path, err := transport.DefaultSocketPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		os.Exit(exitGeneric)
	}
	return client.New(path).WithNoPrompt(noPrompt())
}

// noPrompt reports the AV_NO_PROMPT agent opt-out: any non-empty value is truthy (agents
// set AV_NO_PROMPT=1 — see the generated adapter). When set, a locked daemon session is
// NOT opened with Touch ID on demand; resolve/add/rm return CodeLocked (exit 69) so the
// agent pauses for a human to unlock instead of blocking on a biometric prompt.
func noPrompt() bool { return os.Getenv("AV_NO_PROMPT") != "" }

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

// initOptions are the parsed args of `av init`.
type initOptions struct {
	agent string // which agent's adapter to generate (e.g. "claude-code", "generic")
	dir   string // target project dir (cwd by default)
	force bool   // overwrite existing files instead of refusing
}

// runInit implements `av init --agent X [--dir D] [--force]`. It GENERATES the named
// agent's adapter files (hook script + skill/doc + hooks snippet) into the target dir.
// av stays thin: the templates live in internal/adapter as static strings — no backend,
// age, or gitleaks dependency. An unknown agent / write conflict maps to exit 2.
func runInit(args []string) {
	opt, err := parseInitArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		usage()
		os.Exit(exitBadRequest)
	}
	if err := doInit(opt); err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		os.Exit(exitBadRequest)
	}
}

// doInit resolves the agent's files and writes them under opt.dir, honoring the
// no-clobber rule unless opt.force is set. It prints the files it created (paths only —
// no secret is ever involved here).
func doInit(opt initOptions) error {
	files, err := adapter.Files(opt.agent)
	if err != nil {
		return err
	}
	if err := adapter.Write(opt.dir, files, opt.force); err != nil {
		return err
	}
	for _, f := range files {
		fmt.Printf("wrote %s\n", f.Path)
	}
	return nil
}

// parseInitArgs extracts --agent (required), --dir (default "."), and --force from
// `av init` args. --agent and --dir accept both `--flag value` and `--flag=value`.
func parseInitArgs(args []string) (initOptions, error) {
	opt := initOptions{dir: "."}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--agent":
			if i+1 >= len(args) {
				return opt, fmt.Errorf("--agent needs a value")
			}
			opt.agent = args[i+1]
			i++
		case strings.HasPrefix(a, "--agent="):
			opt.agent = strings.TrimPrefix(a, "--agent=")
		case a == "--dir":
			if i+1 >= len(args) {
				return opt, fmt.Errorf("--dir needs a value")
			}
			opt.dir = args[i+1]
			i++
		case strings.HasPrefix(a, "--dir="):
			opt.dir = strings.TrimPrefix(a, "--dir=")
		case a == "--force":
			opt.force = true
		default:
			return opt, fmt.Errorf("unexpected argument %q", a)
		}
	}
	if opt.agent == "" {
		return opt, fmt.Errorf("av init needs --agent (one of: %s)", strings.Join(adapter.KnownAgents(), ", "))
	}
	return opt, nil
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

// runAdd implements `av add [--backend file] NAME`. It reads the VALUE from stdin (if
// piped) or a TTY prompt with echo OFF — NEVER from argv — and sends it to the daemon,
// which writes it atomically into the writable backend's vault. The value never lands
// in shell history / ps because it is never a command-line argument.
//
// SECURITY: the only secret is the value, which travels client.Add -> AddParams over
// the 0600 peer-cred socket. parseAddArgs refuses any second positional so a value
// passed as an argument is rejected (it would otherwise leak to history/argv).
func runAdd(args []string) {
	backend := "file" // the agefile vault is the only writable backend
	name, err := parseAddArgs(args, &backend)
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		usage()
		os.Exit(exitBadRequest)
	}
	value, err := readSecretValue(os.Stdin, stdinIsTTY())
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		os.Exit(exitBadRequest)
	}
	if err := dialClient().Add(backend, name, value); err != nil {
		os.Exit(exitForError(err))
	}
	fmt.Printf("added %s\n", name)
}

// runSetup implements `av setup [--rotate] [--keychain|--enclave|--require-enclave|--plaintext]`.
// It is a PURE RPC: it asks the daemon (which links age+enclave) to provision the local
// age store and prints the resulting PATHS only — never a secret. With no tier flag the
// daemon auto-picks the strongest available (Enclave→keychain). --rotate forces a fresh
// identity/vault. av stays thin: no age/enclave/provision import lives here.
func runSetup(args []string) {
	p, err := parseSetupArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		usage()
		os.Exit(exitBadRequest)
	}
	res, err := dialClient().Setup(p)
	if err != nil {
		os.Exit(exitForError(err))
	}
	if res.Created {
		fmt.Printf("created vault %s\n  identity %s\n", res.VaultPath, res.IdentityPath)
		return
	}
	fmt.Printf("already provisioned: %s\n", res.VaultPath)
}

// parseSetupArgs extracts the `av setup` flags (no values; only the `--flag` form).
// Tier selection: with no tier flag the daemon auto-picks the best available
// (Enclave→keychain, never plaintext). --keychain / --enclave force a tier;
// --require-enclave forces Enclave and ERRORS instead of downgrading; --plaintext is
// the explicit weakest opt-out. Conflicting tier flags are a usage error. av stays thin:
// this only sets RPC params — the daemon owns the crypto and the selection logic.
func parseSetupArgs(args []string) (ipc.SetupParams, error) {
	var p ipc.SetupParams
	for _, a := range args {
		switch a {
		case "--rotate":
			p.Rotate = true
		case "--plaintext":
			p.Plaintext = true
		case "--keychain", "--enclave":
			if p.Tier != "" {
				return p, fmt.Errorf("conflicting tier flags: --%s with %s", p.Tier, a)
			}
			p.Tier = a[2:] // "keychain" / "enclave"
		case "--require-enclave":
			if p.Tier != "" {
				return p, fmt.Errorf("conflicting tier flags: --%s with %s", p.Tier, a)
			}
			p.Tier = "enclave"
			p.RequireEnclave = true
		default:
			return p, fmt.Errorf("unexpected argument %q", a)
		}
	}
	// A tier flag and --plaintext are mutually exclusive: refuse rather than silently
	// letting one win, so the user's intent is never guessed.
	if p.Plaintext && p.Tier != "" {
		return p, fmt.Errorf("conflicting tier flags: --plaintext with --%s", p.Tier)
	}
	return p, nil
}

// runRm implements `av rm [--backend file] NAME`: it deletes NAME from the writable
// backend's vault via the daemon. A missing name maps to exit 2 (CodeBadRequest).
func runRm(args []string) {
	backend := "file"
	name, err := parseRmArgs(args, &backend)
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		usage()
		os.Exit(exitBadRequest)
	}
	if err := dialClient().Remove(backend, name); err != nil {
		os.Exit(exitForError(err))
	}
	fmt.Printf("removed %s\n", name)
}

// readSecretValue reads the secret value to store. When stdin is piped (not a TTY) it
// reads the whole stream and strips a single trailing newline (a here-string / echo
// adds one) while preserving interior newlines (a multi-line secret). When stdin IS a
// TTY it prompts and reads with echo OFF via term.ReadPassword, so the value never
// appears on screen. An empty value is refused (almost certainly a mistake).
//
// SECURITY: the value is read ONLY from stdin/TTY — never from argv — so it cannot leak
// via shell history or the process table. It is returned to the caller and never logged.
func readSecretValue(stdin io.Reader, stdinIsTTY bool) ([]byte, error) {
	if stdinIsTTY {
		fmt.Fprint(os.Stderr, "Value (input hidden): ")
		v, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr) // ReadPassword swallows the Enter; restore the newline
		if err != nil {
			return nil, fmt.Errorf("read value: %w", err)
		}
		if len(v) == 0 {
			return nil, fmt.Errorf("empty value refused")
		}
		return v, nil
	}
	v, err := io.ReadAll(stdin)
	if err != nil {
		return nil, fmt.Errorf("read value from stdin: %w", err)
	}
	v = []byte(strings.TrimSuffix(string(v), "\n"))
	if len(v) == 0 {
		return nil, fmt.Errorf("empty value refused (pipe a non-empty value)")
	}
	return v, nil
}

// stdinIsTTY reports whether os.Stdin is a terminal, using the stdlib mode bit (the
// same approach as stdoutIsTTY) — no extra dependency beyond what term already brings.
// A pipe or a redirected file is NOT a character device, so this returns false for them.
func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false // on doubt, treat as non-TTY (read from the pipe)
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// parseAddArgs extracts --backend and the single positional NAME from
// `av add [--backend B] NAME`. Exactly ONE positional is allowed: a second positional
// is REFUSED because it would be a value on the command line (leaking to history/argv).
func parseAddArgs(args []string, backend *string) (string, error) {
	return parseNameArgs("av add", args, backend)
}

// parseRmArgs mirrors parseAddArgs for `av rm [--backend B] NAME`.
func parseRmArgs(args []string, backend *string) (string, error) {
	return parseNameArgs("av rm", args, backend)
}

// parseNameArgs is the shared --backend + single-NAME parser for add/rm. It refuses a
// second positional so a secret value can never be passed as an argument.
func parseNameArgs(cmd string, args []string, backend *string) (string, error) {
	var name string
	have := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--backend":
			if i+1 >= len(args) {
				return "", fmt.Errorf("--backend needs a value")
			}
			*backend = args[i+1]
			i++
		case len(a) > 10 && a[:10] == "--backend=":
			*backend = a[10:]
		default:
			if have {
				return "", fmt.Errorf("%s takes exactly one NAME; the value is read from stdin or a TTY prompt, never as an argument", cmd)
			}
			name = a
			have = true
		}
	}
	if !have {
		return "", fmt.Errorf("%s needs a NAME (use: %s [--backend file] NAME)", cmd, cmd)
	}
	return name, nil
}
