package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/beshkenadze/agentvault/internal/config"
	"github.com/beshkenadze/agentvault/internal/ipc"
)

// This file is `av sops` — the human half of the SOPS surface. Every decision that needs to
// understand a key is made in avd (internal/daemon/sops_manage.go); what lives here is
// argument parsing, terminal confirmation, and moving opaque strings between the daemon and
// the user's keys.txt.
//
// av must link neither filippo.io/age nor internal/sopsplugin (TestAvStaysThin), which is
// why the RPC replies carry a ready-made AGE-PLUGIN-AV-1… pointer: this file WRITES that
// string and never computes or parses one. The same rule is why no tier list, no name rule
// and no key format appears below — those are the daemon's, checked before it opens the
// session, so a typo here costs a round trip and never a presence check.

// runSops dispatches `av sops <subcommand>`. An unknown or missing subcommand is a usage
// error (exit 2), matching the top-level switch in main.
func runSops(args []string) {
	if len(args) == 0 {
		sopsUsage()
		os.Exit(exitBadRequest)
	}
	switch args[0] {
	case "keygen":
		runSopsKeygen(args[1:])
	case "ls":
		runSopsLs(args[1:])
	case "recipient":
		runSopsShow(args[1:], sopsFieldRecipient)
	case "identity":
		runSopsShow(args[1:], sopsFieldIdentity)
	case "rm":
		runSopsRm(args[1:])
	case "import":
		runSopsImport(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "av: unknown sops command %q\n", args[0])
		sopsUsage()
		os.Exit(exitBadRequest)
	}
}

func sopsUsage() {
	fmt.Fprintln(os.Stderr, "usage:\n  av sops keygen NAME [--tier normal|dangerous]  (generate a SOPS identity inside the vault)\n  av sops import [--from PATH] [--name NAME]     (move existing age keys out of keys.txt into the vault)\n  av sops ls\n  av sops recipient NAME  (the age1… to encrypt to — put it in .sops.yaml)\n  av sops identity NAME   (the AGE-PLUGIN-AV-1… pointer — put it in keys.txt)\n  av sops rm NAME [--force]")
}

// sopsKeygenOptions are the parsed args of `av sops keygen`.
type sopsKeygenOptions struct {
	name string
	tier string // "" means the daemon's documented default (normal), or the stored tier on a replace
}

// parseSopsKeygenArgs extracts the single positional NAME and --tier from
// `av sops keygen NAME [--tier T]`. A SECOND positional is refused for the reason
// parseAddArgs refuses one: `av sops keygen NAME AGE-SECRET-KEY-1…` would be a private key
// on argv, and importing an existing key is `av sops import`, which reads it from a file.
//
// A flag-looking argument is refused rather than swallowed as a NAME, exactly as
// parseSopsNameArg and parseSopsRmArgs refuse one — and here it is the load-bearing guard of
// the three. Without it `av sops keygen --dry-run` GENERATES a key stored under the name
// "--dry-run" (the daemon's ValidateName has no opinion about a leading dash), and every
// command that could reach it back — rm, recipient, identity — parses that name as a flag.
//
// The tier is NOT validated here — see the file header.
func parseSopsKeygenArgs(args []string) (sopsKeygenOptions, error) {
	var o sopsKeygenOptions
	have := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--tier":
			if i+1 >= len(args) {
				return o, fmt.Errorf("--tier needs a value")
			}
			o.tier = args[i+1]
			i++
		case strings.HasPrefix(a, "--tier="):
			o.tier = strings.TrimPrefix(a, "--tier=")
		case strings.HasPrefix(a, "-"):
			return o, fmt.Errorf("av sops keygen: unexpected flag %q", a)
		default:
			if have {
				return o, fmt.Errorf("av sops keygen takes exactly one NAME; an existing key is imported from a file with `av sops import`, never as an argument")
			}
			o.name = a
			have = true
		}
	}
	if !have {
		return o, fmt.Errorf("av sops keygen needs a NAME (use: av sops keygen NAME [--tier normal|dangerous])")
	}
	return o, nil
}

// runSopsKeygen implements `av sops keygen NAME [--tier T]`: the daemon generates the key,
// stores it, and returns its public half. This is the recommended way to make a SOPS
// identity — on this path the private key never exists outside avd at all.
//
// It lists first so a name that is already taken is announced as the destruction it is
// (see confirmSopsReplace); the daemon replaces without asking anything a human can read.
//
// It ends with warnSopsEnvShadow for the same reason `av sops import` does, and the case is
// if anything stronger here: the summary it just printed tells the user to append the pointer
// to keys.txt, and with SOPS_AGE_KEY set that instruction changes nothing — sops keeps
// decrypting with the key in the environment, the plugin is never exercised, and this command
// reported success. That silent success on the path this command RECOMMENDS is the exact
// failure the whole feature exists to prevent.
func runSopsKeygen(args []string) {
	o, err := parseSopsKeygenArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		sopsUsage()
		os.Exit(exitBadRequest)
	}
	warnOldSops()

	c := dialClient()
	verb := sopsWriteVerb(sopsCheckReplace(c, []string{o.name}, stdinIsTTY(), os.Stdin, os.Stderr))
	info, err := c.SopsKeygen(o.name, o.tier)
	if err != nil {
		os.Exit(exitForError(err))
	}
	fmt.Print(formatSopsCreated(verb, info, config.SopsKeysFilePath()))
	warnSopsEnvShadow()
}

// runSopsLs implements `av sops ls`: every stored identity, sorted by name (the daemon
// sorts, so repeated runs over an unchanged vault do not reshuffle).
func runSopsLs(args []string) {
	if len(args) > 0 {
		// The stray argument is NOT echoed: a mistyped `av sops ls AGE-SECRET-KEY-1…` would
		// otherwise put a private key in stderr and in whatever captured it.
		fmt.Fprintln(os.Stderr, "av: av sops ls takes no arguments")
		os.Exit(exitBadRequest)
	}
	ids, err := dialClient().SopsList()
	if err != nil {
		os.Exit(exitForError(err))
	}
	fmt.Print(formatSopsList(ids))
}

// formatSopsList renders the listing: name, tier, recipient, aligned on the longest name.
// The AGE-PLUGIN-AV-1… pointer is deliberately NOT a column — it is long enough to wrap
// every row, and the one place it is needed (keys.txt) is served by `av sops identity NAME`,
// whose output is exactly the line that file wants.
//
// SECURITY: every field comes from ipc.SopsIdentityInfo, which has no field that can hold a
// private key — so this output, which lands in terminals, CI logs and screenshots, cannot
// contain one.
func formatSopsList(ids []ipc.SopsIdentityInfo) string {
	if len(ids) == 0 {
		return "no SOPS identities yet — create one with: av sops keygen NAME\n"
	}
	width := len("NAME")
	for _, id := range ids {
		if len(id.Name) > width {
			width = len(id.Name)
		}
	}
	var b strings.Builder
	// The tier column is sized for the longest tier there is ("dangerous"), which is a
	// closed set in sopsplugin — a wider one would have to be added there first.
	fmt.Fprintf(&b, "%-*s  %-9s  %s\n", width, "NAME", "TIER", "RECIPIENT")
	for _, id := range ids {
		fmt.Fprintf(&b, "%-*s  %-9s  %s\n", width, id.Name, id.Tier, id.Recipient)
	}
	return b.String()
}

// sopsRmOptions are the parsed args of `av sops rm`.
type sopsRmOptions struct {
	name  string
	force bool
}

// parseSopsRmArgs extracts NAME and the optional --force from
// `av sops rm [--force] [--] NAME`.
//
// `--` ends the flags, and rm is the ONLY sops subcommand that takes it. That is not
// symmetry for its own sake: `av sops import --name -x` still stores an identity whose name
// begins with a dash (--name takes whatever value it is given, by definition), and `av rm
// sops/-x` is refused by the reserved-namespace guard, so without an escape here such an
// entry would be listed forever and removable by nothing. rm already carries that role for
// the other unreachable entry — the one too corrupt for `av sops ls` to decode — so the way
// out lives where the way out already lives.
func parseSopsRmArgs(args []string) (sopsRmOptions, error) {
	var o sopsRmOptions
	have, literal := false, false
	for _, a := range args {
		if !literal {
			switch {
			case a == "--":
				literal = true
				continue
			case a == "--force":
				o.force = true
				continue
			case strings.HasPrefix(a, "-"):
				return o, fmt.Errorf("av sops rm: unexpected flag %q (for a NAME that starts with a dash, use: av sops rm -- NAME)", a)
			}
		}
		if have {
			return o, fmt.Errorf("av sops rm takes exactly one NAME")
		}
		o.name = a
		have = true
	}
	if !have {
		return o, fmt.Errorf("av sops rm needs a NAME (use: av sops rm NAME [--force])")
	}
	return o, nil
}

// runSopsRm implements `av sops rm NAME [--force]` — the one command here that destroys
// something. Deleting a SOPS identity makes every file ever encrypted to it permanently
// unreadable, and the vault holds the only copy, so it is guarded twice over:
//
//   - HERE, by a typed confirmation at a terminal (or an explicit --force). This is the only
//     guard that can explain the consequence, because a socket has no terminal to explain it at.
//   - In the DAEMON, by a fresh presence check when the stored tier is dangerous
//     (sopsTierGate) — a biometric an agent cannot fake, which --force does not bypass.
//
// It lists first so the prompt can name the tier and recipient about to be lost, but a
// FAILED listing must not block the delete: Store.List is strict, so one entry that will not
// decode breaks it wholesale, and `av sops rm` is deliberately the only way to clear such an
// entry (internal/daemon/sops_manage.go). On that path the prompt falls back to the name.
func runSopsRm(args []string) {
	o, err := parseSopsRmArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		sopsUsage()
		os.Exit(exitBadRequest)
	}
	c := dialClient()
	id, known := ipc.SopsIdentityInfo{}, false
	ids, listErr := c.SopsList()
	if listErr != nil {
		fmt.Fprintln(os.Stderr, "av: note: could not list the stored identities, so this cannot show what it is deleting:", listErr)
	} else if id, known = findSopsIdentity(ids, o.name); !known {
		// A successful listing is COMPLETE (List refuses to skip an entry it cannot
		// decode), so a name missing from it is genuinely absent — worth reporting before
		// asking anyone to confirm the deletion of nothing.
		fmt.Fprintln(os.Stderr, "av:", sopsNoSuchIdentity("rm", o.name))
		os.Exit(exitBadRequest)
	}
	if err := confirmSopsRemove(sopsRemoveTarget(o.name, id, known), stdinIsTTY(), o.force, os.Stdin, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		os.Exit(exitBadRequest)
	}
	if err := c.SopsRemove(o.name); err != nil {
		os.Exit(exitForError(err))
	}
	fmt.Printf("removed SOPS identity %q\n", o.name)
}

// sopsRemoveTarget describes what is about to be deleted: tier and recipient when the
// listing knew the identity, the bare name when it did not.
func sopsRemoveTarget(name string, id ipc.SopsIdentityInfo, known bool) string {
	if !known {
		return strconv.Quote(name)
	}
	return fmt.Sprintf("%s (tier %s, %s)", strconv.Quote(id.Name), id.Tier, id.Recipient)
}

// confirmSopsRemove prints the consequence and makes a human agree to it.
//
// The warning is printed on EVERY path, --force included: a run that deleted a key should
// have said why it mattered in whatever log captured it. --force then returns without
// reading stdin at all — a script's stdin is its own data, not an answer to a question.
func confirmSopsRemove(target string, stdinTTY, force bool, in io.Reader, out io.Writer) error {
	fmt.Fprintf(out, "this DELETES %s from the vault — every file encrypted to it becomes permanently unreadable.\n", target)
	if force {
		return nil
	}
	if !stdinTTY {
		return fmt.Errorf("refusing to delete without a terminal to confirm at — re-run interactively, or pass --force if you are certain")
	}
	return sopsConfirm(in, out, "Delete it?")
}

// sopsShowField selects which half of a listed identity `av sops recipient` and
// `av sops identity` print. Its VALUE is the subcommand's own name, so the "no such
// identity" message below reads as the command the user typed without a second table
// mapping one to the other.
type sopsShowField string

const (
	sopsFieldRecipient sopsShowField = "recipient"
	sopsFieldIdentity  sopsShowField = "identity"
)

// runSopsShow implements `av sops recipient NAME` and `av sops identity NAME`. Neither has
// an RPC of its own: sops_list already returns both strings for every identity, so these are
// printers over that reply — which is why the "no such identity" case is decided here.
//
// stdout carries the value and NOTHING else (warnings go to stderr), because the documented
// use of `identity` is `av sops identity work >> keys.txt`: its stdout IS the file line.
func runSopsShow(args []string, field sopsShowField) {
	name, err := parseSopsNameArg("av sops "+string(field), args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		sopsUsage()
		os.Exit(exitBadRequest)
	}
	ids, err := dialClient().SopsList()
	if err != nil {
		os.Exit(exitForError(err))
	}
	id, ok := findSopsIdentity(ids, name)
	if !ok {
		fmt.Fprintln(os.Stderr, "av:", sopsNoSuchIdentity(string(field), name))
		os.Exit(exitBadRequest)
	}
	fmt.Println(sopsShowValue(field, id))
}

// sopsShowValue reads the requested field off a listed identity. Both are PUBLIC: the
// recipient is a public key, and the pointer carries that same recipient — without a running
// avd and a presence check it decrypts nothing, which is what makes it safe to commit.
func sopsShowValue(field sopsShowField, id ipc.SopsIdentityInfo) string {
	if field == sopsFieldIdentity {
		return id.Identity
	}
	return id.Recipient
}

// sopsNoSuchIdentity is the client-side "no such identity", and its wording is the daemon's
// by hand: internal/daemon/sops_manage.go answers the identical condition on `sops rm` with
// `sops %s %q: no such SOPS identity`. Nothing links the two but the test that pins this —
// the daemon's copy lives behind filippo.io/age, which av must not link (TestAvStaysThin).
//
// The exit code matches too: the daemon returns CodeBadRequest for this, which exitForError
// maps to exit 2, and the callers of this error exit 2 directly.
//
// op is the subcommand the user typed, exactly as the daemon interpolates its own op — the
// sopsShowField constants are spelled to be passed straight in.
func sopsNoSuchIdentity(op, name string) error {
	return fmt.Errorf("sops %s %q: no such SOPS identity", op, name)
}

// parseSopsNameArg extracts the single positional NAME for the sops subcommands that take
// nothing else. A flag-looking argument is refused rather than swallowed as a name, so a
// mistyped flag is reported instead of creating a lookup for "--tier".
func parseSopsNameArg(cmd string, args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("%s needs exactly one NAME (use: %s NAME)", cmd, cmd)
	}
	if strings.HasPrefix(args[0], "-") {
		return "", fmt.Errorf("%s: unexpected flag %q", cmd, args[0])
	}
	return args[0], nil
}

// sopsCheckReplace runs the SopsList-then-confirm dance shared by keygen and import, and
// reports whether any of names is already stored (so the caller can say "replaced" rather
// than "created"). It EXITS rather than returning an error when the user declines or when
// the listing itself fails.
//
// A failed listing is fatal on purpose. Without it there is no way to tell a create from a
// replace, and guessing "create" risks destroying a key silently — the one outcome this
// whole command guards against. The dead end that would leave (a corrupt entry breaks
// List for everything) has a documented exit, which the message names: `av sops rm` works
// on entries that will not decode, deliberately (internal/daemon/sops_manage.go).
//
// The terminal and its streams are PARAMETERS rather than os.Stdin/os.Stderr read here, so
// that the branch this function exists to decide can be exercised: a taken name plus a
// terminal is the only way it returns true, and a test has no terminal.
func sopsCheckReplace(c sopsLister, names []string, stdinTTY bool, in io.Reader, out io.Writer) bool {
	ids, err := c.SopsList()
	if err != nil {
		fmt.Fprintln(os.Stderr, "av: could not list the stored SOPS identities, so this cannot tell whether it would replace one — refusing rather than risk destroying a key.")
		fmt.Fprintln(os.Stderr, "av: an entry that will not decode is removable with `av sops rm NAME`.")
		os.Exit(exitForError(err))
	}
	if err := confirmSopsReplace(ids, names, stdinTTY, in, out); err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		os.Exit(exitBadRequest)
	}
	for _, n := range names {
		if _, ok := findSopsIdentity(ids, n); ok {
			return true
		}
	}
	return false
}

// sopsWriteVerb names what `av sops keygen` just did, for formatSopsCreated. The distinction
// is entirely sopsCheckReplace's — the daemon answers a create and a replace identically —
// so this is the one place the two words are chosen, and choosing them here rather than
// inline is what lets a test tie the word to the check that decided it.
func sopsWriteVerb(replacing bool) string {
	if replacing {
		return "replaced"
	}
	return "created"
}

// sopsLister is the SopsList half of *client.Client, so the replace check can be exercised
// without a daemon. It is the only RPC `av sops recipient`, `av sops identity` and the
// replace confirmation need: every listed identity already carries its recipient and its
// pointer, so none of the three has an RPC of its own.
type sopsLister interface {
	SopsList() ([]ipc.SopsIdentityInfo, error)
}

// findSopsIdentity returns the listed identity stored under name.
func findSopsIdentity(ids []ipc.SopsIdentityInfo, name string) (ipc.SopsIdentityInfo, bool) {
	for _, id := range ids {
		if id.Name == name {
			return id, true
		}
	}
	return ipc.SopsIdentityInfo{}, false
}

// confirmSopsReplace makes a human agree, at a terminal, before a stored identity is
// overwritten. It prints WHAT is about to be lost — name, tier, recipient — because the
// daemon's own replace path says nothing a user can read: it carries the stored tier
// forward and destroys the key.
//
// Without a terminal it refuses. keygen and import have no --force by design: the
// non-interactive route to the same end is an explicit `av sops rm NAME --force`, which a
// script has to name, so a key is never destroyed by a command that reads as "create".
func confirmSopsReplace(ids []ipc.SopsIdentityInfo, names []string, stdinTTY bool, in io.Reader, out io.Writer) error {
	var taken []ipc.SopsIdentityInfo
	for _, n := range names {
		if id, ok := findSopsIdentity(ids, n); ok {
			taken = append(taken, id)
		}
	}
	if len(taken) == 0 {
		return nil
	}
	fmt.Fprintln(out, "this REPLACES a stored SOPS identity — every file encrypted to the old key becomes permanently unreadable:")
	quoted := make([]string, 0, len(taken))
	for _, id := range taken {
		fmt.Fprintf(out, "  %s  (tier %s)  %s\n", id.Name, id.Tier, id.Recipient)
		quoted = append(quoted, strconv.Quote(id.Name))
	}
	if !stdinTTY {
		return fmt.Errorf("refusing to replace %s without a terminal to confirm at — re-run interactively, or delete it first with `av sops rm NAME --force`", strings.Join(quoted, ", "))
	}
	return sopsConfirm(in, out, "Replace it?")
}

// sopsConfirm asks prompt and proceeds only on an exact "yes". "y" is not enough and a bare
// newline is not enough: every caller is about to destroy a key that files depend on, and
// the answer should cost more than the Enter key someone was already holding down.
func sopsConfirm(in io.Reader, out io.Writer, prompt string) error {
	fmt.Fprintf(out, "%s Type 'yes' to continue: ", prompt)
	line, err := bufio.NewReader(in).ReadString('\n')
	// A read error is only reported when it produced nothing: a final line without a
	// trailing newline arrives as (line, io.EOF) and is a perfectly good "yes".
	if err != nil && line == "" {
		fmt.Fprintln(out)
		return fmt.Errorf("aborted (nothing to read from stdin)")
	}
	fmt.Fprintln(out)
	if strings.TrimSpace(line) != "yes" {
		return fmt.Errorf("aborted")
	}
	return nil
}

// formatSopsCreated renders what a human needs after keygen: the identity's public half,
// and the two placements that make sops actually use it — the recipient in .sops.yaml (what
// files get encrypted to) and the pointer in keys.txt (how sops finds its way back to avd).
// Neither is done automatically: .sops.yaml is the user's repo, and keys.txt may hold other
// identities that `av sops import` owns the rewriting of.
//
// SECURITY: everything printed comes from ipc.SopsIdentityInfo, which has no field that can
// hold a private key.
func formatSopsCreated(verb string, info ipc.SopsIdentityInfo, keysPath string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s SOPS identity %q (tier %s)\n", verb, info.Name, info.Tier)
	fmt.Fprintf(&b, "  recipient %s\n", info.Recipient)
	fmt.Fprintf(&b, "encrypt to it — add to .sops.yaml:\n")
	fmt.Fprintf(&b, "  creation_rules:\n    - age: %s\n", info.Recipient)
	// Quoted: the darwin keys.txt path contains a space ("Application Support"), and an
	// unquoted paste appends the pointer to a file sops never opens.
	fmt.Fprintf(&b, "decrypt with it — point sops at the vault:\n  av sops identity %s >> %q\n", info.Name, keysPath)
	return b.String()
}

// warnOldSops warns when the installed sops predates 3.10, where age plugin support landed.
// An older sops does not run age-plugin-av at all: it reads the AGE-PLUGIN-AV-1… pointer,
// fails to make sense of it, and reports a decryption failure that says nothing about the
// version. A clear warning now beats that error later.
//
// No sops on PATH is NOT an error and NOT a warning worth alarm: plenty of setups install it
// per-project or in CI only. It is stated once and the command continues. So is a version
// that will not parse — a fork or a distro build is not a reason to block anything.
func warnOldSops() {
	out, ok := sopsVersionOutput()
	if !ok {
		fmt.Fprintln(os.Stderr, "note: sops is not on PATH — install sops 3.10 or newer to use this identity.")
		return
	}
	if note := sopsVersionNote(out); note != "" {
		fmt.Fprintln(os.Stderr, note)
	}
}

// sopsVersionOutput runs `sops --version` and returns its output. --disable-version-check
// stops sops phoning home to GitHub for the latest release, which is both slow and a network
// call a user did not ask for; it landed in sops 3.8, so a failure retries without it rather
// than reporting the old sops we are trying to detect as "not installed".
func sopsVersionOutput() (string, bool) {
	if _, err := exec.LookPath("sops"); err != nil {
		return "", false
	}
	out, err := exec.Command("sops", "--version", "--disable-version-check").Output()
	if err != nil {
		out, err = exec.Command("sops", "--version").Output()
		if err != nil {
			return "", false
		}
	}
	return string(out), true
}

// sopsVersionNote returns the warning for a `sops --version` output, or "" when the version
// is new enough (or unrecognizable — see warnOldSops).
func sopsVersionNote(versionOutput string) string {
	major, minor, ok := parseSopsVersion(versionOutput)
	if !ok {
		return ""
	}
	if major > 3 || (major == 3 && minor >= 10) {
		return ""
	}
	return fmt.Sprintf("WARNING: sops %d.%d is too old for age plugins (need 3.10+) — it will fail to decrypt with an AgentVault identity.", major, minor)
}

// parseSopsVersion pulls the major and minor out of `sops --version` output, which reads
// "sops 3.9.0" (plus " (latest)" when the version check ran). It scans for the first
// dotted-numeric field rather than assuming a position, so a build banner or a leading
// "sops" spelled differently does not defeat it.
func parseSopsVersion(versionOutput string) (major, minor int, ok bool) {
	for _, f := range strings.Fields(versionOutput) {
		f = strings.TrimPrefix(f, "v")
		parts := strings.SplitN(f, ".", 3)
		if len(parts) < 2 {
			continue
		}
		maj, err1 := strconv.Atoi(parts[0])
		min, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			continue
		}
		return maj, min, true
	}
	return 0, 0, false
}
