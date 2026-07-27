package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/beshkenadze/agentvault/internal/config"
	"github.com/beshkenadze/agentvault/internal/ipc"
)

// `av sops import` moves an age private key off the disk and into the vault, leaving an
// AGE-PLUGIN-AV-1… pointer where the key was. It is the only place in cmd/av that handles
// key material besides `av add`, and it handles it the same way: the bytes are read from a
// file, ferried to the daemon over the 0600 peer-cred socket, and never logged, never
// echoed, never placed in an error. av does not parse them — that would mean linking
// filippo.io/age, which TestAvStaysThin forbids — so what is or is not a key is the
// daemon's call, and this side only recognizes a prefix.
//
// Two failure modes shape everything below, and both LOOK like success if handled wrongly:
//
//  1. Writing the pointer to the wrong file. SOPS_AGE_KEY_FILE is ADDITIVE — sops opens it
//     AND the user-config-dir file, as two independent readers — so a pointer written to
//     SopsKeysFilePath() while the key was read from SOPS_AGE_KEY_FILE leaves the plaintext
//     key on disk, still decrypting everything, with the plugin never once exercised. The
//     path the key came from is therefore carried through to the rewrite (see runSopsImport).
//  2. Rewriting after a partial store. Each key is one sops_put and there is no transaction,
//     so a file claiming every key moved when one did not would delete the only copy of that
//     key. Nothing is rewritten unless every put succeeded (see putSopsKeys).

// sopsDefaultImportName is the base name for imported identities when --name is not given.
//
// It is a CONSTANT and not something read out of the file, which is the whole point: names
// reach the audit log, and every line of a keys.txt is key material or sits next to some.
// sopsplugin.ValidateName would happily accept an AGE-SECRET-KEY-1… string as a name.
const sopsDefaultImportName = "imported"

// sopsBackupSuffix is appended to the source path for the pre-import copy. The backup still
// holds the PLAINTEXT KEY, which is why keeping one is offered rather than assumed and why
// the summary says so out loud.
const sopsBackupSuffix = ".bak"

// sopsImportOptions are the parsed args of `av sops import`.
type sopsImportOptions struct {
	from string // --from: the exact file to read AND rewrite ("" = search the candidates)
	name string // --name: the base name to store under ("" = sopsDefaultImportName)
}

// parseSopsImportArgs extracts --from and --name. There are no positionals: a bare argument
// here would most likely be a key or a path meant for --from, and guessing which is worse
// than asking.
func parseSopsImportArgs(args []string) (sopsImportOptions, error) {
	var o sopsImportOptions
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--from":
			if i+1 >= len(args) {
				return o, fmt.Errorf("--from needs a value")
			}
			o.from = args[i+1]
			i++
		case strings.HasPrefix(a, "--from="):
			o.from = strings.TrimPrefix(a, "--from=")
		case a == "--name":
			if i+1 >= len(args) {
				return o, fmt.Errorf("--name needs a value")
			}
			o.name = args[i+1]
			i++
		case strings.HasPrefix(a, "--name="):
			o.name = strings.TrimPrefix(a, "--name=")
		default:
			return o, fmt.Errorf("unexpected argument %q (use: av sops import [--from PATH] [--name NAME])", a)
		}
	}
	return o, nil
}

// runSopsImport implements `av sops import [--from PATH] [--name NAME]`.
//
// The order matters and is: find the file, read it, name what is in it, WARN, ask, store,
// and only then rewrite. Everything that can refuse happens before anything is touched, and
// the rewrite target is the file the keys were actually read from — never
// config.SopsKeysFilePath(), for the reason in this file's header.
func runSopsImport(args []string) {
	o, err := parseSopsImportArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		sopsUsage()
		os.Exit(exitBadRequest)
	}
	warnOldSops()

	candidates := config.SopsKeysFileCandidates()
	src, err := sopsSourceFile(o.from, candidates)
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		os.Exit(exitBadRequest)
	}
	if src == "" {
		fmt.Fprint(os.Stderr, sopsNothingFoundMessage(candidates, sopsAgeKeyEnvSet(), sopsAgeKeyCmdEnvSet(), config.SopsKeysFilePath()))
		os.Exit(exitBadRequest)
	}

	data, err := os.ReadFile(src)
	if err != nil {
		// SECURITY: the path is named, the content is not — a read that failed part way
		// still must not put file bytes in an error.
		fmt.Fprintf(os.Stderr, "av: read %s: %v\n", src, err)
		os.Exit(exitGeneric)
	}
	keys, existing := scanSopsKeysFile(data)
	source := sopsImportSource{path: src, data: data, existing: existing}
	if len(keys) == 0 {
		if len(existing) > 0 {
			fmt.Printf("%s holds %d %s and no age private key — nothing to import.\n", src, len(existing), plural(len(existing), "pointer", "pointers"))
			return
		}
		fmt.Fprintf(os.Stderr, "av: no age private key (AGE-SECRET-KEY-1…) in %s\n", src)
		os.Exit(exitBadRequest)
	}

	base := o.name
	if base == "" {
		base = sopsDefaultImportName
	}
	names := sopsImportNames(base, len(keys))
	// Reported BEFORE anything is touched, per the plan: the user sees which file is about
	// to be rewritten and under which names its keys will land.
	fmt.Printf("found %d age %s in %s\n  importing as: %s\n", len(keys), plural(len(keys), "key", "keys"), src, strings.Join(names, ", "))

	c := dialClient()
	sopsCheckReplace(c, names) // exits when a name is taken and the user declines

	keepBackup := askSopsBackup(os.Stdin, os.Stderr, stdinIsTTY(), source.path)

	stored, err := importSopsKeys(c, source, names, keys, keepBackup)
	switch {
	case errors.Is(err, errSopsRewrite):
		// Every key IS in the vault; only the file is in doubt. Say so, and name the way
		// back — this is recoverable, and a user who reads "failed" and re-imports from a
		// half-written file has a much worse day.
		fmt.Fprintln(os.Stderr, "av:", err)
		fmt.Fprintf(os.Stderr, "av: the keys ARE in the vault — rebuild the file with: av sops identity NAME >> %q\n", source.path)
		os.Exit(exitGeneric)
	case err != nil:
		reportSopsImportFailure(source.path, names, stored)
		os.Exit(exitForError(err))
	}
	fmt.Print(formatSopsImportDone(source.path, stored, keepBackup))
	warnSopsEnvShadow()
}

// sopsImportSource is the file being imported. Its path is BOTH where the keys were read
// from and where the pointers go back — one field, so there is no second path for the
// rewrite to be computed from and get wrong.
//
// That is not a stylistic preference. config.SopsKeysFilePath() is the obvious thing to
// write to and it is the bug: SOPS_AGE_KEY_FILE is additive, so a user whose key lives there
// would get a pointer in the config-dir file and keep the plaintext key in theirs — sops
// reads both, everything still decrypts with the old key, the plugin is never exercised, and
// the import reports success.
type sopsImportSource struct {
	path     string   // read from here, rewritten here
	data     []byte   // the original bytes, kept for the backup
	existing []string // plugin pointers already in the file, carried into the rewrite
}

// errSopsRewrite marks a failure to write the pointer file back, which is a different
// outcome from a failed store and needs a different thing said to the user: the keys are in
// the vault and only the file is wrong.
var errSopsRewrite = errors.New("could not rewrite the keys file")

// importSopsKeys stores every key and, ONLY if every one landed, rewrites the source file
// with the pointers. It returns what was stored either way.
//
// The all-or-nothing rule is the whole function. Each key is one sops_put with no
// transaction between them, so a rewrite after a partial store would replace the only copy
// of a key that never made it. The alternative — rewriting just the lines that stored, and
// leaving the rest as plaintext — produces a keys.txt holding one pointer and one bare key:
// valid to sops, unreadable to a human, and impossible for a later import to reason about.
// Untouched, the file is still exactly what sops was using before this ran.
func importSopsKeys(c sopsPutter, src sopsImportSource, names []string, keys [][]byte, keepBackup bool) ([]ipc.SopsIdentityInfo, error) {
	stored, err := putSopsKeys(c, names, keys)
	if err != nil {
		return stored, err
	}
	if err := writeSopsPointerFile(src.path, formatSopsPointerFile(stored, src.existing), src.data, keepBackup); err != nil {
		return stored, fmt.Errorf("%w: %v", errSopsRewrite, err)
	}
	return stored, nil
}

// sopsSourceFile picks the file to read the keys from — and therefore the file that will be
// rewritten. --from wins over every candidate and MUST exist: falling back to a candidate
// after a --from that is not there would import and rewrite a file the user did not name.
//
// With no --from it takes the first candidate that exists. config.SopsKeysFileCandidates is
// ordered by preference and already accounts for SOPS_AGE_KEY_FILE, which is exactly why the
// result is carried to the rewrite rather than recomputed as SopsKeysFilePath().
//
// Nothing anywhere returns ("", nil): the caller has far more to say about that than an
// error string can (sopsNothingFoundMessage).
func sopsSourceFile(from string, candidates []string) (string, error) {
	if from != "" {
		if _, err := os.Stat(from); err != nil {
			return "", fmt.Errorf("--from %q: %v", from, err)
		}
		return from, nil
	}
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}
	return "", nil
}

// scanSopsKeysFile splits a keys.txt into the private keys to import and the plugin pointers
// already in it. Comments and blank lines are dropped; the backup keeps them.
//
// The pointers are collected because the rewrite REPLACES the file, and a rewrite that wrote
// only the new pointers would drop the old ones — every file encrypted to those identities
// would stop decrypting, with the key still safe in the vault and nothing on disk pointing
// at it. Every AGE-PLUGIN- prefix is preserved, not just AgentVault's: another plugin's
// identity line breaks the same way.
//
// SECURITY: keys are returned to the caller and go straight to the daemon. Nothing here
// interprets them — the prefix match is a format marker, not a parse — so this function
// cannot report, log or wrap what it found.
func scanSopsKeysFile(data []byte) (keys [][]byte, pointers []string) {
	for _, raw := range strings.Split(string(data), "\n") {
		// TrimSpace also drops the \r of a CRLF file: a key read as "…\r" reaches the
		// daemon as something that is not a key, reported as if the user's key were bad.
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "AGE-SECRET-KEY-1"):
			keys = append(keys, []byte(line))
		case strings.HasPrefix(upper, "AGE-PLUGIN-"):
			pointers = append(pointers, line)
		}
	}
	return keys, pointers
}

// sopsImportNames builds the names the keys will be stored under: the base name alone for a
// single key, numbered suffixes for several. It takes a base and a COUNT and nothing else —
// there is no path from file content to a name, which is what keeps key material out of the
// audit log (see sopsDefaultImportName).
func sopsImportNames(base string, n int) []string {
	if n == 1 {
		return []string{base}
	}
	names := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		names = append(names, fmt.Sprintf("%s-%d", base, i))
	}
	return names
}

// sopsPutter is the SopsPut half of *client.Client, so the import loop — the part with the
// partial-failure rule in it — is testable without a daemon.
type sopsPutter interface {
	SopsPut(name, tier string, key []byte) (ipc.SopsIdentityInfo, error)
}

// putSopsKeys stores each key under its name, STOPPING at the first failure and returning
// what landed before it. The caller must not rewrite anything unless err is nil.
//
// The tier sent is always empty, deliberately. Empty means the documented default on a
// create; on a REPLACE the daemon carries the STORED tier forward, so importing over a
// dangerous-tier identity cannot silently demote it to normal.
//
// SECURITY: keys[i] is a private key. It is passed straight through and appears in no error
// here — including the one returned, which is the daemon's own and names the identity.
func putSopsKeys(c sopsPutter, names []string, keys [][]byte) ([]ipc.SopsIdentityInfo, error) {
	stored := make([]ipc.SopsIdentityInfo, 0, len(keys))
	for i, key := range keys {
		info, err := c.SopsPut(names[i], "", key)
		if err != nil {
			return stored, err
		}
		stored = append(stored, info)
	}
	return stored, nil
}

// reportSopsImportFailure explains a partial import: which keys reached the vault, which did
// not, and why the file was left exactly as it was.
//
// Leaving it alone is the deliberate choice. The alternative — rewriting the lines that made
// it and keeping the rest as plaintext — produces a keys.txt holding one pointer and one
// bare key, which is valid to sops and unreadable to everyone else: nothing in it says which
// half of the migration happened, and a later import cannot tell either. Untouched, the file
// is still precisely what sops was using before this ran, and the keys that did land are
// duplicates that change nothing until the file says otherwise.
func reportSopsImportFailure(src string, names []string, stored []ipc.SopsIdentityInfo) {
	fmt.Fprintf(os.Stderr, "av: import FAILED after %d of %d keys — %s was NOT modified.\n", len(stored), len(names), src)
	if len(stored) == 0 {
		return
	}
	got := make([]string, 0, len(stored))
	for _, info := range stored {
		got = append(got, info.Name)
	}
	fmt.Fprintf(os.Stderr, "av: already in the vault: %s. They are duplicates of what is still in the file, so nothing is lost — but re-running the import will ask to replace them.\n", strings.Join(got, ", "))
}

// askSopsBackup asks whether to keep the original at <src>.bak before it is overwritten.
//
// Every ambiguous answer resolves toward still having the key: a bare Enter keeps it, an
// unrecognized answer keeps it, and with no terminal to ask at it is kept without asking.
// Only an explicit "n" declines — and that is the one path on which the plaintext key stops
// existing outside the vault, which is the point of the whole exercise but not something to
// do to someone who did not say so.
func askSopsBackup(in io.Reader, out io.Writer, stdinTTY bool, src string) bool {
	if !stdinTTY {
		fmt.Fprintf(out, "keeping a backup at %s%s (no terminal to ask at).\n", src, sopsBackupSuffix)
		return true
	}
	fmt.Fprintf(out, "Keep a backup of the original at %s%s? [Y/n] (Ctrl-C to abort) ", src, sopsBackupSuffix)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(out)
		return true
	}
	fmt.Fprintln(out)
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "n", "no":
		return false
	default:
		return true
	}
}

// formatSopsPointerFile renders the replacement keys.txt: one block per imported identity,
// plus any pointer that was already in the file.
//
// The comments are for the human who opens this file in a year wondering what it is. The
// pointer itself is public — it carries a recipient, not a key, and decrypts nothing without
// a running avd and a presence check — which is why this file no longer needs guarding the
// way the one it replaces did.
func formatSopsPointerFile(infos []ipc.SopsIdentityInfo, existing []string) string {
	var b strings.Builder
	written := make(map[string]bool, len(infos))
	for _, info := range infos {
		fmt.Fprintf(&b, "# managed by AgentVault — this is a pointer, not a key.\n")
		fmt.Fprintf(&b, "# identity: %s\n", info.Name)
		fmt.Fprintf(&b, "# recipient: %s\n", info.Recipient)
		fmt.Fprintf(&b, "# useless without a running avd + your presence check.\n")
		fmt.Fprintf(&b, "%s\n\n", info.Identity)
		written[info.Identity] = true
	}
	var kept []string
	for _, p := range existing {
		if !written[p] {
			kept = append(kept, p)
		}
	}
	if len(kept) > 0 {
		fmt.Fprintf(&b, "# pointers that were already in this file, kept as they were.\n")
		for _, p := range kept {
			fmt.Fprintf(&b, "%s\n", p)
		}
	}
	return b.String()
}

// writeSopsPointerFile replaces path with content, optionally copying the original to
// <path>.bak first.
//
// The write goes through a temp file in the same directory and a rename, so an interrupted
// run cannot leave a truncated keys.txt — the file either still holds what it held or holds
// the complete pointer file. Mode 0600 on both: the original is frequently 0644, and a file
// being rewritten is the moment to fix that (the backup still holds the plaintext key).
func writeSopsPointerFile(path, content string, original []byte, keepBackup bool) error {
	if keepBackup {
		if err := os.WriteFile(path+sopsBackupSuffix, original, 0o600); err != nil {
			return fmt.Errorf("write backup %s%s: %w", path, sopsBackupSuffix, err)
		}
	}
	tmp := path + ".av-tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp) // best effort: never leave a stray temp next to a keys.txt
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// formatSopsImportDone is the summary. It names every identity that landed, the file that
// now points at them, and — when a backup was kept — that the PLAINTEXT KEY is still sitting
// in it. "It never deletes a key silently" has a second half: the copy it did not delete has
// to be named, or the user is left believing the key is off their disk when it is not.
func formatSopsImportDone(src string, infos []ipc.SopsIdentityInfo, keptBackup bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "imported %d %s into the vault:\n", len(infos), plural(len(infos), "identity", "identities"))
	for _, info := range infos {
		fmt.Fprintf(&b, "  %s  (tier %s)  %s\n", info.Name, info.Tier, info.Recipient)
	}
	fmt.Fprintf(&b, "%s now holds pointers instead of keys.\n", src)
	if keptBackup {
		fmt.Fprintf(&b, "the plaintext key is STILL in %s%s — delete it once you have confirmed sops can decrypt.\n", src, sopsBackupSuffix)
	}
	return b.String()
}

// plural picks the singular or plural word for n. `av sops import` reports counts in half a
// dozen places and "1 identity(ies)" reads like a bug in a command whose whole job is to
// sound trustworthy while it moves a private key.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// sopsAgeKeyEnvSet / sopsAgeKeyCmdEnvSet report the two ways sops reads an identity that a
// path search cannot see. They return BOOLEANS on purpose: SOPS_AGE_KEY holds a private key
// outright and SOPS_AGE_KEY_CMD can hold one (`echo AGE-SECRET-KEY-1…`), so no caller is
// handed a value it could print.
func sopsAgeKeyEnvSet() bool    { return os.Getenv("SOPS_AGE_KEY") != "" }
func sopsAgeKeyCmdEnvSet() bool { return os.Getenv("SOPS_AGE_KEY_CMD") != "" }

// warnSopsEnvShadow warns, after a successful import, that sops will keep using the key in
// the environment. The pointer is now in place and everything still decrypts — with the old
// key, never exercising the plugin — so without this the import looks like it worked and did
// nothing.
func warnSopsEnvShadow() {
	for _, name := range []string{"SOPS_AGE_KEY", "SOPS_AGE_KEY_CMD"} {
		if os.Getenv(name) != "" {
			fmt.Fprintf(os.Stderr, "WARNING: %s is set — sops reads that key too and will keep using it. Unset it (and remove it from your shell profile) or the pointer is never used.\n", name)
		}
	}
}

// sopsNothingFoundMessage explains that no keys.txt was found — which is NOT the same as
// "you have no key". sops reads its identity from four places and only two are files, so a
// user with SOPS_AGE_KEY or SOPS_AGE_KEY_CMD set has a working setup and no keys.txt by
// design; telling them a file is missing sends them hunting for one that never existed.
// Those two are therefore answered first, with the exact commands that move the key into a
// file this command can import.
//
// SECURITY: it takes booleans, not values. The shell lines it prints expand $SOPS_AGE_KEY
// and $SOPS_AGE_KEY_CMD at the user's own prompt, so a private key in either variable is
// never read by av, never printed, and never in a terminal scrollback because of this.
func sopsNothingFoundMessage(candidates []string, hasAgeKey, hasAgeKeyCmd bool, keysPath string) string {
	var b strings.Builder
	if hasAgeKey || hasAgeKeyCmd {
		if hasAgeKey {
			fmt.Fprintf(&b, "no keys.txt to import, but SOPS_AGE_KEY is set — sops reads your key from that variable, not from a file, so there is nothing on disk to find.\n")
			fmt.Fprintf(&b, "to import it, put it where sops keeps keys and import that file:\n")
			fmt.Fprintf(&b, "  mkdir -p %q && printf '%%s\\n' \"$SOPS_AGE_KEY\" > %q\n  av sops import\n", filepath.Dir(keysPath), keysPath)
			fmt.Fprintf(&b, "then unset SOPS_AGE_KEY (and remove it from your shell profile): while it is set, sops keeps using that key and the pointer is never exercised.\n")
		}
		if hasAgeKeyCmd {
			fmt.Fprintf(&b, "no keys.txt to import, but SOPS_AGE_KEY_CMD is set — sops gets your key by running that command, so there is nothing on disk to find.\n")
			fmt.Fprintf(&b, "to import it, write what it prints where sops keeps keys and import that file:\n")
			fmt.Fprintf(&b, "  mkdir -p %q && sh -c \"$SOPS_AGE_KEY_CMD\" > %q\n  av sops import\n", filepath.Dir(keysPath), keysPath)
			fmt.Fprintf(&b, "then unset SOPS_AGE_KEY_CMD (and remove it from your shell profile): while it is set, sops keeps using that key and the pointer is never exercised.\n")
		}
		fmt.Fprintf(&b, "(no keys.txt at %s either, which is expected with that set.)\n", strings.Join(candidates, ", "))
		return b.String()
	}
	fmt.Fprintf(&b, "no age key to import. Checked:\n")
	for _, p := range candidates {
		fmt.Fprintf(&b, "  %s\n", p)
	}
	fmt.Fprintf(&b, "SOPS_AGE_KEY and SOPS_AGE_KEY_CMD are not set either, so sops has no identity here.\n")
	fmt.Fprintf(&b, "if you have no key yet, make one that never touches disk:  av sops keygen NAME\n")
	return b.String()
}
