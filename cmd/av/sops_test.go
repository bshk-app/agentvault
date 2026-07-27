package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/beshkenadze/agentvault/internal/ipc"
)

// sampleRecipient / samplePointer are a real recipient and the pointer it encodes to, taken
// from internal/sopsplugin's testdata shape. Only their FORM matters here: av never parses
// either — it prints what the daemon sent — so these are opaque strings on this side.
const (
	sampleRecipient = "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj"
	samplePointer   = "AGE-PLUGIN-AV-1QYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQ8FJ9WD"
)

func sampleInfo(name, tier string) ipc.SopsIdentityInfo {
	return ipc.SopsIdentityInfo{Name: name, Tier: tier, Recipient: sampleRecipient, Identity: samplePointer}
}

// TestParseSopsKeygenArgs: NAME is the single positional and --tier takes both flag forms.
func TestParseSopsKeygenArgs(t *testing.T) {
	for _, tc := range []struct {
		args []string
		name string
		tier string
	}{
		{[]string{"work"}, "work", ""},
		{[]string{"work", "--tier", "dangerous"}, "work", "dangerous"},
		{[]string{"--tier=dangerous", "work"}, "work", "dangerous"},
	} {
		o, err := parseSopsKeygenArgs(tc.args)
		if err != nil {
			t.Fatalf("parseSopsKeygenArgs(%q): %v", tc.args, err)
		}
		if o.name != tc.name || o.tier != tc.tier {
			t.Fatalf("parseSopsKeygenArgs(%q) = %+v, want name=%q tier=%q", tc.args, o, tc.name, tc.tier)
		}
	}
}

// TestParseSopsKeygenArgsErrors: a missing NAME, a second positional and a valueless --tier
// are all usage errors. The second positional matters most — `av sops keygen NAME KEY` would
// be a private key on argv, which is exactly what parseAddArgs refuses for `av add`.
func TestParseSopsKeygenArgsErrors(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"work", "extra"},
		{"work", "--tier"},
	} {
		if _, err := parseSopsKeygenArgs(args); err == nil {
			t.Fatalf("parseSopsKeygenArgs(%q) = nil error, want a usage error", args)
		}
	}
}

// TestParseSopsKeygenArgsRefusesFlags is the guard that keeps a typo from becoming permanent.
//
// Without it `av sops keygen --dry-run` GENERATES a key and stores it under the name
// "--dry-run" — the daemon's name rule refuses only an empty name and a slash — and from
// then on nothing can reach it: `av sops rm --dry-run`, `recipient` and `identity` all parse
// it as a flag, and `av rm sops/--dry-run` is refused by the reserved-namespace guard. The
// entry sits in `av sops ls` forever. A mistyped flag must be an error, never a name.
func TestParseSopsKeygenArgsRefusesFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--dry-run"},
		{"-n"},
		{"--force"},
		{"work", "--dry-run"},
		{"--dry-run", "--tier", "normal"},
	} {
		if o, err := parseSopsKeygenArgs(args); err == nil {
			t.Fatalf("parseSopsKeygenArgs(%q) accepted a flag as NAME %q", args, o.name)
		}
	}
}

// TestParseSopsKeygenArgsDoesNotValidateTier: an unknown tier passes the parser untouched.
// NormalizeTier in sopsplugin is the ONE definition of a valid tier and the daemon applies
// it before opening the session, so a typo is already refused for free — a second list here
// would be a second definition to drift.
func TestParseSopsKeygenArgsDoesNotValidateTier(t *testing.T) {
	o, err := parseSopsKeygenArgs([]string{"work", "--tier", "normla"})
	if err != nil {
		t.Fatalf("parser rejected an unknown tier locally: %v", err)
	}
	if o.tier != "normla" {
		t.Fatalf("tier = %q, want it passed through verbatim", o.tier)
	}
}

// TestFormatSopsCreated: the summary names the identity, its tier and its PUBLIC recipient,
// and tells the user the two things that must happen next for sops to use it — the recipient
// into .sops.yaml, the pointer into keys.txt.
func TestFormatSopsCreated(t *testing.T) {
	out := formatSopsCreated("created", sampleInfo("work", "normal"), "/cfg/sops/age/keys.txt")
	for _, want := range []string{"created", `"work"`, "normal", sampleRecipient, ".sops.yaml", "av sops identity work", "/cfg/sops/age/keys.txt"} {
		if !strings.Contains(out, want) {
			t.Fatalf("formatSopsCreated output missing %q:\n%s", want, out)
		}
	}
}

// TestFormatSopsCreatedQuotesKeysPath: the hint is a shell line and the darwin keys.txt path
// contains a space ("Application Support"). Unquoted, a user pasting it appends the pointer
// to a file called "Support/sops/age/keys.txt" and sops never sees it.
func TestFormatSopsCreatedQuotesKeysPath(t *testing.T) {
	const path = "/Users/x/Library/Application Support/sops/age/keys.txt"
	out := formatSopsCreated("created", sampleInfo("work", "normal"), path)
	if !strings.Contains(out, `"`+path+`"`) {
		t.Fatalf("keys.txt path must be quoted for the shell:\n%s", out)
	}
}

// TestFindSopsIdentity: the client-side lookup `recipient`, `identity` and the replace
// confirmation all share.
func TestFindSopsIdentity(t *testing.T) {
	ids := []ipc.SopsIdentityInfo{sampleInfo("a", "normal"), sampleInfo("b", "dangerous")}
	if got, ok := findSopsIdentity(ids, "b"); !ok || got.Tier != "dangerous" {
		t.Fatalf("findSopsIdentity(b) = %+v, %v", got, ok)
	}
	if _, ok := findSopsIdentity(ids, "c"); ok {
		t.Fatal("findSopsIdentity(c) reported a hit for a name nobody stored")
	}
}

// TestSopsConfirmRequiresYes: only an exact "yes" proceeds. A bare newline (someone leaning
// on Enter), "y", and EOF (a closed stdin) all abort.
func TestSopsConfirmRequiresYes(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool // want confirmed
	}{
		{"yes\n", true},
		{"  yes  \n", true},
		{"y\n", false},
		{"\n", false},
		{"", false},
		{"no\n", false},
	} {
		var out bytes.Buffer
		err := sopsConfirm(strings.NewReader(tc.in), &out, "Delete it?")
		if (err == nil) != tc.want {
			t.Fatalf("sopsConfirm(%q) err = %v, want confirmed=%v", tc.in, err, tc.want)
		}
		if !strings.Contains(out.String(), "Delete it?") {
			t.Fatalf("sopsConfirm did not print its prompt: %q", out.String())
		}
	}
}

// TestConfirmSopsReplaceNoCollision: a name nobody stored is a create, so nothing is asked
// and nothing is printed — the common case must not grow a prompt.
func TestConfirmSopsReplaceNoCollision(t *testing.T) {
	var out bytes.Buffer
	err := confirmSopsReplace([]ipc.SopsIdentityInfo{sampleInfo("other", "normal")},
		[]string{"work"}, true, strings.NewReader(""), &out)
	if err != nil {
		t.Fatalf("confirmSopsReplace on a free name: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("confirmSopsReplace printed on a free name: %q", out.String())
	}
}

// TestConfirmSopsReplaceNamesWhatDies: the user is told which identity, at which tier, and
// what the consequence is BEFORE being asked. The daemon replaces a name without asking
// anything a human can read, so this text is the only warning that exists.
func TestConfirmSopsReplaceNamesWhatDies(t *testing.T) {
	var out bytes.Buffer
	ids := []ipc.SopsIdentityInfo{sampleInfo("work", "dangerous")}
	if err := confirmSopsReplace(ids, []string{"work"}, true, strings.NewReader("yes\n"), &out); err != nil {
		t.Fatalf("confirmSopsReplace with yes: %v", err)
	}
	for _, want := range []string{"work", "dangerous", "unreadable"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("replace warning missing %q:\n%s", want, out.String())
		}
	}
}

// TestConfirmSopsReplaceDeclined: anything but "yes" leaves the stored key alone.
func TestConfirmSopsReplaceDeclined(t *testing.T) {
	var out bytes.Buffer
	ids := []ipc.SopsIdentityInfo{sampleInfo("work", "normal")}
	if err := confirmSopsReplace(ids, []string{"work"}, true, strings.NewReader("no\n"), &out); err == nil {
		t.Fatal("confirmSopsReplace proceeded on a declined prompt")
	}
}

// TestFormatSopsListColumns: one line per identity with its name, tier and PUBLIC recipient,
// under a header, aligned on the longest name.
func TestFormatSopsListColumns(t *testing.T) {
	out := formatSopsList([]ipc.SopsIdentityInfo{
		sampleInfo("prod-deploy-key", "dangerous"),
		sampleInfo("work", "normal"),
	})
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want a header + 2 rows, got %d lines:\n%s", len(lines), out)
	}
	if !strings.HasPrefix(lines[0], "NAME") || !strings.Contains(lines[0], "TIER") || !strings.Contains(lines[0], "RECIPIENT") {
		t.Fatalf("header = %q", lines[0])
	}
	// The recipient column starts at the same offset on every row, header included.
	col := strings.Index(lines[0], "RECIPIENT")
	for _, l := range lines[1:] {
		if strings.Index(l, sampleRecipient) != col {
			t.Fatalf("recipient column misaligned (want %d):\n%s", col, out)
		}
	}
}

// TestFormatSopsListPrintsNoPrivateKey is the property that lets `av sops ls` output be
// pasted into an issue: it is built from ipc.SopsIdentityInfo, which has no field that can
// hold a private key, so the AGE-SECRET-KEY-1… prefix cannot appear however it is called.
// The check is cheap and pins the guarantee at the surface a user actually sees.
func TestFormatSopsListPrintsNoPrivateKey(t *testing.T) {
	out := formatSopsList([]ipc.SopsIdentityInfo{sampleInfo("work", "normal")})
	if strings.Contains(out, "AGE-SECRET-KEY") {
		t.Fatalf("listing leaked key material:\n%s", out)
	}
}

// TestFormatSopsListEmpty: an empty vault is not an error — it says so and names the command
// that fixes it. `av sops ls` on a fresh install is the likeliest first contact with this
// surface, so it must not read as a failure.
func TestFormatSopsListEmpty(t *testing.T) {
	out := formatSopsList(nil)
	if !strings.Contains(out, "no SOPS identities") || !strings.Contains(out, "av sops keygen") {
		t.Fatalf("empty listing = %q", out)
	}
}

// TestParseSopsNameArg: exactly one positional NAME, nothing else.
func TestParseSopsNameArg(t *testing.T) {
	name, err := parseSopsNameArg("av sops recipient", []string{"work"})
	if err != nil || name != "work" {
		t.Fatalf("got %q, %v", name, err)
	}
	for _, args := range [][]string{nil, {"a", "b"}, {"--tier", "normal", "a"}, {"-x"}, {"--"}} {
		if _, err := parseSopsNameArg("av sops recipient", args); err == nil {
			t.Fatalf("parseSopsNameArg(%q) accepted bad args", args)
		}
	}
}

// TestParseSopsNameArgEscapesADashName is the read half of the escape parseSopsRmArgs
// carries for the delete half. `av sops import --name -x` stores a dash-named identity
// (--name takes whatever value it is given), so one has to be reachable — and reachable
// means READABLE, not merely deletable: `av sops identity` is what prints the
// AGE-PLUGIN-AV-1… pointer, and without the pointer the key cannot go in keys.txt and is
// therefore unusable.
func TestParseSopsNameArgEscapesADashName(t *testing.T) {
	for _, cmd := range []string{"av sops recipient", "av sops identity"} {
		name, err := parseSopsNameArg(cmd, []string{"--", "-x"})
		if err != nil || name != "-x" {
			t.Fatalf("%s -- -x = %q, %v; want %q", cmd, name, err, "-x")
		}
	}
	// Without the escape the dash is still a typo, and the message has to name the way out
	// — a user who cannot see `--` here has no reason to guess it.
	_, err := parseSopsNameArg("av sops identity", []string{"-x"})
	if err == nil {
		t.Fatal("a bare -x must be refused as a flag")
	}
	if !strings.Contains(err.Error(), "av sops identity -- NAME") {
		t.Fatalf("error should point at the escape, got: %v", err)
	}
}

// TestSopsShowValue: `recipient` prints the age1… to encrypt to, `identity` prints the
// AGE-PLUGIN-AV-1… line keys.txt wants — bare, with nothing around it, because the whole
// point of `av sops identity NAME >> keys.txt` is that its stdout IS the file line.
func TestSopsShowValue(t *testing.T) {
	id := sampleInfo("work", "normal")
	if got := sopsShowValue(sopsFieldRecipient, id); got != sampleRecipient {
		t.Fatalf("recipient = %q", got)
	}
	if got := sopsShowValue(sopsFieldIdentity, id); got != samplePointer {
		t.Fatalf("identity = %q", got)
	}
}

// TestSopsNoSuchIdentityMatchesDaemon pins the client-side "no such identity" to the
// daemon's spelling. `recipient` and `identity` have no RPC of their own — they read a
// field out of the sops_list reply — so this condition is produced HERE while the identical
// condition on `rm` is produced in internal/daemon/sops_manage.go:334 as
// `fmt.Sprintf("sops %s %q: no such SOPS identity", op, name)`. Two spellings of one
// condition in two packages, with nothing but this test linking them.
func TestSopsNoSuchIdentityMatchesDaemon(t *testing.T) {
	const want = `sops recipient "typo": no such SOPS identity`
	if got := sopsNoSuchIdentity(string(sopsFieldRecipient), "typo").Error(); got != want {
		t.Fatalf("sopsNoSuchIdentity = %q, want %q", got, want)
	}
}

// TestParseSopsRmArgs: NAME plus an optional --force, in either order.
func TestParseSopsRmArgs(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		name  string
		force bool
	}{
		{[]string{"work"}, "work", false},
		{[]string{"work", "--force"}, "work", true},
		{[]string{"--force", "work"}, "work", true},
	} {
		o, err := parseSopsRmArgs(tc.args)
		if err != nil {
			t.Fatalf("parseSopsRmArgs(%q): %v", tc.args, err)
		}
		if o.name != tc.name || o.force != tc.force {
			t.Fatalf("parseSopsRmArgs(%q) = %+v", tc.args, o)
		}
	}
	for _, args := range [][]string{nil, {"--force"}, {"a", "b"}} {
		if _, err := parseSopsRmArgs(args); err == nil {
			t.Fatalf("parseSopsRmArgs(%q) accepted bad args", args)
		}
	}
}

// TestParseSopsRmArgsEndOfFlags: `--` ends the flags, so a NAME that starts with a dash is
// removable. rm is the only sops subcommand that takes `--`, and it takes it because it is
// the only one that can clear such an entry: `av sops import --name -x` still creates one by
// definition (--name takes the value it is given), and `av rm sops/-x` is refused by the
// reserved-namespace guard. Without this, that entry would be listed forever and deletable
// by nothing.
func TestParseSopsRmArgsEndOfFlags(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		name  string
		force bool
	}{
		{[]string{"--", "--dry-run"}, "--dry-run", false},
		{[]string{"--force", "--", "-x"}, "-x", true},
		{[]string{"--", "--force"}, "--force", false}, // after --, even a real flag is a name
		{[]string{"--", "--"}, "--", false},
	} {
		o, err := parseSopsRmArgs(tc.args)
		if err != nil {
			t.Fatalf("parseSopsRmArgs(%q): %v", tc.args, err)
		}
		if o.name != tc.name || o.force != tc.force {
			t.Fatalf("parseSopsRmArgs(%q) = %+v, want name=%q force=%v", tc.args, o, tc.name, tc.force)
		}
	}
	// A bare `--` names nothing, and two positionals after it are still two positionals.
	for _, args := range [][]string{{"--"}, {"--", "a", "b"}} {
		if _, err := parseSopsRmArgs(args); err == nil {
			t.Fatalf("parseSopsRmArgs(%q) accepted bad args", args)
		}
	}
	// The refusal has to name the escape, or it is a dead end with a way out nobody knows.
	_, err := parseSopsRmArgs([]string{"--dry-run"})
	if err == nil || !strings.Contains(err.Error(), "av sops rm -- NAME") {
		t.Fatalf("the unexpected-flag refusal should name the -- escape: %v", err)
	}
}

// TestSopsRemoveTarget: the prompt names the tier and recipient when the listing knew the
// identity, and falls back to the bare name when it did not — a corrupt entry that breaks
// `av sops ls` must still be removable, so the prompt has to work without a listing.
func TestSopsRemoveTarget(t *testing.T) {
	known := sopsRemoveTarget("work", sampleInfo("work", "dangerous"), true)
	for _, want := range []string{`"work"`, "dangerous", sampleRecipient} {
		if !strings.Contains(known, want) {
			t.Fatalf("sopsRemoveTarget(known) = %q, missing %q", known, want)
		}
	}
	if got := sopsRemoveTarget("junk", ipc.SopsIdentityInfo{}, false); got != `"junk"` {
		t.Fatalf("sopsRemoveTarget(unknown) = %q", got)
	}
}

// TestConfirmSopsRemoveWarnsThenAsks: the consequence is printed before the question, on
// every path — including --force, so whatever log captured the run also captured the warning.
func TestConfirmSopsRemoveWarnsThenAsks(t *testing.T) {
	var out bytes.Buffer
	if err := confirmSopsRemove(`"work"`, true, false, strings.NewReader("yes\n"), &out); err != nil {
		t.Fatalf("confirmSopsRemove with yes: %v", err)
	}
	for _, want := range []string{"work", "unreadable", "yes"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("delete warning missing %q:\n%s", want, out.String())
		}
	}
}

// TestConfirmSopsRemoveDeclined: anything but "yes" leaves the key alone.
func TestConfirmSopsRemoveDeclined(t *testing.T) {
	var out bytes.Buffer
	if err := confirmSopsRemove(`"work"`, true, false, strings.NewReader("nope\n"), &out); err == nil {
		t.Fatal("confirmSopsRemove proceeded on a declined prompt")
	}
}

// TestConfirmSopsRemoveRefusesWithoutTTY: no terminal, no --force, no deletion. This is the
// path a script or an agent takes, and there is nobody there to be warned.
func TestConfirmSopsRemoveRefusesWithoutTTY(t *testing.T) {
	var out bytes.Buffer
	err := confirmSopsRemove(`"work"`, false, false, strings.NewReader("yes\n"), &out)
	if err == nil {
		t.Fatal("confirmSopsRemove proceeded without a TTY")
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Fatalf("refusal should name --force: %v", err)
	}
	if !strings.Contains(out.String(), "unreadable") {
		t.Fatalf("the consequence must be printed even when refusing:\n%s", out.String())
	}
}

// TestConfirmSopsRemoveForceSkipsPrompt: --force is the deliberate non-interactive opt-out,
// and it must not read stdin — a script's stdin is its own data, not an answer to a question.
func TestConfirmSopsRemoveForceSkipsPrompt(t *testing.T) {
	var out bytes.Buffer
	in := strings.NewReader("no\n") // would abort if it were read
	if err := confirmSopsRemove(`"work"`, false, true, in, &out); err != nil {
		t.Fatalf("confirmSopsRemove --force: %v", err)
	}
	if strings.Contains(out.String(), "Type 'yes'") {
		t.Fatalf("--force must not prompt:\n%s", out.String())
	}
}

// TestParseSopsVersion covers the shapes `sops --version` actually prints: bare, with the
// " (latest)" suffix the online version check adds, and a "v"-prefixed build.
func TestParseSopsVersion(t *testing.T) {
	for _, tc := range []struct {
		out   string
		major int
		minor int
		ok    bool
	}{
		{"sops 3.9.0\n", 3, 9, true},
		{"sops 3.10.2 (latest)\n", 3, 10, true},
		{"sops v3.8.1\n", 3, 8, true},
		{"sops 4.0.0\n", 4, 0, true},
		{"some fork with no version\n", 0, 0, false},
		{"", 0, 0, false},
	} {
		major, minor, ok := parseSopsVersion(tc.out)
		if ok != tc.ok || major != tc.major || minor != tc.minor {
			t.Fatalf("parseSopsVersion(%q) = %d.%d,%v want %d.%d,%v", tc.out, major, minor, ok, tc.major, tc.minor, tc.ok)
		}
	}
}

// TestSopsVersionNote: below 3.10 warns (age plugin support landed there), 3.10 and above
// say nothing, and an unparseable version says nothing either — a fork or a distro build is
// not a reason to alarm anyone.
func TestSopsVersionNote(t *testing.T) {
	if note := sopsVersionNote("sops 3.9.0"); !strings.Contains(note, "3.10") {
		t.Fatalf("sops 3.9 should warn about 3.10, got %q", note)
	}
	for _, out := range []string{"sops 3.10.0", "sops 3.11.2 (latest)", "sops 4.1.0", "sops (unknown)"} {
		if note := sopsVersionNote(out); note != "" {
			t.Fatalf("sopsVersionNote(%q) = %q, want no warning", out, note)
		}
	}
}

// fakeLister is the sopsLister seam: the sops_list half of *client.Client, which is all the
// replace check needs. Every identity in a listing already carries its recipient and its
// pointer, so no part of this surface has an RPC of its own.
type fakeLister struct {
	ids   []ipc.SopsIdentityInfo
	calls int
}

func (f *fakeLister) SopsList() ([]ipc.SopsIdentityInfo, error) {
	f.calls++
	return f.ids, nil
}

// TestSopsCheckReplaceDecidesTheVerb covers both outcomes of the check `av sops keygen` and
// `av sops import` open with, and the word keygen prints because of it.
//
// The "replaced" branch is only reachable with a terminal — a taken name without one is
// refused outright — which is why the terminal and its streams are parameters. A test has no
// terminal, so before that seam existed this function could only ever return "created".
func TestSopsCheckReplaceDecidesTheVerb(t *testing.T) {
	stored := []ipc.SopsIdentityInfo{sampleInfo("work", "dangerous")}

	// A free name: no prompt, no output, a create.
	c := &fakeLister{ids: stored}
	var out bytes.Buffer
	if replacing := sopsCheckReplace(c, []string{"fresh"}, false, strings.NewReader(""), &out); replacing {
		t.Fatal("a name nobody stored is a create")
	}
	if c.calls != 1 {
		t.Fatalf("SopsList calls = %d, want exactly 1", c.calls)
	}
	if out.Len() != 0 {
		t.Fatalf("the common case must not print anything: %q", out.String())
	}
	if got := sopsWriteVerb(false); got != "created" {
		t.Fatalf("verb = %q, want created", got)
	}

	// A taken name, confirmed at a terminal: a replace, and the user was told what dies.
	out.Reset()
	if replacing := sopsCheckReplace(c, []string{"work"}, true, strings.NewReader("yes\n"), &out); !replacing {
		t.Fatal("a name that is already stored is a replace")
	}
	for _, want := range []string{"work", "dangerous", "unreadable", "Replace it?"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("the replace prompt is missing %q:\n%s", want, out.String())
		}
	}
	if got := sopsWriteVerb(true); got != "replaced" {
		t.Fatalf("verb = %q, want replaced", got)
	}
	// Both words reach the user through the same summary.
	for _, verb := range []string{"created", "replaced"} {
		if !strings.Contains(formatSopsCreated(verb, sampleInfo("work", "normal"), "/k.txt"), verb) {
			t.Fatalf("formatSopsCreated dropped the verb %q", verb)
		}
	}
}

// TestSopsCheckReplaceChecksEveryName: import stores several keys at once, and ONE taken name
// among them is a replace — anything less would let a multi-key import destroy a stored
// identity while reporting that it created one.
func TestSopsCheckReplaceChecksEveryName(t *testing.T) {
	c := &fakeLister{ids: []ipc.SopsIdentityInfo{sampleInfo("imported-2", "normal")}}
	var out bytes.Buffer
	if !sopsCheckReplace(c, []string{"imported-1", "imported-2"}, true, strings.NewReader("yes\n"), &out) {
		t.Fatal("a taken name anywhere in the list is a replace")
	}
}

// TestSopsWarnsAboutEnvShadowOnEveryPath pins the CALL SITES of warnSopsEnvShadow. Both
// commands end in a dialClient()'d RPC, so neither runSops* function can be exercised without
// a daemon, and the call site is the only thing left that a test can reach.
//
// It is worth reaching. `av sops keygen` shipped without the call, and what that lets through
// is precisely the failure this whole feature exists to prevent: the summary tells the user
// to append the pointer to keys.txt, and with SOPS_AGE_KEY set sops goes on decrypting with
// the old key, the plugin is never exercised, and every command involved reports success.
func TestSopsWarnsAboutEnvShadowOnEveryPath(t *testing.T) {
	for _, tc := range []struct{ file, fn string }{
		{"sops.go", "runSopsKeygen"},
		{"sops_import.go", "runSopsImport"},
	} {
		if !funcCallsFunc(t, tc.file, tc.fn, "warnSopsEnvShadow") {
			t.Errorf("%s does not call warnSopsEnvShadow: a user with SOPS_AGE_KEY set gets a success message and an identity sops never uses", tc.fn)
		}
	}
}

// funcCallsFunc reports whether the named function in file contains a call to want. It fails
// the test outright when the function is not there, so a rename cannot turn this into a
// vacuous pass.
func funcCallsFunc(t *testing.T, file, fn, want string) bool {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range parsed.Decls {
		decl, ok := d.(*ast.FuncDecl)
		if !ok || decl.Name.Name != fn {
			continue
		}
		found := false
		ast.Inspect(decl.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == want {
					found = true
				}
			}
			return !found
		})
		return found
	}
	t.Fatalf("%s has no func %s — this test is guarding a call site that no longer exists", file, fn)
	return false
}

// captureStderr runs fn with os.Stderr redirected to a pipe and returns what it wrote. The
// error renderers print with fmt.Fprintln(os.Stderr, …), so asserting on the STREAM is what
// makes the tests below about the line a user reads rather than about some string on the way
// to it — and the way to it is exactly where the two locked messages were being lost.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = saved }()
	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if _, err := b.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	r.Close()
	return b.String()
}

// TestSopsExitForErrorRelaysBothLockedMessages is av's half of the assertion
// cmd/age-plugin-av/main_test.go makes for the plugin, and the gap it fills is why the
// collapse survived every per-task review: the daemon writes two DIFFERENT CodeLocked texts,
// internal/client carries both through intact (internal/client/sops_test.go pins that), and
// then the renderer here replaced them with one fixed string on the last hop to the
// terminal. Nothing tested that hop. A user whose vault was OPEN was told to unlock it —
// runs `av unlock`, nothing changes, the agent retries, the identical error comes back.
//
// The two strings are PASTED from internal/daemon/sops_rpc.go rather than shared with it: av
// must not link the daemon (TestAvStaysThin), and a shared constant would make the two ends
// agree by construction, which is the one thing a test of a relay must not assume.
func TestSopsExitForErrorRelaysBothLockedMessages(t *testing.T) {
	const (
		// sopsLockedMsg("rm") — a genuinely locked vault, where `av unlock` is the fix.
		lockedVault = `sops rm: vault locked — ask a human to run "av unlock"`
		// sopsTierGate under no_prompt — the session is OPEN and only the fresh per-call
		// presence check is missing, so `av unlock` changes nothing.
		dangerousTier = `sops rm "prod": dangerous-tier identity needs a fresh presence check, and this caller set no_prompt`
	)
	for _, want := range []string{lockedVault, dangerousTier} {
		var code int
		out := captureStderr(t, func() {
			code = sopsExitForError(&ipc.RPCError{Code: ipc.CodeLocked, Message: want})
		})
		// EQUALITY, not Contains. The bug was one string standing in for two, and a
		// keyword assertion ("locked", "presence") is satisfiable by a substitute — which
		// is how a message test can pass over the very defect it was written for.
		if got := strings.TrimRight(out, "\n"); got != "av: "+want {
			t.Errorf("av printed %q, want %q", got, "av: "+want)
		}
		if code != exitLocked {
			t.Errorf("exit code for %q = %d, want exitLocked (%d)", want, code, exitLocked)
		}
	}
}

// TestSopsExitForErrorFallsBackAndLeavesOtherPathsAlone pins the two edges of the override:
// what it does with nothing to relay, and what it does NOT do to the rest of av.
func TestSopsExitForErrorFallsBackAndLeavesOtherPathsAlone(t *testing.T) {
	const fixed = "av: vault locked — ask a human to unlock"
	// A CodeLocked carrying no message — an older daemon, or a path that sends the bare
	// code — must still print something actionable rather than "av: ".
	var code int
	out := captureStderr(t, func() { code = sopsExitForError(&ipc.RPCError{Code: ipc.CodeLocked}) })
	if got := strings.TrimRight(out, "\n"); got != fixed {
		t.Errorf("an empty message printed %q, want the fixed fallback %q", got, fixed)
	}
	if code != exitLocked {
		t.Errorf("fallback exit code = %d, want exitLocked (%d)", code, exitLocked)
	}
	// And the override stops at `av sops`. Everywhere else the daemon's CodeLocked message
	// is ErrLocked's own text, which is accurate and advice-free; relaying it there would
	// LOSE the actionable string rather than gain one.
	out = captureStderr(t, func() {
		code = exitForError(&ipc.RPCError{Code: ipc.CodeLocked, Message: "vault locked: authorization not available"})
	})
	if got := strings.TrimRight(out, "\n"); got != fixed {
		t.Errorf("exitForError printed %q, want the fixed string %q — other RPCs must be unchanged", got, fixed)
	}
	if code != exitLocked {
		t.Errorf("exitForError exit code = %d, want exitLocked (%d)", code, exitLocked)
	}
}

// TestSopsCommandsRenderErrorsThroughSopsExitForError keeps the fix from being undone one
// command at a time. The messages above only prove the renderer relays; this proves every
// `av sops` failure path REACHES it. A new subcommand wired to exitForError reintroduces the
// collapse on its own path, and no message test would notice, because a message test only
// covers the paths it happens to call.
func TestSopsCommandsRenderErrorsThroughSopsExitForError(t *testing.T) {
	for _, file := range []string{"sops.go", "sops_import.go"} {
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range parsed.Decls {
			decl, ok := d.(*ast.FuncDecl)
			// sopsExitForError is the one legitimate caller: it delegates everything but
			// CodeLocked to the shared mapping rather than restating it.
			if !ok || decl.Body == nil || decl.Name.Name == "sopsExitForError" {
				continue
			}
			ast.Inspect(decl.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "exitForError" {
					t.Errorf("%s: %s calls exitForError — an `av sops` path must use sopsExitForError, or the daemon's two CodeLocked messages collapse into one on this command", file, decl.Name.Name)
				}
				return true
			})
		}
	}
}

// TestConfirmSopsReplaceRefusesWithoutTTY: with no terminal there is nobody to warn, so a
// replace is refused outright rather than assumed. keygen and import have no --force by
// design: the non-interactive route to the same end is an explicit `av sops rm`, which is a
// separate command a script has to name.
func TestConfirmSopsReplaceRefusesWithoutTTY(t *testing.T) {
	var out bytes.Buffer
	ids := []ipc.SopsIdentityInfo{sampleInfo("work", "normal")}
	err := confirmSopsReplace(ids, []string{"work"}, false, strings.NewReader("yes\n"), &out)
	if err == nil {
		t.Fatal("confirmSopsReplace proceeded without a TTY")
	}
	if !strings.Contains(err.Error(), "av sops rm") {
		t.Fatalf("refusal should name the non-interactive route: %v", err)
	}
}
