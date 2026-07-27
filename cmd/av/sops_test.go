package main

import (
	"bytes"
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
