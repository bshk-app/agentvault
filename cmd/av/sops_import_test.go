package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beshkenadze/agentvault/internal/ipc"
)

// sampleKey is key-SHAPED text, not a key: nothing in cmd/av parses one (that would mean
// linking filippo.io/age, which TestAvStaysThin forbids), so these tests only need the
// prefix the scanner keys off. The daemon is the only thing that decides what is a key.
const sampleKey = "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"

// writeFile is the tests' fixture writer: a keys.txt with the given content.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestParseSopsImportArgs: --from and --name in both flag forms, and no positionals.
func TestParseSopsImportArgs(t *testing.T) {
	o, err := parseSopsImportArgs([]string{"--from", "/k.txt", "--name", "work"})
	if err != nil || o.from != "/k.txt" || o.name != "work" {
		t.Fatalf("got %+v, %v", o, err)
	}
	if o, err := parseSopsImportArgs([]string{"--from=/k.txt", "--name=work"}); err != nil || o.from != "/k.txt" || o.name != "work" {
		t.Fatalf("got %+v, %v", o, err)
	}
	if o, err := parseSopsImportArgs(nil); err != nil || o.from != "" || o.name != "" {
		t.Fatalf("no-arg import should parse clean: %+v, %v", o, err)
	}
	for _, args := range [][]string{{"work"}, {"--from"}, {"--name"}, {"--nope"}} {
		if _, err := parseSopsImportArgs(args); err == nil {
			t.Fatalf("parseSopsImportArgs(%q) accepted bad args", args)
		}
	}
}

// TestSopsSourceFilePrefersFrom: --from wins over every candidate, and a --from that is not
// there is an error rather than a silent fall back to a candidate. Falling back would import
// a file the user did not name and rewrite it.
func TestSopsSourceFilePrefersFrom(t *testing.T) {
	dir := t.TempDir()
	from := writeFile(t, dir, "mine.txt", sampleKey+"\n")
	cand := writeFile(t, dir, "keys.txt", sampleKey+"\n")

	got, err := sopsSourceFile(from, []string{cand})
	if err != nil || got != from {
		t.Fatalf("sopsSourceFile(--from) = %q, %v; want %q", got, err, from)
	}
	if _, err := sopsSourceFile(filepath.Join(dir, "nope.txt"), []string{cand}); err == nil {
		t.Fatal("a --from that does not exist must be an error")
	}
}

// TestSopsSourceFileFirstCandidate: with no --from, the first candidate that EXISTS wins —
// candidates are ordered by preference and an earlier one that is absent is not a match.
func TestSopsSourceFileFirstCandidate(t *testing.T) {
	dir := t.TempDir()
	second := writeFile(t, dir, "second.txt", sampleKey+"\n")
	got, err := sopsSourceFile("", []string{filepath.Join(dir, "first.txt"), second})
	if err != nil || got != second {
		t.Fatalf("sopsSourceFile = %q, %v; want %q", got, err, second)
	}
	// Nothing anywhere is not an error — the caller says something far more useful than
	// an error string can (see sopsNothingFoundMessage).
	got, err = sopsSourceFile("", []string{filepath.Join(dir, "first.txt")})
	if err != nil || got != "" {
		t.Fatalf("sopsSourceFile(nothing) = %q, %v; want \"\", nil", got, err)
	}
}

// TestScanSopsKeysFile: private keys are collected for import, existing plugin pointers are
// collected to be CARRIED OVER, and comments and blanks are dropped.
//
// The pointers matter as much as the keys. A second `av sops import` (a new key generated
// with age-keygen, appended to a file already holding pointers from the first import) that
// wrote only the new pointers would drop the earlier ones — and every file encrypted to
// those identities would stop decrypting, with the key still safe in the vault and nothing
// on disk pointing at it.
func TestScanSopsKeysFile(t *testing.T) {
	const content = "# created: 2026-07-26\n" +
		"# public key: age1abc\n" +
		sampleKey + "\n" +
		"\n" +
		"# managed by AgentVault\n" +
		samplePointer + "\n" +
		"AGE-PLUGIN-YUBIKEY-1XYZ\n" +
		"  " + sampleKey + "2  \n"
	keys, pointers := scanSopsKeysFile([]byte(content))
	if len(keys) != 2 || string(keys[0]) != sampleKey || string(keys[1]) != sampleKey+"2" {
		t.Fatalf("keys = %q", keys)
	}
	// Another plugin's identity is preserved too: wiping a yubikey pointer breaks that
	// setup exactly as dropping ours would break this one.
	if len(pointers) != 2 || pointers[0] != samplePointer || pointers[1] != "AGE-PLUGIN-YUBIKEY-1XYZ" {
		t.Fatalf("pointers = %q", pointers)
	}
}

// TestScanSopsKeysFileCRLF: a keys.txt written on Windows must not have its keys read as
// "…\r" and rejected by the daemon as not-a-key.
func TestScanSopsKeysFileCRLF(t *testing.T) {
	keys, _ := scanSopsKeysFile([]byte("# c\r\n" + sampleKey + "\r\n"))
	if len(keys) != 1 || string(keys[0]) != sampleKey {
		t.Fatalf("keys = %q", keys)
	}
}

// TestSopsImportNames: one key takes the base name; several take numbered suffixes, so the
// names are predictable and printable before anything is stored.
func TestSopsImportNames(t *testing.T) {
	if got := sopsImportNames("work", 1); len(got) != 1 || got[0] != "work" {
		t.Fatalf("got %q", got)
	}
	got := sopsImportNames("work", 3)
	want := []string{"work-1", "work-2", "work-3"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sopsImportNames = %q, want %q", got, want)
		}
	}
}

// TestSopsImportNamesNeverDerivedFromFile is requirement 4 restated as a test: the name
// reaches the audit log, and a line of keys.txt is key material or adjacent to it. There is
// no code path from file content to a name — sopsImportNames takes only the --name value (or
// the default) and a COUNT, so a key cannot become a name however the file is shaped.
func TestSopsImportNamesNeverDerivedFromFile(t *testing.T) {
	for _, n := range sopsImportNames(sopsDefaultImportName, 2) {
		if strings.Contains(n, "AGE-") {
			t.Fatalf("generated name looks like key material: %q", n)
		}
		if !strings.HasPrefix(n, sopsDefaultImportName) {
			t.Fatalf("name %q is not derived from the default base", n)
		}
	}
}

// TestFormatSopsPointerFile: one block per imported identity, naming it and its recipient,
// plus the pointer line itself — and no private key anywhere.
func TestFormatSopsPointerFile(t *testing.T) {
	out := formatSopsPointerFile([]ipc.SopsIdentityInfo{sampleInfo("work", "normal")}, nil)
	for _, want := range []string{"managed by AgentVault", "pointer, not a key", "# identity: work", "# recipient: " + sampleRecipient, samplePointer} {
		if !strings.Contains(out, want) {
			t.Fatalf("pointer file missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "AGE-SECRET-KEY") {
		t.Fatalf("pointer file leaked key material:\n%s", out)
	}
}

// TestFormatSopsPointerFileKeepsExisting: pointers that were already in the file survive the
// rewrite, and one that duplicates a freshly written pointer is not written twice.
func TestFormatSopsPointerFileKeepsExisting(t *testing.T) {
	const other = "AGE-PLUGIN-YUBIKEY-1XYZ"
	out := formatSopsPointerFile([]ipc.SopsIdentityInfo{sampleInfo("work", "normal")}, []string{other, samplePointer})
	if !strings.Contains(out, other) {
		t.Fatalf("existing pointer dropped:\n%s", out)
	}
	if strings.Count(out, samplePointer) != 1 {
		t.Fatalf("duplicate pointer written:\n%s", out)
	}
}

// TestWriteSopsPointerFileKeepsBackup: the original lands at <path>.bak, byte for byte, and
// the rewritten file is 0600 — a keys.txt is world-readable often enough to be worth fixing
// on the way past.
func TestWriteSopsPointerFileKeepsBackup(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "keys.txt", sampleKey+"\n")
	original := []byte(sampleKey + "\n")

	if err := writeSopsPointerFile(path, "POINTER\n", original, true); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "POINTER\n" {
		t.Fatalf("rewritten file = %q, %v", got, err)
	}
	bak, err := os.ReadFile(path + sopsBackupSuffix)
	if err != nil || !bytes.Equal(bak, original) {
		t.Fatalf("backup = %q, %v", bak, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("keys.txt mode = %o, want 600", perm)
	}
}

// TestWriteSopsPointerFileNoBackup: declining the backup leaves no .bak behind — the whole
// point of declining is that the plaintext key stops existing on disk.
func TestWriteSopsPointerFileNoBackup(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "keys.txt", sampleKey+"\n")
	if err := writeSopsPointerFile(path, "POINTER\n", []byte(sampleKey+"\n"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + sopsBackupSuffix); !os.IsNotExist(err) {
		t.Fatalf("a backup was written after it was declined (err=%v)", err)
	}
}

// TestWriteSopsPointerFileLeavesNoTemp: the write goes through a temp file so a crash cannot
// leave a truncated keys.txt; the temp must not survive a successful write.
func TestWriteSopsPointerFileLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "keys.txt", sampleKey+"\n")
	if err := writeSopsPointerFile(path, "POINTER\n", nil, false); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "keys.txt" {
		t.Fatalf("stray files left behind: %v", entries)
	}
}

// TestAskSopsBackupDefaultsToKeeping: a bare Enter keeps the backup, "n" declines it, and
// with no terminal to ask at the backup is kept without asking. Every ambiguous answer
// resolves toward still having the key.
func TestAskSopsBackupDefaultsToKeeping(t *testing.T) {
	for _, tc := range []struct {
		in     string
		tty    bool
		backup bool
	}{
		{"\n", true, true},
		{"y\n", true, true},
		{"maybe\n", true, true},
		{"n\n", true, false},
		{"NO\n", true, false},
		{"", false, true}, // no TTY: keep, do not ask
	} {
		var out bytes.Buffer
		if got := askSopsBackup(strings.NewReader(tc.in), &out, tc.tty, "/k.txt"); got != tc.backup {
			t.Fatalf("askSopsBackup(%q, tty=%v) = %v, want %v", tc.in, tc.tty, got, tc.backup)
		}
	}
}

// TestSopsNothingFoundListsPaths: with neither env var set, every path that was checked is
// named — a user whose key is somewhere unusual can see at a glance that it was not looked
// at — and the way out for someone with no key at all is named too.
func TestSopsNothingFoundListsPaths(t *testing.T) {
	msg := sopsNothingFoundMessage([]string{"/a/keys.txt", "/b/keys.txt"}, false, false, "/a/keys.txt")
	for _, want := range []string{"/a/keys.txt", "/b/keys.txt", "av sops keygen"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message missing %q:\n%s", want, msg)
		}
	}
}

// TestSopsNothingFoundExplainsEnvKey: "found nothing" is not "you have no key". A user with
// SOPS_AGE_KEY set has a working sops and no keys.txt by design, and telling them a file is
// missing sends them hunting for one that was never supposed to exist.
func TestSopsNothingFoundExplainsEnvKey(t *testing.T) {
	msg := sopsNothingFoundMessage([]string{"/a/keys.txt"}, true, false, "/a/keys.txt")
	for _, want := range []string{"SOPS_AGE_KEY is set", "unset SOPS_AGE_KEY", "/a/keys.txt", "av sops import"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message missing %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "SOPS_AGE_KEY_CMD") {
		t.Fatalf("SOPS_AGE_KEY_CMD is not set here and must not be mentioned:\n%s", msg)
	}
}

// TestSopsNothingFoundExplainsEnvCmd: same for the command form, whose key is not even in
// the environment — it is whatever the command prints.
func TestSopsNothingFoundExplainsEnvCmd(t *testing.T) {
	msg := sopsNothingFoundMessage([]string{"/a/keys.txt"}, false, true, "/a/keys.txt")
	for _, want := range []string{"SOPS_AGE_KEY_CMD is set", "unset SOPS_AGE_KEY_CMD", "/a/keys.txt"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message missing %q:\n%s", want, msg)
		}
	}
}

// TestSopsNothingFoundTakesBoolsNotValues is a structural check, and the reason the signature
// is shaped the way it is. SOPS_AGE_KEY holds a private key and SOPS_AGE_KEY_CMD can hold one
// too (`echo AGE-SECRET-KEY-1…`), so this function is given BOOLEANS: it cannot print a value
// it was never handed, whatever anyone later adds to its text. The shell lines it prints
// expand the variables at the user's prompt instead.
func TestSopsNothingFoundTakesBoolsNotValues(t *testing.T) {
	t.Setenv("SOPS_AGE_KEY", sampleKey)
	msg := sopsNothingFoundMessage([]string{"/a/keys.txt"}, true, true, "/a/keys.txt")
	if strings.Contains(msg, sampleKey) {
		t.Fatalf("message echoed the key material in SOPS_AGE_KEY:\n%s", msg)
	}
	if !strings.Contains(msg, `"$SOPS_AGE_KEY"`) {
		t.Fatalf("message should expand the variable at the user's shell:\n%s", msg)
	}
}

// TestFormatSopsImportDone: the summary names every stored identity and, when a backup was
// kept, says plainly that the plaintext key is still sitting in it. "It never deletes a key
// silently" cuts both ways — the copy it did NOT delete has to be named too.
func TestFormatSopsImportDone(t *testing.T) {
	infos := []ipc.SopsIdentityInfo{sampleInfo("work", "normal")}
	withBackup := formatSopsImportDone("/k.txt", infos, true)
	for _, want := range []string{"work", "/k.txt", "/k.txt" + sopsBackupSuffix, "STILL"} {
		if !strings.Contains(withBackup, want) {
			t.Fatalf("summary missing %q:\n%s", want, withBackup)
		}
	}
	if strings.Contains(formatSopsImportDone("/k.txt", infos, false), sopsBackupSuffix) {
		t.Fatal("no backup was kept; the summary must not mention one")
	}
}

// TestPutSopsKeysAllOrNothing is the partial-failure decision, pinned. Two keys means two
// sops_put calls with no transaction between them, so when the second fails the first is
// already in the vault. putSopsKeys reports exactly what landed and returns the error, and
// the caller rewrites NOTHING: the file is still the only copy of the key that did not
// store, and a keys.txt holding one pointer and one plaintext key is a state neither the
// user nor a later import can reason about.
func TestPutSopsKeysAllOrNothing(t *testing.T) {
	p := &fakePutter{failOn: 2}
	infos, err := putSopsKeys(p, []string{"a", "b", "c"}, [][]byte{[]byte(sampleKey), []byte(sampleKey), []byte(sampleKey)})
	if err == nil {
		t.Fatal("want the second put's error")
	}
	if len(infos) != 1 || infos[0].Name != "a" {
		t.Fatalf("stored = %+v, want exactly the one that landed", infos)
	}
	if p.calls != 2 {
		t.Fatalf("calls = %d, want 2 (stop at the first failure)", p.calls)
	}
}

// TestPutSopsKeysSendsEmptyTier: import never sends a tier. Empty means the documented
// default on a create, and on a REPLACE the daemon carries the STORED tier forward — so an
// import over a dangerous-tier identity cannot silently demote it to normal.
func TestPutSopsKeysSendsEmptyTier(t *testing.T) {
	p := &fakePutter{}
	if _, err := putSopsKeys(p, []string{"a"}, [][]byte{[]byte(sampleKey)}); err != nil {
		t.Fatal(err)
	}
	if p.tiers[0] != "" {
		t.Fatalf("tier = %q, want empty so the daemon decides", p.tiers[0])
	}
}

// TestImportSopsKeysRewritesTheFileItReadFrom is the SOPS_AGE_KEY_FILE hazard, pinned. The
// pointer must land in the file the key came from — here a --from path — and NOT in the
// user-config-dir keys.txt that config.SopsKeysFilePath() would name. sops opens both (the
// env var is additive, not an override), so a pointer written to the wrong one leaves the
// plaintext key on disk still decrypting everything, with the plugin never exercised and the
// import reporting success.
func TestImportSopsKeysRewritesTheFileItReadFrom(t *testing.T) {
	dir := t.TempDir()
	src := writeFile(t, dir, "mine.txt", "# mine\n"+sampleKey+"\n")
	other := writeFile(t, dir, "keys.txt", sampleKey+"\n")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}

	source := sopsImportSource{path: src, data: data}
	stored, err := importSopsKeys(&fakePutter{}, source, []string{"work"}, [][]byte{[]byte(sampleKey)}, true)
	if err != nil || len(stored) != 1 {
		t.Fatalf("importSopsKeys = %+v, %v", stored, err)
	}

	got, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), samplePointer) || strings.Contains(string(got), sampleKey) {
		t.Fatalf("the file the key came from was not turned into a pointer file:\n%s", got)
	}
	// The config-dir file is somebody else's and must not have been touched.
	untouched, err := os.ReadFile(other)
	if err != nil || string(untouched) != sampleKey+"\n" {
		t.Fatalf("a file that was not the source got rewritten: %q, %v", untouched, err)
	}
}

// TestImportSopsKeysLeavesFileOnPartialFailure is the partial-failure rule end to end: the
// second put fails, so the source file is byte-for-byte what it was and no backup or temp
// was left behind. The file is still the only copy of the key that did not store.
func TestImportSopsKeysLeavesFileOnPartialFailure(t *testing.T) {
	dir := t.TempDir()
	const content = sampleKey + "\n" + sampleKey + "2\n"
	src := writeFile(t, dir, "keys.txt", content)

	source := sopsImportSource{path: src, data: []byte(content)}
	stored, err := importSopsKeys(&fakePutter{failOn: 2}, source,
		[]string{"a", "b"}, [][]byte{[]byte(sampleKey), []byte(sampleKey + "2")}, true)
	if err == nil {
		t.Fatal("want the failed put's error")
	}
	if len(stored) != 1 {
		t.Fatalf("stored = %+v, want the one that landed", stored)
	}
	got, err := os.ReadFile(src)
	if err != nil || string(got) != content {
		t.Fatalf("the keys file was modified after a partial import:\n%s", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("a failed import left files behind: %v", entries)
	}
}

// TestImportSopsKeysRewriteFailureIsDistinct: a store that succeeded and a rewrite that did
// not is a different outcome from a failed store — the keys ARE in the vault and only the
// file is wrong — so it carries a marker the caller can branch on to say the recoverable
// thing rather than "import failed".
func TestImportSopsKeysRewriteFailureIsDistinct(t *testing.T) {
	dir := t.TempDir()
	// A directory where the keys file should be: the rewrite cannot replace it.
	path := filepath.Join(dir, "keys.txt")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	source := sopsImportSource{path: path}
	stored, err := importSopsKeys(&fakePutter{}, source, []string{"a"}, [][]byte{[]byte(sampleKey)}, false)
	if !errors.Is(err, errSopsRewrite) {
		t.Fatalf("err = %v, want it marked as a rewrite failure", err)
	}
	if len(stored) != 1 {
		t.Fatalf("stored = %+v; the key did land and the caller has to be told", stored)
	}
}

// fakePutter records the SopsPut calls `av sops import` makes and can fail the nth one.
type fakePutter struct {
	calls  int
	failOn int // 1-based call index to fail on; 0 never fails
	tiers  []string
}

func (f *fakePutter) SopsPut(name, tier string, key []byte) (ipc.SopsIdentityInfo, error) {
	f.calls++
	f.tiers = append(f.tiers, tier)
	if f.failOn == f.calls {
		return ipc.SopsIdentityInfo{}, &ipc.RPCError{Code: ipc.CodeBadRequest, Message: "sops import: nope"}
	}
	return sampleInfo(name, "normal"), nil
}
