# AgentVault Phase 1 — Redaction Core Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build and prove the redaction library — the novel, highest-risk part of AgentVault — in full isolation, before any IPC, daemon, or backend exists.

**Architecture:** A pure Go package (`internal/redact`) that masks known secret values (and their common encodings) in both whole strings and byte streams, plus a verified gitleaks adapter for derived/unknown secrets. The streaming redactor uses an overlap buffer so a value split across two writes is still caught. Both enforcement layers from the design (layer 1 in `av run`, layer 2 in `av scrub`/`avd`) will later reuse this one package — DRY.

**Tech Stack:** Go 1.23+, standard library only for Phase 1 (no test framework dep — table-driven `testing`), `github.com/zricethezav/gitleaks/v8` evaluated as a library in the spike. Module path `github.com/beshkenadze/agentvault` (adjust to your real remote).

**Scope of this plan:** Phase 1 only. Subsequent phases are listed in *Roadmap* and each gets its own detailed plan when reached.

**Design reference:** `docs/plans/2026-06-17-agentvault-design.md` — see *Redaction pipeline* and *Implementation risks*.

---

## Task 1: Project skeleton

**Files:**
- Create: `go.mod`
- Create: `Makefile`
- Create: `.gitignore`
- Create: `internal/redact/doc.go`

**Step 1: Initialize the module**

Run:
```bash
cd /Volumes/DATA/agent-vault
go mod init github.com/beshkenadze/agentvault
```
Expected: creates `go.mod` with `go 1.23` (or your installed version).

**Step 2: Create `.gitignore`**

```gitignore
/bin/
*.test
*.out
.DS_Store
```

**Step 3: Create `Makefile`**

```makefile
.PHONY: test build vet
test:
	go test ./...
vet:
	go vet ./...
build:
	go build -o bin/avd ./cmd/avd
	go build -o bin/av ./cmd/av
```

**Step 4: Create `internal/redact/doc.go`**

```go
// Package redact masks known secret values, and values derived/leaked at runtime,
// in whole strings and in byte streams. It is the single redaction implementation
// shared by both enforcement layers (av run source masking and avd scrub service).
package redact
```

**Step 5: Verify the module builds**

Run: `go build ./...`
Expected: no output, exit 0.

**Step 6: Commit**

```bash
git add go.mod Makefile .gitignore internal/redact/doc.go
git commit -m "chore: project skeleton and redact package"
```

---

## Task 2: Exact-match on raw values (whole string)

**Files:**
- Create: `internal/redact/exact.go`
- Test: `internal/redact/exact_test.go`

**Step 1: Write the failing test**

`internal/redact/exact_test.go`:
```go
package redact

import "testing"

func TestMaskRawValue(t *testing.T) {
	m := NewMatcher([]Secret{{Name: "TOKEN", Value: "s3cr3t-value"}})
	got := m.Mask("the token is s3cr3t-value here")
	want := "the token is {{AV:TOKEN}} here"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMaskNoMatchUnchanged(t *testing.T) {
	m := NewMatcher([]Secret{{Name: "TOKEN", Value: "s3cr3t-value"}})
	in := "nothing secret here"
	if got := m.Mask(in); got != in {
		t.Fatalf("got %q, want unchanged %q", got, in)
	}
}

func TestEmptyValueIgnored(t *testing.T) {
	m := NewMatcher([]Secret{{Name: "EMPTY", Value: ""}})
	in := "" // an empty needle must never match and blank everything
	_ = in
	if got := m.Mask("abc"); got != "abc" {
		t.Fatalf("empty value should not mask: got %q", got)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/redact/ -run TestMask -v`
Expected: FAIL — `NewMatcher`, `Secret`, `Mask` undefined.

**Step 3: Write minimal implementation**

`internal/redact/exact.go`:
```go
package redact

import (
	"sort"
	"strings"
)

// Secret is one named value to redact.
type Secret struct {
	Name  string
	Value string
}

// Matcher masks known secret values, replacing each with {{AV:NAME}}.
type Matcher struct {
	forms   map[string]string // exact form -> placeholder
	ordered []string          // forms, longest first
	maxLen  int
}

// NewMatcher builds a matcher over the raw values only (encodings added in Task 3).
func NewMatcher(secrets []Secret) *Matcher {
	m := &Matcher{forms: map[string]string{}}
	for _, s := range secrets {
		if s.Value == "" {
			continue
		}
		placeholder := "{{AV:" + s.Name + "}}"
		for _, form := range formsFor(s.Value) {
			if form == "" {
				continue
			}
			if _, ok := m.forms[form]; !ok {
				m.forms[form] = placeholder
			}
		}
	}
	for f := range m.forms {
		m.ordered = append(m.ordered, f)
		if len(f) > m.maxLen {
			m.maxLen = len(f)
		}
	}
	sort.Slice(m.ordered, func(i, j int) bool { return len(m.ordered[i]) > len(m.ordered[j]) })
	return m
}

// formsFor returns every wire form of a value that should be masked.
// Task 2 masks only the raw value; Task 3 extends this.
func formsFor(v string) []string { return []string{v} }

// MaxFormLen is the longest masked form. Stream buffers overlap by at least this-1.
func (m *Matcher) MaxFormLen() int { return m.maxLen }

// Mask replaces every known form in s, longest forms first.
func (m *Matcher) Mask(s string) string {
	for _, form := range m.ordered {
		if strings.Contains(s, form) {
			s = strings.ReplaceAll(s, form, m.forms[form])
		}
	}
	return s
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/redact/ -run TestMask -v`
Expected: PASS (all three).

**Step 5: Commit**

```bash
git add internal/redact/exact.go internal/redact/exact_test.go
git commit -m "feat(redact): exact-match masking of raw values"
```

---

## Task 3: Encoding-aware matching

Masks base64 (4 variants), hex, URL-encoding, and JSON-escaping of each value — a secret that passed through the vault must be caught even after the subprocess re-encodes it.

**Files:**
- Modify: `internal/redact/exact.go` (replace `formsFor`)
- Create: `internal/redact/encodings.go`
- Test: `internal/redact/encodings_test.go`

**Step 1: Write the failing test**

`internal/redact/encodings_test.go`:
```go
package redact

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"testing"
)

func TestMaskEncodings(t *testing.T) {
	val := "AKIA-secret/key+v1"
	m := NewMatcher([]Secret{{Name: "K", Value: val}})

	cases := map[string]string{
		"raw":       val,
		"b64std":    base64.StdEncoding.EncodeToString([]byte(val)),
		"b64url":    base64.URLEncoding.EncodeToString([]byte(val)),
		"b64rawstd": base64.RawStdEncoding.EncodeToString([]byte(val)),
		"hex":       hex.EncodeToString([]byte(val)),
		"urlquery":  url.QueryEscape(val),
	}
	for name, enc := range cases {
		in := "prefix " + enc + " suffix"
		if got := m.Mask(in); got == in {
			t.Errorf("%s: form %q was not masked", name, enc)
		}
	}
}

func TestMaskJSONEscaped(t *testing.T) {
	val := `line"with\slash`
	m := NewMatcher([]Secret{{Name: "J", Value: val}})
	// how the value appears inside a JSON string literal
	in := `{"k":"line\"with\\slash"}`
	if got := m.Mask(in); got == in {
		t.Fatalf("json-escaped form not masked: %q", got)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/redact/ -run TestMaskEncodings -v`
Expected: FAIL — only `raw` masks; encoded forms unchanged.

**Step 3: Write the implementation**

`internal/redact/encodings.go`:
```go
package redact

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
)

// allForms returns the raw value plus every encoding we mask.
func allForms(v string) []string {
	b := []byte(v)
	return []string{
		v,
		base64.StdEncoding.EncodeToString(b),
		base64.RawStdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b),
		base64.RawURLEncoding.EncodeToString(b),
		hex.EncodeToString(b),
		url.QueryEscape(v),
		jsonInner(v),
	}
}

// jsonInner returns the value as it appears inside a JSON string, without the quotes.
func jsonInner(v string) string {
	enc, err := json.Marshal(v)
	if err != nil || len(enc) < 2 {
		return ""
	}
	return string(enc[1 : len(enc)-1])
}
```

In `internal/redact/exact.go`, replace `formsFor` with a call to `allForms`:
```go
// delete formsFor; in NewMatcher change:
//   for _, form := range formsFor(s.Value) {
// to:
//   for _, form := range allForms(s.Value) {
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/redact/ -v`
Expected: PASS (Task 2 and Task 3 tests).

**Step 5: Commit**

```bash
git add internal/redact/encodings.go internal/redact/exact.go internal/redact/encodings_test.go
git commit -m "feat(redact): mask base64/hex/url/json encodings of secrets"
```

---

## Task 4: Streaming redactor with overlap buffer

The core correctness property: a secret split across two `Write` calls must still be masked. We retain raw bytes wherever the end of the buffer is a proper prefix of any known form, and flush the rest masked.

**Files:**
- Create: `internal/redact/stream.go`
- Modify: `internal/redact/exact.go` (add prefix helper to `Matcher`)
- Test: `internal/redact/stream_test.go`

**Step 1: Write the failing test**

`internal/redact/stream_test.go`:
```go
package redact

import (
	"bytes"
	"testing"
)

func writeChunks(m *Matcher, chunks ...string) string {
	var out bytes.Buffer
	r := NewStreamRedactor(m, &out)
	for _, c := range chunks {
		if _, err := r.Write([]byte(c)); err != nil {
			panic(err)
		}
	}
	if err := r.Close(); err != nil {
		panic(err)
	}
	return out.String()
}

func TestStreamWholeValue(t *testing.T) {
	m := NewMatcher([]Secret{{Name: "T", Value: "ghp_ABCDEFG"}})
	if got := writeChunks(m, "x ghp_ABCDEFG y"); got != "x {{AV:T}} y" {
		t.Fatalf("got %q", got)
	}
}

func TestStreamSplitAcrossWrites(t *testing.T) {
	m := NewMatcher([]Secret{{Name: "T", Value: "ghp_ABCDEFG"}})
	// secret straddles the chunk boundary
	if got := writeChunks(m, "x ghp_AB", "CDEFG y"); got != "x {{AV:T}} y" {
		t.Fatalf("split value leaked: got %q", got)
	}
}

func TestStreamByteByByte(t *testing.T) {
	m := NewMatcher([]Secret{{Name: "T", Value: "ghp_ABCDEFG"}})
	chunks := make([]string, 0)
	for _, c := range "x ghp_ABCDEFG y" {
		chunks = append(chunks, string(c))
	}
	if got := writeChunks(m, chunks...); got != "x {{AV:T}} y" {
		t.Fatalf("byte-split value leaked: got %q", got)
	}
}

func TestStreamNoFalseRetain(t *testing.T) {
	m := NewMatcher([]Secret{{Name: "T", Value: "ghp_ABCDEFG"}})
	in := "completely unrelated output text\n"
	if got := writeChunks(m, in); got != in {
		t.Fatalf("got %q, want unchanged", got)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/redact/ -run TestStream -v`
Expected: FAIL — `NewStreamRedactor` undefined.

**Step 3: Add the prefix helper to `Matcher`**

Append to `internal/redact/exact.go`:
```go
// hasFormWithPrefix reports whether some known form is strictly longer than s and
// begins with s. Used by the streaming redactor to decide what to retain.
func (m *Matcher) hasFormWithPrefix(s string) bool {
	for _, form := range m.ordered {
		if len(form) > len(s) && strings.HasPrefix(form, s) {
			return true
		}
	}
	return false
}
```

**Step 4: Write the streaming redactor**

`internal/redact/stream.go`:
```go
package redact

import "io"

// StreamRedactor masks secrets in a byte stream and forwards masked output to w.
// It retains the trailing bytes that could still grow into a known form, so a value
// split across writes is caught. Always call Close to flush the final tail.
type StreamRedactor struct {
	m    *Matcher
	w    io.Writer
	tail []byte
}

func NewStreamRedactor(m *Matcher, w io.Writer) *StreamRedactor {
	return &StreamRedactor{m: m, w: w}
}

func (r *StreamRedactor) Write(p []byte) (int, error) {
	buf := append(r.tail, p...)
	cut := r.retainStart(buf)
	if cut > 0 {
		if _, err := io.WriteString(r.w, r.m.Mask(string(buf[:cut]))); err != nil {
			return 0, err
		}
	}
	r.tail = append(r.tail[:0], buf[cut:]...)
	return len(p), nil
}

// Close flushes the retained tail, masking it fully (no more data can arrive).
func (r *StreamRedactor) Close() error {
	if len(r.tail) == 0 {
		return nil
	}
	_, err := io.WriteString(r.w, r.m.Mask(string(r.tail)))
	r.tail = nil
	return err
}

// retainStart returns the earliest index i such that buf[i:] is a proper prefix of
// some known form. Everything before i is safe to mask and emit now. If nothing at
// the tail could grow into a form, the whole buffer is safe (returns len(buf)).
func (r *StreamRedactor) retainStart(buf []byte) int {
	start := len(buf) - r.m.MaxFormLen() + 1
	if start < 0 {
		start = 0
	}
	for i := start; i < len(buf); i++ {
		if r.m.hasFormWithPrefix(string(buf[i:])) {
			return i
		}
	}
	return len(buf)
}
```

**Step 5: Run tests to verify they pass**

Run: `go test ./internal/redact/ -v`
Expected: PASS (all redact tests).

**Step 6: Commit**

```bash
git add internal/redact/stream.go internal/redact/exact.go internal/redact/stream_test.go
git commit -m "feat(redact): streaming redactor with overlap buffer"
```

---

## Task 5: Golden tests for the encoding matrix over a stream

Locks behavior with a data file so future refactors can't regress masking. Combines streaming + encodings + boundary splits.

**Files:**
- Create: `internal/redact/testdata/golden_input.txt`
- Create: `internal/redact/testdata/golden_want.txt`
- Test: `internal/redact/golden_test.go`

**Step 1: Create the golden input**

`internal/redact/testdata/golden_input.txt` (contains the literal secret `SECRET_VALUE_123` in several forms; build it so each form is on its own line):
```
raw: SECRET_VALUE_123
b64: U0VDUkVUX1ZBTFVFXzEyMw==
hex: 5345435245545f56414c55455f313233
url: SECRET_VALUE_123
unrelated commit hash: 7d374bbf00ddeadbeef
```

**Step 2: Create the expected output**

`internal/redact/testdata/golden_want.txt`:
```
raw: {{AV:S}}
b64: {{AV:S}}
hex: {{AV:S}}
url: {{AV:S}}
unrelated commit hash: 7d374bbf00ddeadbeef
```

**Step 3: Write the golden test (chunked at every size)**

`internal/redact/golden_test.go`:
```go
package redact

import (
	"bytes"
	"os"
	"testing"
)

func TestGoldenAllChunkSizes(t *testing.T) {
	in, err := os.ReadFile("testdata/golden_input.txt")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/golden_want.txt")
	if err != nil {
		t.Fatal(err)
	}
	m := NewMatcher([]Secret{{Name: "S", Value: "SECRET_VALUE_123"}})

	for size := 1; size <= len(in); size++ {
		var out bytes.Buffer
		r := NewStreamRedactor(m, &out)
		for i := 0; i < len(in); i += size {
			end := i + size
			if end > len(in) {
				end = len(in)
			}
			if _, err := r.Write(in[i:end]); err != nil {
				t.Fatal(err)
			}
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out.Bytes(), want) {
			t.Fatalf("chunk size %d: leak or mismatch\n got: %q\nwant: %q", size, out.String(), want)
		}
	}
}
```

**Step 4: Run the golden test**

Run: `go test ./internal/redact/ -run TestGolden -v`
Expected: PASS for every chunk size 1..N (proves no boundary leaks).

> If a chunk size fails, the overlap logic in Task 4 is wrong — fix `retainStart`/`Close`, do not edit the golden files to match buggy output.

**Step 5: Commit**

```bash
git add internal/redact/testdata internal/redact/golden_test.go
git commit -m "test(redact): golden encoding matrix across all chunk sizes"
```

---

## Task 6: SPIKE — verify gitleaks usable as a library (decision gate)

**This is a verification task, not TDD.** The design's *Implementation risks* flag that gitleaks targets git-repo scanning, not streaming string redaction. Confirm before committing layer 2 to it.

Relevant skill: @verify-known-issues:verify-known-issues for confirming the API surface. Use context7 (`/zricethezav/gitleaks` if resolvable) or read the package source for `detect.Detector` + `DetectString`/`Detect`.

**Files:**
- Create: `internal/redact/gitleaks_spike_test.go` (temporary, may be deleted after decision)

**Step 1: Add the dependency**

Run:
```bash
go get github.com/zricethezav/gitleaks/v8@latest
```
Expected: resolves and updates `go.mod`/`go.sum`. If it fails or pulls a huge/incompatible tree, record that — it is itself a finding.

**Step 2: Write a probe test**

`internal/redact/gitleaks_spike_test.go`:
```go
package redact

import (
	"testing"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// TestGitleaksDetectsString probes whether gitleaks can scan an in-memory string
// (no git, no filesystem) and return findings. This is the API layer 2 needs.
func TestGitleaksDetectsString(t *testing.T) {
	vc := config.DefaultConfig // or config.ViperConfig{} -> Translate(); confirm exact name
	cfg, err := vc.Translate()
	if err != nil {
		t.Skipf("cannot build default config (record exact API): %v", err)
	}
	d := detect.NewDetector(cfg)
	findings := d.DetectString("token github ghp_0123456789abcdefABCDEF0123456789abcd")
	if len(findings) == 0 {
		t.Fatalf("gitleaks found nothing on an obvious token; API or rules unusable for layer 2")
	}
	for _, f := range findings {
		t.Logf("rule=%s start=%d end=%d", f.RuleID, f.StartColumn, f.EndColumn)
	}
}
```

> Method/type names above are best-effort. The task is to make this compile and pass against the real package. Adjust to the actual API discovered.

**Step 3: Run the probe**

Run: `go test ./internal/redact/ -run TestGitleaks -v`
Expected: PASS with at least one finding, OR a clear failure that tells us the API is unusable.

**Step 4: Record the decision**

Append a short note to `docs/plans/2026-06-17-agentvault-design.md` under *Implementation risks* stating one of:
- **GO:** gitleaks exposes `DetectString` (offsets usable for masking) → layer 2 embeds it.
- **NO-GO:** API needs files/git or gives no offsets → fall back to vendoring its rule regexes into our own scanner; open a follow-up task.

**Step 5: Commit**

```bash
git add go.mod go.sum docs/plans/2026-06-17-agentvault-design.md internal/redact/gitleaks_spike_test.go
git commit -m "spike(redact): verify gitleaks usable as in-memory detection library"
```

---

## Task 7: Redactor service interface (the unit avd/av will host)

A small interface that composes exact-match (always) with the gitleaks tier (default on), masking gitleaks findings with `{{AV:REDACTED:<rule>}}`. Keeps both enforcement layers calling one thing — DRY.

> If Task 6 was NO-GO, implement only the exact-match tier here and leave a TODO for the vendored-rules scanner. Do not block Phase 1 on gitleaks.

**Files:**
- Create: `internal/redact/redactor.go`
- Test: `internal/redact/redactor_test.go`

**Step 1: Write the failing test**

`internal/redact/redactor_test.go`:
```go
package redact

import "testing"

func TestRedactorExactTier(t *testing.T) {
	r := NewRedactor([]Secret{{Name: "T", Value: "ghp_ABCDEFG"}}, Options{Gitleaks: false})
	if got := r.Redact("see ghp_ABCDEFG"); got != "see {{AV:T}}" {
		t.Fatalf("got %q", got)
	}
}

func TestRedactorGitleaksTier(t *testing.T) {
	// a token never issued this session: exact-match can't know it; gitleaks should.
	r := NewRedactor(nil, Options{Gitleaks: true})
	in := "leaked ghp_0123456789abcdefABCDEF0123456789abcd here"
	got := r.Redact(in)
	if got == in {
		t.Skip("enable only if Task 6 was GO; otherwise expected to be unchanged")
	}
	if !contains(got, "{{AV:REDACTED") {
		t.Fatalf("gitleaks finding not masked with placeholder: %q", got)
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (indexOf(s, sub) >= 0) }
func indexOf(s, sub string) int   { return len([]rune(s)) - len([]rune(s)) + stdIndex(s, sub) }
```

> Simplify the helper to `strings.Contains` — the awkward helpers above are intentionally a smell to remove; use the stdlib.

**Step 2: Run test to verify it fails**

Run: `go test ./internal/redact/ -run TestRedactor -v`
Expected: FAIL — `NewRedactor`, `Options`, `Redact` undefined.

**Step 3: Write the implementation**

`internal/redact/redactor.go`:
```go
package redact

// Options configures which tiers run.
type Options struct {
	Gitleaks bool // run the gitleaks tier after exact-match (default on in production)
}

// Redactor composes the exact-match tier with the gitleaks tier.
type Redactor struct {
	exact *Matcher
	opts  Options
	// gl holds the gitleaks detector if Task 6 was GO; nil otherwise.
}

func NewRedactor(secrets []Secret, opts Options) *Redactor {
	return &Redactor{exact: NewMatcher(secrets), opts: opts}
}

// Redact masks a whole string. (Streaming wrapper added when wiring av scrub.)
func (r *Redactor) Redact(s string) string {
	s = r.exact.Mask(s)
	if r.opts.Gitleaks {
		s = r.maskGitleaks(s) // implemented per Task 6 outcome
	}
	return s
}
```

Add `maskGitleaks` in a build-tagged or plain file depending on the Task 6 decision; for NO-GO make it `func (r *Redactor) maskGitleaks(s string) string { return s }` with a TODO.

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/redact/ -v`
Expected: PASS (gitleaks sub-test skips if NO-GO).

**Step 5: Commit**

```bash
git add internal/redact/redactor.go internal/redact/redactor_test.go
git commit -m "feat(redact): Redactor composing exact-match and gitleaks tiers"
```

---

## Phase 1 done — definition of done

- `go test ./...` green, including the golden test across **all** chunk sizes.
- `go vet ./...` clean.
- The redaction guarantee is provable in isolation: every encoding masked, no boundary leaks.
- A recorded GO/NO-GO decision on gitleaks-as-library.

---

## Roadmap (subsequent phases — each gets its own detailed plan)

**Phase 2 — IPC walking skeleton.** `cmd/avd` listens on a unix socket (`0600`) in `$XDG_RUNTIME_DIR`; newline-delimited JSON-RPC; peer-cred check via `getpeereid` (macOS); `cmd/av` connects and `ping`s; `av` autostarts `avd`. Security regression tests: socket mode, peer-cred rejection.

**Phase 3 — Backends + manifest.** `Backend` interface; mock backend; `age`-file backend (`filippo.io/age`); `agentvault.yaml` parsing (profiles, refs, tiers); `av://` reference parser. Test auth stub `AV_TEST_AUTH=allow` (test builds only).

**Phase 4 — Session + `av run` (layers wired).** Resolve profile → values via `avd`; session store + TTL + auto-lock; `av run` injects env, forks child, wraps child stdout/stderr in `StreamRedactor` (layer 1); `av scrub` streams stdin→`avd` Redactor (layer 2). End-to-end test with the stub: agent sees `{{AV:NAME}}`, never the value.

**Phase 5 — Native auth + dangerous tier.** Touch ID via cgo (`LocalAuthentication`); `avd` as per-user GUI-session LaunchAgent; per-secret labeled prompts; never-cache/fresh-presence path; distinguishable exit codes when headless/denied.

**Phase 6 — Real backends + hardening + adapter.** 1Password (`op`), macOS Keychain (`go-keychain`); memguard (`mlock`, zeroize), Secure Enclave key wrap, hardened runtime/no-dump; rate limiting; append-only audit log; remaining CLI verbs (`lock`/`unlock`/`status`/`audit`/`ls`/`add`/`rm`); `av init --agent claude-code` generating hook + skill; `av read` non-TTY refusal test.

---

## Notes for the executing engineer

- **TDD is non-negotiable** here: the redactor is the security boundary. Red → green → commit, every task.
- **Never weaken a test to make it pass.** A failing chunk-size in the golden test means a real leak.
- **KISS first:** the exact-match scan is `strings.Contains`/`ReplaceAll`, not Aho-Corasick. Optimize only if a real profile size makes it slow (YAGNI).
- **DRY:** both enforcement layers must import this one package; do not reimplement masking in `av run`.
