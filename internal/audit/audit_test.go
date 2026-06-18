package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestEventHasNoValueField is the STRUCTURAL no-secret guarantee: the Event type must
// expose no field that could hold a secret value. We assert the exact field set so a
// future "Value"/"Secret" field can never be added without breaking this test.
func TestEventHasNoValueField(t *testing.T) {
	want := map[string]bool{"Time": true, "Kind": true, "Name": true, "Tier": true, "Profile": true, "Detail": true}
	rt := reflect.TypeOf(Event{})
	if rt.NumField() != len(want) {
		t.Fatalf("Event has %d fields, want %d (no value field allowed)", rt.NumField(), len(want))
	}
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		if !want[name] {
			t.Fatalf("SECURITY: Event has unexpected field %q — a value-bearing field is forbidden", name)
		}
		lower := strings.ToLower(name)
		if strings.Contains(lower, "value") || strings.Contains(lower, "secret") {
			t.Fatalf("SECURITY: Event field %q looks value-bearing", name)
		}
	}
}

// readLines reads the JSONL file and returns its non-empty lines.
func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// TestFileLoggerAppendsOnePerLog: each Log writes exactly one JSONL line with the
// expected fields parsed back.
func TestFileLoggerAppendsOnePerLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	l.now = func() time.Time { return time.Unix(1_700_000_000, 0) }

	l.Log(Event{Kind: "issue", Name: "GITHUB_TOKEN", Tier: "normal", Profile: "smoke"})
	l.Log(Event{Kind: "unlock"})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	lines := readLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %q", len(lines), lines)
	}
	var e Event
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatal(err)
	}
	if e.Kind != "issue" || e.Name != "GITHUB_TOKEN" || e.Tier != "normal" || e.Profile != "smoke" {
		t.Fatalf("first entry wrong: %+v", e)
	}
	if e.Time == "" {
		t.Fatal("logger must stamp a time when none is set")
	}
}

// TestFileLoggerAppendOnlyAcrossReopen: reopening the same path PRESERVES existing
// lines and appends after them (append-only, O_APPEND).
func TestFileLoggerAppendOnlyAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	l1, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	l1.Log(Event{Kind: "issue", Name: "A"})
	l1.Close()

	l2, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	l2.Log(Event{Kind: "lock"})
	l2.Close()

	lines := readLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("append-only: want 2 lines after reopen, got %d: %q", len(lines), lines)
	}
	if !strings.Contains(lines[0], `"name":"A"`) {
		t.Fatalf("first (pre-existing) line must be preserved, got %q", lines[0])
	}
	if !strings.Contains(lines[1], `"kind":"lock"`) {
		t.Fatalf("second line must be appended after the first, got %q", lines[1])
	}
}

// TestFileLoggerMode0600: the audit file must be created mode 0600 (never readable
// by other users).
func TestFileLoggerMode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.Log(Event{Kind: "issue"})

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("audit file mode = %o, want 0600", perm)
	}
}

// TestFileLoggerConcurrent: concurrent Log calls must each produce one well-formed
// line with no interleaving (mutex-serialized writes). Run with -race.
func TestFileLoggerConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Log(Event{Kind: "issue", Name: "X"})
		}()
	}
	wg.Wait()

	lines := readLines(t, path)
	if len(lines) != n {
		t.Fatalf("want %d lines, got %d", n, len(lines))
	}
	for _, ln := range lines {
		var e Event
		if err := json.Unmarshal([]byte(ln), &e); err != nil {
			t.Fatalf("interleaved/garbled line %q: %v", ln, err)
		}
	}
}

// TestNopLoggerDiscards: the default sink must not panic and must write nothing.
func TestNopLoggerDiscards(t *testing.T) {
	var l Logger = NopLogger{}
	l.Log(Event{Kind: "issue", Name: "X"}) // must be a no-op
}
