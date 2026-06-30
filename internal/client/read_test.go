package client

import (
	"bytes"
	"strings"
	"testing"
)

// TestReadRefusesNonTTY is the load-bearing security regression: when stdout is
// NOT a terminal (a pipe/file), av read MUST write NOTHING of the value and
// return the distinct refusal exit code. An agent reading a secret through a
// pipe gets nothing — this is the deliberate guard from the design.
func TestReadRefusesNonTTY(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	cl := newRunServer(t)
	yaml := writeManifest(t)

	var out bytes.Buffer
	code, err := Read(cl, ReadOptions{
		Profile:      "smoke",
		ManifestPath: yaml,
		Name:         "SECRET",
	}, &out, false /* outIsTTY: a pipe/file */)
	// Refusal returns the distinct exit code AND a secret-free message for cmd/av
	// to print; the load-bearing assertion is that NOTHING of the value leaks.
	if code != exitReadRefused {
		t.Fatalf("exit code = %d, want %d (read-refused)", code, exitReadRefused)
	}
	if err == nil {
		t.Fatal("refusal must return a (secret-free) error message")
	}
	// SECURITY: the value must never reach a non-TTY sink — not in out, not in err.
	if strings.Contains(out.String(), "topsecret") {
		t.Fatalf("SECURITY: value leaked to non-TTY out: %q", out.String())
	}
	if out.Len() != 0 {
		t.Fatalf("SECURITY: refusal must write NOTHING to out; got %q", out.String())
	}
	if strings.Contains(err.Error(), "topsecret") {
		t.Fatalf("SECURITY: value leaked into the refusal message: %q", err.Error())
	}
}

// TestReadPrintsOnTTY proves the print branch: when stdout IS a terminal, the
// value is printed followed by a newline.
func TestReadPrintsOnTTY(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	cl := newRunServer(t)
	yaml := writeManifest(t)

	var out bytes.Buffer
	code, err := Read(cl, ReadOptions{
		Profile:      "smoke",
		ManifestPath: yaml,
		Name:         "SECRET",
	}, &out, true /* outIsTTY */)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if out.String() != "topsecret\n" {
		t.Fatalf("out = %q, want %q", out.String(), "topsecret\n")
	}
}

// TestReadDirectBackendNoManifest is the symmetry fix: a value added with
// `av add NAME` (the writable file backend) must be readable with `av read NAME`
// WITHOUT an agentvault.yaml. Direct mode addresses av://<backend>/<NAME> straight
// through the resolver — no manifest on disk (note: no writeManifest call here).
func TestReadDirectBackendNoManifest(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	cl := newRunServer(t)

	var out bytes.Buffer
	code, err := Read(cl, ReadOptions{Backend: "mock", Name: "S"}, &out, true /* outIsTTY */)
	if err != nil {
		t.Fatalf("direct read error: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if out.String() != "topsecret\n" {
		t.Fatalf("out = %q, want %q", out.String(), "topsecret\n")
	}
}

// TestReadDirectRefusesNonTTY: the security guard still holds in direct mode —
// reading to a pipe writes nothing of the value and returns the refusal code.
func TestReadDirectRefusesNonTTY(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	cl := newRunServer(t)

	var out bytes.Buffer
	code, err := Read(cl, ReadOptions{Backend: "mock", Name: "S"}, &out, false /* pipe */)
	if code != exitReadRefused {
		t.Fatalf("exit code = %d, want %d (read-refused)", code, exitReadRefused)
	}
	if err == nil {
		t.Fatal("refusal must return a (secret-free) error message")
	}
	if out.Len() != 0 || strings.Contains(out.String(), "topsecret") {
		t.Fatalf("SECURITY: refusal must write NOTHING to out; got %q", out.String())
	}
}

// TestReadMissingName errors (and prints no value) when the logical name is not
// in the resolved profile — even on a TTY, an absent name yields NO value.
func TestReadMissingName(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	cl := newRunServer(t)
	yaml := writeManifest(t)

	var out bytes.Buffer
	code, err := Read(cl, ReadOptions{
		Profile:      "smoke",
		ManifestPath: yaml,
		Name:         "NOPE",
	}, &out, true /* outIsTTY */)
	if err == nil {
		t.Fatal("missing name must error")
	}
	if code == 0 {
		t.Fatalf("exit code = %d, want non-zero on missing name", code)
	}
	if out.Len() != 0 {
		t.Fatalf("nothing should be written on missing name; out=%q", out.String())
	}
}
