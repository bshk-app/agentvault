package client

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeEnvFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestEnvRunInjectsAndMasks: a .env with one av:// ref + one literal → the child sees
// the resolved value in its env (proved by writing it to a file the test reads) and the
// masked value on stdout ({{AV:S}}), while the literal passes through.
func TestEnvRunInjectsAndMasks(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	cl := newRunServer(t)
	out := filepath.Join(t.TempDir(), "seen.txt")
	env := writeEnvFile(t, "S=av://mock/S\nPLAIN=hello\n")

	var stdout, stderr bytes.Buffer
	// The child echoes $S (masked on stdout) and writes $S+$PLAIN to a file (unmasked,
	// proving real injection of both the resolved ref and the literal).
	code, err := EnvRun(cl, EnvOptions{
		EnvFilePath: env,
		Command:     []string{"sh", "-c", "echo $S; printf '%s' \"$S:$PLAIN\" > " + out},
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("EnvRun: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if strings.Contains(stdout.String(), "topsecret") {
		t.Fatalf("SECURITY: secret leaked to stdout: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "{{AV:S}}") {
		t.Fatalf("stdout should show the masked ref, got %q", stdout.String())
	}
	b, _ := os.ReadFile(out)
	if string(b) != "topsecret:hello" {
		t.Fatalf("child env = %q, want topsecret:hello (ref resolved + literal injected)", b)
	}
}

// TestEnvRunNoSourcesErrors: neither .env nor agentvault.yaml → fail-closed, no child.
func TestEnvRunNoSourcesErrors(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	cl := newRunServer(t)
	dir := t.TempDir()
	code, err := EnvRun(cl, EnvOptions{
		EnvFilePath:  filepath.Join(dir, ".env"),             // absent
		ManifestPath: filepath.Join(dir, "agentvault.yaml"), // absent
		Command:      []string{"sh", "-c", "echo nope"},
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected an error when neither .env nor agentvault.yaml exists")
	}
	if code == 0 {
		t.Fatalf("exit = %d, want non-zero", code)
	}
}

// TestEnvRunNoMask: with NoMask the resolved value passes through unmasked.
func TestEnvRunNoMask(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	cl := newRunServer(t)
	env := writeEnvFile(t, "S=av://mock/S\n")
	var stdout bytes.Buffer
	code, err := EnvRun(cl, EnvOptions{
		EnvFilePath: env,
		NoMask:      true,
		Command:     []string{"sh", "-c", "echo $S"},
	}, &stdout, &bytes.Buffer{})
	if err != nil || code != 0 {
		t.Fatalf("EnvRun: code=%d err=%v", code, err)
	}
	if !strings.Contains(stdout.String(), "topsecret") {
		t.Fatalf("--no-mask should pass the value through, got %q", stdout.String())
	}
}
