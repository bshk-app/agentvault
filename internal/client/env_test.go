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
		EnvFilePath:  filepath.Join(dir, ".env"),            // absent
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

// TestEnvRunYamlOnlyFallback: with no .env but an agentvault.yaml present, the chosen
// profile (default smoke) carries the load — this is the only path that exercises the
// yaml merge loop feeding `entries`.
func TestEnvRunYamlOnlyFallback(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	cl := newRunServer(t)
	man := writeManifest(t) // smoke: SECRET -> av://mock/S
	seen := filepath.Join(t.TempDir(), "seen.txt")

	var stdout, stderr bytes.Buffer
	code, err := EnvRun(cl, EnvOptions{
		EnvFilePath:  filepath.Join(t.TempDir(), ".env"), // absent
		ManifestPath: man,
		Command:      []string{"sh", "-c", "printf '%s' \"$SECRET\" > " + seen},
	}, &stdout, &stderr)
	if err != nil || code != 0 {
		t.Fatalf("EnvRun (yaml-only): code=%d err=%v", code, err)
	}
	b, _ := os.ReadFile(seen)
	if string(b) != "topsecret" {
		t.Fatalf("SECRET not injected from the yaml profile: %q", b)
	}
}

// TestEnvRunConflictErrors: a NAME defined in BOTH .env and the yaml profile is a hard
// error — fail-closed, no child started (don't guess precedence / downgrade a tier).
func TestEnvRunConflictErrors(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	cl := newRunServer(t)
	man := writeManifest(t)                        // smoke defines SECRET
	env := writeEnvFile(t, "SECRET=av://mock/S\n") // .env also defines SECRET

	var stdout, stderr bytes.Buffer
	code, err := EnvRun(cl, EnvOptions{
		EnvFilePath:  env,
		ManifestPath: man,
		Command:      []string{"sh", "-c", "echo CHILD_RAN"},
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("a name in both .env and the yaml profile must hard-error")
	}
	if code == 0 {
		t.Fatalf("exit = %d, want non-zero on conflict", code)
	}
	if !strings.Contains(err.Error(), "SECRET") {
		t.Errorf("error %q should name the conflicting key", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("fail-closed: no child should run on conflict; stdout=%q", stdout.String())
	}
}
