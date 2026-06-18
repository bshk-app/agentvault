package client

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/daemon"
)

// runMockBE is a tiny in-test backend mapping locators to values, so the client
// package's run test can drive a real resolver without linking any production
// backend (av/client must stay backend-free; this mock lives only in _test.go).
type runMockBE struct{ data map[string]string }

func (m runMockBE) Resolve(loc string) (backend.Secret, error) {
	v, ok := m.data[loc]
	if !ok {
		return backend.Secret{}, backend.ErrNotFound
	}
	return backend.Secret{Value: v}, nil
}
func (runMockBE) List(string) ([]backend.Meta, error) { return nil, nil }

const runManifestYAML = `profiles:
  smoke:
    SECRET:
      ref: av://mock/S
      tier: normal
`

// newRunServer starts an in-process daemon on a short socket with a mock-backed
// resolver returning {"SECRET":"topsecret"} for profile "smoke", and returns a
// client bound to it. AV_TEST_AUTH=allow must be set by the caller.
func newRunServer(t *testing.T) *Client {
	t.Helper()
	path := shortSocketPath(t)
	srv, err := daemon.New(path)
	if err != nil {
		t.Fatal(err)
	}
	reg := backend.NewRegistry()
	reg.Register("mock", runMockBE{data: map[string]string{"S": "topsecret"}})
	srv.SetResolver(daemon.NewResolver(reg, daemon.NewStubAuthorizer(), daemon.NewSession(15*time.Minute)))
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	return New(path)
}

// writeManifest writes runManifestYAML to a temp file and returns its path.
func writeManifest(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agentvault.yaml")
	if err := os.WriteFile(p, []byte(runManifestYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestRunMasksChildOutput is the core proof: av run resolves SECRET=topsecret,
// injects it into the child's env (the echo proves receipt), and masks the
// child's stdout at the source — the agent sees {{AV:SECRET}}, never the value.
func TestRunMasksChildOutput(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	cl := newRunServer(t)
	yaml := writeManifest(t)

	var out, errOut bytes.Buffer
	code, err := Run(cl, RunOptions{
		Profile:      "smoke",
		ManifestPath: yaml,
		Command:      []string{"sh", "-c", "echo value is $SECRET"},
	}, &out, &errOut)
	if err != nil {
		t.Fatalf("Run error: %v (stderr=%q)", err, errOut.String())
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", code, errOut.String())
	}
	if strings.Contains(out.String(), "topsecret") {
		t.Fatalf("SECURITY: value leaked to stdout: %q", out.String())
	}
	if !strings.Contains(out.String(), "{{AV:SECRET}}") {
		t.Fatalf("masked placeholder missing; stdout=%q", out.String())
	}
}

// TestRunPropagatesExitCode proves the child's non-zero exit code is surfaced so
// the agent can branch on it.
func TestRunPropagatesExitCode(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	cl := newRunServer(t)
	yaml := writeManifest(t)

	var out, errOut bytes.Buffer
	code, err := Run(cl, RunOptions{
		Profile:      "smoke",
		ManifestPath: yaml,
		Command:      []string{"sh", "-c", "exit 3"},
	}, &out, &errOut)
	if err != nil {
		t.Fatalf("Run should not error on a clean non-zero exit: %v", err)
	}
	if code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
}

// TestRunMissingManifest returns a clear error (and no secret) when the manifest
// file is absent.
func TestRunMissingManifest(t *testing.T) {
	cl := New(shortSocketPath(t))
	var out, errOut bytes.Buffer
	code, err := Run(cl, RunOptions{
		Profile:      "smoke",
		ManifestPath: filepath.Join(t.TempDir(), "nope.yaml"),
		Command:      []string{"true"},
	}, &out, &errOut)
	if err == nil {
		t.Fatal("missing manifest must error")
	}
	if code != -1 {
		t.Fatalf("exit code = %d, want -1 on resolve/setup failure", code)
	}
}

// TestRunEmptyCommand rejects an empty argv before contacting the daemon.
func TestRunEmptyCommand(t *testing.T) {
	cl := New(shortSocketPath(t))
	var out, errOut bytes.Buffer
	if _, err := Run(cl, RunOptions{Profile: "smoke", Command: nil}, &out, &errOut); err == nil {
		t.Fatal("empty command must error")
	}
}
