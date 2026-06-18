package client

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/beshkenadze/agentvault/internal/backend/agefile"
	"github.com/beshkenadze/agentvault/internal/ipc"
)

// realSecret is the value the e2e proves NEVER reaches av's stdout/stderr. The
// REAL avd binary (not an in-process Server) decrypts the vault and brokers it;
// av masks it at the source. If this string appears anywhere the agent can see,
// the redaction pipeline — or the production avd resolver wiring (I-1) — is broken.
const realSecret = "ghp_REAL_e2e"

// e2eVault age-encrypts {GITHUB_TOKEN: realSecret} to <dir>/vault.age, writes the
// identity string to <dir>/id.txt (the standard age identity-file format that
// avd's age.ParseIdentities reads), and writes an agentvault.yaml with profile
// "smoke". It returns the identity-file path, vault path, and manifest path.
func e2eVault(t *testing.T, dir string) (idPath, vaultPath, manifestPath string) {
	t.Helper()

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	idPath = filepath.Join(dir, "id.txt")
	if err := os.WriteFile(idPath, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	vaultPath = filepath.Join(dir, "vault.age")
	vf, err := os.Create(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := agefile.EncryptVault(vf, id.Recipient(), map[string]string{"GITHUB_TOKEN": realSecret}); err != nil {
		vf.Close()
		t.Fatal(err)
	}
	if err := vf.Close(); err != nil {
		t.Fatal(err)
	}

	manifestPath = filepath.Join(dir, "agentvault.yaml")
	manifest := "profiles:\n" +
		"  smoke:\n" +
		"    GITHUB_TOKEN:\n" +
		"      ref: av://file/GITHUB_TOKEN\n" +
		"      tier: normal\n"
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	return idPath, vaultPath, manifestPath
}

// buildAndAutostartEnv builds the REAL avd into a short /tmp dir and points the env
// at it so client.dial autostarts that binary (the spawned avd inherits the parent
// env — autostart uses exec.Command without a custom Env). It sets AV_AGE_IDENTITY /
// AV_AGE_VAULT so the spawned avd wires the agefile backend, and (unless auth is
// "") AV_TEST_AUTH so the stub authorizer allows issuance. It returns the dir, the
// socket path the autostarted daemon will bind, and the manifest path.
//
// Cleanup is mandatory: it kills the spawned avd by its unique binary path and
// removes the socket + lockfile so nothing leaks past the test.
func buildAndAutostartEnv(t *testing.T, auth string) (dir, sockPath, manifestPath string) {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "ave")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	avd := filepath.Join(dir, "avd")
	build := exec.Command("go", "build", "-o", avd, "github.com/beshkenadze/agentvault/cmd/avd")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build avd: %v\n%s", err, out)
	}

	idPath, vaultPath, manifestPath := e2eVault(t, dir)

	t.Setenv("AV_AVD_PATH", avd)
	t.Setenv("XDG_RUNTIME_DIR", dir) // socket resolves under this short dir
	t.Setenv("AV_AGE_IDENTITY", idPath)
	t.Setenv("AV_AGE_VAULT", vaultPath)
	if auth != "" {
		t.Setenv("AV_TEST_AUTH", auth)
	} else {
		t.Setenv("AV_TEST_AUTH", "") // explicitly locked: no auth configured
	}

	sockPath = filepath.Join(dir, "agentvault", "avd.sock")
	t.Cleanup(func() {
		_ = exec.Command("pkill", "-f", avd).Run()
		_ = os.Remove(sockPath)
		_ = os.Remove(sockPath + ".lock")
	})
	return dir, sockPath, manifestPath
}

// assertNoSecret fails if the real secret appears anywhere in the given buffers.
func assertNoSecret(t *testing.T, where string, bufs ...*bytes.Buffer) {
	t.Helper()
	for _, b := range bufs {
		if strings.Contains(b.String(), realSecret) {
			t.Fatalf("%s: real secret leaked: %q", where, b.String())
		}
	}
}

// TestE2ERunMasksRealSecret is the I-1 guard: it autostarts the REAL avd binary,
// which must wire the resolver (production path), decrypt the age vault, broker
// GITHUB_TOKEN, and have av mask it at the source. The child echoes the env var;
// av's stdout must show the placeholder and the real value must appear NOWHERE.
func TestE2ERunMasksRealSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: builds and spawns the real avd")
	}
	_, sockPath, manifestPath := buildAndAutostartEnv(t, "allow")

	var out, errBuf bytes.Buffer
	code, err := Run(New(sockPath), RunOptions{
		Profile:      "smoke",
		ManifestPath: manifestPath,
		Command:      []string{"sh", "-c", "echo got=$GITHUB_TOKEN"},
	}, &out, &errBuf)
	if err != nil {
		t.Fatalf("run: %v (stderr=%q)", err, errBuf.String())
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if got := strings.TrimSpace(out.String()); got != "got={{AV:GITHUB_TOKEN}}" {
		t.Fatalf("stdout = %q, want got={{AV:GITHUB_TOKEN}}", got)
	}
	// The whole point: the REAL secret must be nowhere the agent can see it.
	assertNoSecret(t, "run", &out, &errBuf)
}

// TestE2EScrubMasksRealSecret proves layer-2: piping a string containing the real
// secret through the real avd's scrub stream masks it. The session must already
// hold the value, so this reuses the SAME daemon by resolving first (Run), then
// scrubbing over a fresh connection to the same socket.
func TestE2EScrubMasksRealSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: builds and spawns the real avd")
	}
	_, sockPath, manifestPath := buildAndAutostartEnv(t, "allow")
	cl := New(sockPath)

	// Resolve once so the daemon's session holds GITHUB_TOKEN for scrub to mask.
	var out, errBuf bytes.Buffer
	if _, err := Run(cl, RunOptions{
		Profile:      "smoke",
		ManifestPath: manifestPath,
		Command:      []string{"true"},
	}, &out, &errBuf); err != nil {
		t.Fatalf("priming run: %v", err)
	}

	var scrubbed bytes.Buffer
	in := strings.NewReader("leak " + realSecret + " here")
	if err := cl.Scrub(in, &scrubbed); err != nil {
		t.Fatalf("scrub: %v", err)
	}
	if !strings.Contains(scrubbed.String(), "{{AV:GITHUB_TOKEN}}") {
		t.Fatalf("scrub output not masked: %q", scrubbed.String())
	}
	assertNoSecret(t, "scrub", &scrubbed)
}

// TestE2ELockedRunFails proves the auth seam end-to-end: a real avd started WITHOUT
// AV_TEST_AUTH refuses resolve with CodeLocked, and the value is never issued. The
// run returns a *ipc.RPCError whose Code is CodeLocked (cmd/av maps it to exit 69).
func TestE2ELockedRunFails(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: builds and spawns the real avd")
	}
	_, sockPath, manifestPath := buildAndAutostartEnv(t, "") // no AV_TEST_AUTH

	var out, errBuf bytes.Buffer
	code, err := Run(New(sockPath), RunOptions{
		Profile:      "smoke",
		ManifestPath: manifestPath,
		Command:      []string{"sh", "-c", "echo got=$GITHUB_TOKEN"},
	}, &out, &errBuf)
	if err == nil {
		t.Fatalf("locked daemon must fail resolve; got code=%d out=%q", code, out.String())
	}
	var rpc *ipc.RPCError
	if !errors.As(err, &rpc) {
		t.Fatalf("want *ipc.RPCError, got %T: %v", err, err)
	}
	if rpc.Code != ipc.CodeLocked {
		t.Fatalf("want CodeLocked, got code=%d msg=%q", rpc.Code, rpc.Message)
	}
	assertNoSecret(t, "locked", &out, &errBuf)
	if strings.Contains(rpc.Message, realSecret) {
		t.Fatalf("locked error leaked secret: %q", rpc.Message)
	}
}
