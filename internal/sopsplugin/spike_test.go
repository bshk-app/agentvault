// Package sopsplugin holds the AgentVault age plugin's daemon-facing logic.
package sopsplugin_test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// TestPluginUnwrapsStandardX25519Stanza is the load-bearing test of the SOPS design.
// It encrypts to an ORDINARY age1... recipient (no plugin on the write side) and
// decrypts through a plugin. Passing means SOPS files keep their normal recipients, so
// Flux, CI, and teammates decrypt them unchanged. Failing invalidates the design.
func TestPluginUnwrapsStandardX25519Stanza(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin discovery on Windows is verified by the smoke script, not here")
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt with a STANDARD recipient. This is the crux: nothing here knows about plugins.
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, "spike payload"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Build the test plugin and put it on PATH under the name age discovers it by.
	dir := t.TempDir()
	build := exec.Command("go", "build", "-o", filepath.Join(dir, "age-plugin-avtest"), "./testdata/plugin")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build test plugin: %v\n%s", err, out)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("AV_TEST_PLUGIN_KEY", id.String())

	// A nil *ClientUI panics: the client calls methods on it that read its callback
	// fields unconditionally. The spike must not interact, so every callback errors —
	// that turns an unexpected prompt into a named failure instead of a silent "fail"
	// stanza. The identity carries no data: age.X25519Recipient exports no accessor for
	// its 32 bytes, and the test plugin ignores data anyway (plugin.NewIdentityWithoutData
	// encodes exactly this). Task 2 gives the real identity a recipient payload.
	ui := &plugin.ClientUI{
		DisplayMessage: func(name, message string) error {
			return fmt.Errorf("unexpected message from plugin %q", name)
		},
		RequestValue: func(name, _ string, _ bool) (string, error) {
			return "", fmt.Errorf("unexpected value request from plugin %q", name)
		},
		Confirm: func(name, _, _, _ string) (bool, error) {
			return false, fmt.Errorf("unexpected confirmation request from plugin %q", name)
		},
	}
	pid, err := plugin.NewIdentity(plugin.EncodeIdentity("avtest", nil), ui)
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.Decrypt(bytes.NewReader(ct.Bytes()), pid)
	if err != nil {
		t.Fatalf("decrypt through plugin: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "spike payload" {
		t.Fatalf("got %q, want %q", got, "spike payload")
	}
}
