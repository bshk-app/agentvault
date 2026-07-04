package daemon

import (
	"encoding/json"
	"testing"

	"github.com/beshkenadze/agentvault/internal/ipc"
)

// versionServer wires a bare Server (no resolver/provisioner needed — version touches
// no secret) and returns it plus its socket path. The version RPC must answer with
// whatever was wired via SetVersion + SetKeyTier, so version works even with no vault.
func versionServer(t *testing.T) (*Server, string) {
	t.Helper()
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	return srv, path
}

// TestVersionRPCReportsWiredFields: the "version" case returns avd's wired version plus
// the active tier (SetKeyTier) and build Enclave-capability (SetEnclaveAvailable), which
// are independent — a keychain-tier vault on an Enclave-capable build. No secret involved.
func TestVersionRPCReportsWiredFields(t *testing.T) {
	srv, path := versionServer(t)
	srv.SetVersion("v9.9.9")
	srv.SetKeyTier("keychain")
	srv.SetEnclaveAvailable(true) // capable build, but the active tier is keychain

	resp := rpc(t, path, "version")
	if resp.Error != nil {
		t.Fatalf("version error: %+v", resp.Error)
	}
	var res ipc.VersionResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.Version != "v9.9.9" {
		t.Fatalf("Version = %q, want v9.9.9", res.Version)
	}
	if res.Tier != "keychain" {
		t.Fatalf("Tier = %q, want keychain", res.Tier)
	}
	if !res.EnclaveAvailable {
		t.Fatalf("EnclaveAvailable = false, want true (capability is independent of tier)")
	}
}

// TestVersionRPCEmptyTierIsNone: an unset tier ("" — no local vault) surfaces as "none"
// so the client never has to special-case the empty string.
func TestVersionRPCEmptyTierIsNone(t *testing.T) {
	srv, path := versionServer(t)
	srv.SetVersion("dev")
	// no SetKeyTier call → keyTier is ""

	resp := rpc(t, path, "version")
	if resp.Error != nil {
		t.Fatalf("version error: %+v", resp.Error)
	}
	var res ipc.VersionResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.Tier != "none" {
		t.Fatalf("Tier = %q, want none", res.Tier)
	}
	if res.Version != "dev" {
		t.Fatalf("Version = %q, want dev", res.Version)
	}
}
