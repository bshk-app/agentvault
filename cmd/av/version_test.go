package main

import (
	"strings"
	"testing"

	"github.com/beshkenadze/agentvault/internal/ipc"
)

// TestFormatVersionMatch: when av and avd report the SAME version, the block lists both
// versions, the tier, and the socket, and raises NO mismatch warning.
func TestFormatVersionMatch(t *testing.T) {
	res := &ipc.VersionResult{Version: "v1.2.3", Tier: "keychain", EnclaveAvailable: false}
	out, mismatch := formatVersion("v1.2.3", res, "/run/agentvault/avd.sock")
	if mismatch {
		t.Fatalf("matching versions must not flag a mismatch; out=%q", out)
	}
	for _, want := range []string{"v1.2.3", "keychain", "/run/agentvault/avd.sock"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	// A matched build must not nag about restarting.
	if strings.Contains(strings.ToLower(out), "restart") {
		t.Fatalf("matching versions must not suggest a restart:\n%s", out)
	}
}

// TestFormatVersionMismatch: when av != avd, the block must carry a LOUD warning that
// suggests restarting the service, and still set the mismatch flag.
func TestFormatVersionMismatch(t *testing.T) {
	res := &ipc.VersionResult{Version: "v0.9.0", Tier: "enclave", EnclaveAvailable: true}
	out, mismatch := formatVersion("v1.0.0", res, "/run/agentvault/avd.sock")
	if !mismatch {
		t.Fatalf("differing versions must flag a mismatch; out=%q", out)
	}
	if !strings.Contains(out, "brew services restart agentvault") {
		t.Fatalf("mismatch must suggest the restart command:\n%s", out)
	}
	if !strings.Contains(out, "v1.0.0") || !strings.Contains(out, "v0.9.0") {
		t.Fatalf("mismatch block must show BOTH versions:\n%s", out)
	}
}

// TestFormatVersionDaemonUnreachable: with res==nil (daemon not running), the block must
// still print the av version, report "not running" + the socket path, and NOT flag a
// mismatch (there is nothing to compare against).
func TestFormatVersionDaemonUnreachable(t *testing.T) {
	out, mismatch := formatVersion("v1.2.3", nil, "/run/agentvault/avd.sock")
	if mismatch {
		t.Fatalf("an unreachable daemon must not flag a mismatch; out=%q", out)
	}
	if !strings.Contains(out, "v1.2.3") {
		t.Fatalf("must still print the av version:\n%s", out)
	}
	if !strings.Contains(out, "not running") {
		t.Fatalf("must report the daemon is not running:\n%s", out)
	}
	if !strings.Contains(out, "/run/agentvault/avd.sock") {
		t.Fatalf("must print the socket path so the user can debug:\n%s", out)
	}
}

// TestFormatVersionEnclaveNote: a non-enclave tier annotates that the Enclave is
// unavailable; an enclave tier does not carry that note.
func TestFormatVersionEnclaveNote(t *testing.T) {
	keychain := &ipc.VersionResult{Version: "v1", Tier: "keychain", EnclaveAvailable: false}
	out, _ := formatVersion("v1", keychain, "/s.sock")
	if !strings.Contains(out, "Enclave unavailable") {
		t.Fatalf("non-enclave tier must note the Enclave is unavailable:\n%s", out)
	}

	enclave := &ipc.VersionResult{Version: "v1", Tier: "enclave", EnclaveAvailable: true}
	out, _ = formatVersion("v1", enclave, "/s.sock")
	if strings.Contains(out, "Enclave unavailable") {
		t.Fatalf("enclave tier must not carry the unavailable note:\n%s", out)
	}
}
