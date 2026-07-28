package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The av binary must stay thin: it must never transitively import gitleaks or its
// heavy tree (wazero, viper, afero), nor any backend implementation's deps
// (filippo.io/age). This guards the architecture invariant from the design
// (gitleaks lives only in avd's path; backends live in avd, never in the thin av).
func TestAvStaysThin(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	// Guard against vacuous pass: confirm go list actually resolved this package's
	// dependency graph before scanning it (an empty/partial output must not pass).
	const self = "github.com/beshkenadze/agentvault/cmd/av"
	if !strings.Contains(string(out), self) {
		t.Fatalf("go list returned no deps for %s; output=%q", self, out)
	}
	// internal/sopsplugin is named directly, not left to be caught through its
	// filippo.io/age import. That inference holds today but is not an assertion: a
	// sopsplugin file or subpackage that happens not to import age would slip past.
	// The SOPS design leans on this — the sops/ namespace is enforced in the daemon
	// rather than in av precisely because av must not grow that dependency.
	for _, bad := range []string{"gitleaks", "wazero", "spf13/viper", "spf13/afero", "filippo.io/age", "internal/audit", "internal/backend/onepassword", "internal/backend/bitwarden", "internal/backend/keychain", "internal/enclave", "internal/sopsplugin"} {
		if strings.Contains(string(out), bad) {
			t.Errorf("av must not link %q", bad)
		}
	}
}
