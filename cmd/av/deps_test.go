package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The av binary must stay thin: it must never transitively import gitleaks or its
// heavy tree (wazero, viper, afero). This guards the architecture invariant from
// the design (gitleaks lives only in avd's path).
func TestAvDoesNotLinkGitleaks(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	for _, bad := range []string{"gitleaks", "wazero", "spf13/viper", "spf13/afero"} {
		if strings.Contains(string(out), bad) {
			t.Errorf("av must not link %q", bad)
		}
	}
}
