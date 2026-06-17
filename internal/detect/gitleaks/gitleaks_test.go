package gitleaks_test

import (
	"strings"
	"testing"

	"github.com/beshkenadze/agentvault/internal/detect/gitleaks"
	"github.com/beshkenadze/agentvault/internal/redact"
)

// TestGitleaksTierEndToEnd is the real end-to-end of the gitleaks tier: the detector
// lives in this package (which may import gitleaks), and is injected into a Redactor
// from internal/redact (which must NOT import gitleaks). A raw GitHub token must not
// survive, and the REDACTED placeholder must appear.
func TestGitleaksTierEndToEnd(t *testing.T) {
	d, err := gitleaks.New()
	if err != nil {
		t.Fatalf("gitleaks.New() failed: %v", err)
	}
	r := redact.NewRedactor(nil, redact.Options{Detector: d})

	const token = "ghp_0123456789abcdefABCDEF0123456789abcd"
	got := r.Redact("token github " + token)

	if strings.Contains(got, token) {
		t.Errorf("Redact() = %q, raw token survived the gitleaks tier", got)
	}
	if !strings.Contains(got, "{{AV:REDACTED:") {
		t.Errorf("Redact() = %q, want it to contain the REDACTED placeholder", got)
	}
}
