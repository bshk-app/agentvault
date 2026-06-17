package redact

import (
	"strings"
	"testing"
)

// fakeDetector is an in-test Detector that returns a fixed set of findings,
// proving Redactor's composition without importing gitleaks into this package.
type fakeDetector struct {
	findings []Finding
}

func (f fakeDetector) Detect(string) []Finding { return f.findings }

func TestRedactorExactTier(t *testing.T) {
	r := NewRedactor([]Secret{{Name: "T", Value: "ghp_ABCDEFG"}}, Options{})
	got := r.Redact("see ghp_ABCDEFG")
	if want := "see {{AV:T}}"; got != want {
		t.Errorf("Redact() = %q, want %q", got, want)
	}
}

func TestRedactorDetectorTier(t *testing.T) {
	det := fakeDetector{findings: []Finding{{Secret: "leakedXYZ", Rule: "fake-rule"}}}
	r := NewRedactor(nil, Options{Detector: det})
	got := r.Redact("a leakedXYZ b")
	if !strings.Contains(got, "{{AV:REDACTED:fake-rule}}") {
		t.Errorf("Redact() = %q, want it to contain the detector placeholder", got)
	}
	if strings.Contains(got, "leakedXYZ") {
		t.Errorf("Redact() = %q, raw secret leaked through detector tier", got)
	}
}

func TestRedactorExactBeforeDetector(t *testing.T) {
	// "secretval" is both an issued secret (exact tier) and a detector finding.
	// Exact runs first, so it must win with {{AV:NAME}}, never the detector mask.
	det := fakeDetector{findings: []Finding{{Secret: "secretval", Rule: "fake-rule"}}}
	r := NewRedactor([]Secret{{Name: "K", Value: "secretval"}}, Options{Detector: det})
	got := r.Redact("x secretval y")
	if want := "x {{AV:K}} y"; got != want {
		t.Errorf("Redact() = %q, want %q (exact tier must win over detector)", got, want)
	}
	if strings.Contains(got, "REDACTED") {
		t.Errorf("Redact() = %q, detector masked a value the exact tier already handled", got)
	}
}
