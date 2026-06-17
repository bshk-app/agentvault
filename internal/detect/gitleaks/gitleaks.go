// Package gitleaks provides a redact.Detector backed by gitleaks' default rule set.
// It lives in its own package so the heavy gitleaks dependency tree (wazero, viper,
// afero, ...) stays out of internal/redact and the thin av binary.
package gitleaks

import (
	"github.com/beshkenadze/agentvault/internal/redact"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// Detector implements redact.Detector backed by gitleaks' default rule set.
type Detector struct{ d *detect.Detector }

// New builds a Detector with gitleaks' embedded default configuration.
func New() (*Detector, error) {
	d, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, err
	}
	return &Detector{d: d}, nil
}

// Detect returns one Finding per gitleaks finding, using the captured Secret string
// (robust to multi-line; no offset math). It falls back to the full Match when the
// rule did not capture a narrower secret.
func (g *Detector) Detect(s string) []redact.Finding {
	fs := g.d.DetectString(s)
	out := make([]redact.Finding, 0, len(fs))
	for _, f := range fs {
		secret := f.Secret
		if secret == "" {
			secret = f.Match
		}
		out = append(out, redact.Finding{Secret: secret, Rule: f.RuleID})
	}
	return out
}
