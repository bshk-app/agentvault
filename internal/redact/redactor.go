package redact

import "strings"

// Finding is a secret-like substring discovered by a Detector (e.g. a derived token
// the vault never issued). Secret is the exact text to mask; Rule names the detector rule.
type Finding struct {
	Secret string
	Rule   string
}

// Detector finds secrets that exact-match does not know about. Implementations live
// in their own packages (e.g. a gitleaks-backed one) so heavy deps stay out of redact.
type Detector interface {
	Detect(s string) []Finding
}

// Options configures the Redactor. A nil Detector means exact-match only.
type Options struct {
	Detector Detector
}

// Redactor composes the exact-match tier with an optional Detector tier.
type Redactor struct {
	exact *Matcher
	det   Detector
}

// NewRedactor builds a Redactor over the issued secrets, with an optional Detector tier.
func NewRedactor(secrets []Secret, opts Options) *Redactor {
	return &Redactor{exact: NewMatcher(secrets), det: opts.Detector}
}

// Redact masks a whole string: exact-match first, then any Detector findings.
func (r *Redactor) Redact(s string) string {
	s = r.exact.Mask(s)
	if r.det != nil {
		for _, f := range r.det.Detect(s) {
			if f.Secret == "" {
				continue
			}
			s = strings.ReplaceAll(s, f.Secret, "{{AV:REDACTED:"+f.Rule+"}}")
		}
	}
	return s
}
