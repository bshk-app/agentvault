package redact

import (
	"sort"
	"strings"
)

// Secret is one named value to redact.
type Secret struct {
	Name  string
	Value string
}

// Matcher masks known secret values, replacing each with {{AV:NAME}}.
type Matcher struct {
	forms   map[string]string // exact form -> placeholder
	ordered []string          // forms, longest first
	maxLen  int
}

// NewMatcher builds a matcher over the raw values only (encodings added in Task 3).
func NewMatcher(secrets []Secret) *Matcher {
	m := &Matcher{forms: map[string]string{}}
	for _, s := range secrets {
		if s.Value == "" {
			continue
		}
		placeholder := "{{AV:" + s.Name + "}}"
		for _, form := range allForms(s.Value) {
			if form == "" {
				continue
			}
			if _, ok := m.forms[form]; !ok {
				m.forms[form] = placeholder
			}
		}
	}
	for f := range m.forms {
		m.ordered = append(m.ordered, f)
		if len(f) > m.maxLen {
			m.maxLen = len(f)
		}
	}
	sort.Slice(m.ordered, func(i, j int) bool { return len(m.ordered[i]) > len(m.ordered[j]) })
	return m
}

// MaxFormLen is the longest masked form. Stream buffers overlap by at least this-1.
func (m *Matcher) MaxFormLen() int { return m.maxLen }

// Mask replaces every known form in s, longest forms first.
func (m *Matcher) Mask(s string) string {
	for _, form := range m.ordered {
		if strings.Contains(s, form) {
			s = strings.ReplaceAll(s, form, m.forms[form])
		}
	}
	return s
}

// hasFormWithPrefix reports whether some known form is strictly longer than s and
// begins with s. Used by the streaming redactor to decide what to retain.
func (m *Matcher) hasFormWithPrefix(s string) bool {
	for _, form := range m.ordered {
		if len(form) > len(s) && strings.HasPrefix(form, s) {
			return true
		}
	}
	return false
}

// straddleStart reports the earliest start index of any complete form occurrence
// in s that strictly straddles cut (i.e. occurs at [start, end) with
// start < cut < end). It returns (start, true) for the minimum such start, or
// (0, false) if no occurrence straddles cut. The streaming redactor uses this to
// pull a tentative cut back so it never bisects a complete secret occurrence.
func (m *Matcher) straddleStart(s string, cut int) (int, bool) {
	min := -1
	for _, form := range m.ordered {
		for off := 0; ; {
			i := strings.Index(s[off:], form)
			if i < 0 {
				break
			}
			start := off + i
			end := start + len(form)
			if start < cut && cut < end {
				if min < 0 || start < min {
					min = start
				}
			}
			off = start + 1 // allow overlapping occurrences
		}
	}
	if min < 0 {
		return 0, false
	}
	return min, true
}
