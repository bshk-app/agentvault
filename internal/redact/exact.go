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
		for _, form := range formsFor(s.Value) {
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

// formsFor returns every wire form of a value that should be masked.
// Task 2 masks only the raw value; Task 3 extends this.
func formsFor(v string) []string { return []string{v} }

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
