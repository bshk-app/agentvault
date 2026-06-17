package redact

import "testing"

func TestMaskRawValue(t *testing.T) {
	m := NewMatcher([]Secret{{Name: "TOKEN", Value: "s3cr3t-value"}})
	got := m.Mask("the token is s3cr3t-value here")
	want := "the token is {{AV:TOKEN}} here"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMaskNoMatchUnchanged(t *testing.T) {
	m := NewMatcher([]Secret{{Name: "TOKEN", Value: "s3cr3t-value"}})
	in := "nothing secret here"
	if got := m.Mask(in); got != in {
		t.Fatalf("got %q, want unchanged %q", got, in)
	}
}

func TestEmptyValueIgnored(t *testing.T) {
	m := NewMatcher([]Secret{{Name: "EMPTY", Value: ""}})
	in := "" // an empty needle must never match and blank everything
	_ = in
	if got := m.Mask("abc"); got != "abc" {
		t.Fatalf("empty value should not mask: got %q", got)
	}
}
