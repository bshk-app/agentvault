package redact

import (
	"bytes"
	"testing"
)

func writeChunks(m *Matcher, chunks ...string) string {
	var out bytes.Buffer
	r := NewStreamRedactor(m, &out)
	for _, c := range chunks {
		if _, err := r.Write([]byte(c)); err != nil {
			panic(err)
		}
	}
	if err := r.Close(); err != nil {
		panic(err)
	}
	return out.String()
}

func TestStreamWholeValue(t *testing.T) {
	m := NewMatcher([]Secret{{Name: "T", Value: "ghp_ABCDEFG"}})
	if got := writeChunks(m, "x ghp_ABCDEFG y"); got != "x {{AV:T}} y" {
		t.Fatalf("got %q", got)
	}
}

func TestStreamSplitAcrossWrites(t *testing.T) {
	m := NewMatcher([]Secret{{Name: "T", Value: "ghp_ABCDEFG"}})
	// secret straddles the chunk boundary
	if got := writeChunks(m, "x ghp_AB", "CDEFG y"); got != "x {{AV:T}} y" {
		t.Fatalf("split value leaked: got %q", got)
	}
}

func TestStreamByteByByte(t *testing.T) {
	m := NewMatcher([]Secret{{Name: "T", Value: "ghp_ABCDEFG"}})
	chunks := make([]string, 0)
	for _, c := range "x ghp_ABCDEFG y" {
		chunks = append(chunks, string(c))
	}
	if got := writeChunks(m, chunks...); got != "x {{AV:T}} y" {
		t.Fatalf("byte-split value leaked: got %q", got)
	}
}

func TestStreamNoFalseRetain(t *testing.T) {
	m := NewMatcher([]Secret{{Name: "T", Value: "ghp_ABCDEFG"}})
	in := "completely unrelated output text\n"
	if got := writeChunks(m, in); got != in {
		t.Fatalf("got %q, want unchanged", got)
	}
}
