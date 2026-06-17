package redact

import (
	"bytes"
	"strings"
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

// --- Regression tests for the bisection defect ---
//
// The old retainStart-then-mask algorithm masked buf[:cut] in isolation and
// retained buf[cut:], which split a complete secret occurrence straddling cut:
// the prefix was emitted raw and the suffix flushed raw later. These cases each
// leaked a raw secret value through the boundary.

// secret "aa", writes "paa","a","aaq" -> leaked raw "aa".
func TestStreamBisect_SelfOverlapAA(t *testing.T) {
	m := NewMatcher([]Secret{{Name: "A", Value: "aa"}})
	// Total bytes: "paa"+"a"+"aaq" = "paaaaaq" (p, five a's, q). The five a's mask
	// as two non-overlapping pairs with one literal "a" left over: AV AV a.
	got := writeChunks(m, "paa", "a", "aaq")
	if strings.Contains(got, "aa") {
		t.Fatalf("raw secret %q leaked in output %q", "aa", got)
	}
	want := "p{{AV:A}}{{AV:A}}aq"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// secret "ababababab", write "xababababababab" -> leaked raw.
func TestStreamBisect_SelfOverlapABAB(t *testing.T) {
	secret := "ababababab"
	m := NewMatcher([]Secret{{Name: "AB", Value: secret}})
	got := writeChunks(m, "xababababababab")
	if strings.Contains(got, secret) {
		t.Fatalf("raw secret %q leaked in output %q", secret, got)
	}
	// "x" + secret + "abab" leftover; the leftover "abab" cannot complete a form.
	want := "x{{AV:AB}}abab"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// secrets "KEYabc" and "abcdefghijklmnop", fed byte-by-byte "KEYabc" -> leaked "KEYabc".
func TestStreamBisect_SharedAffixByteByByte(t *testing.T) {
	m := NewMatcher([]Secret{
		{Name: "K", Value: "KEYabc"},
		{Name: "L", Value: "abcdefghijklmnop"},
	})
	got := writeChunks(m, splitBytes("KEYabc")...)
	if strings.Contains(got, "KEYabc") {
		t.Fatalf("raw secret %q leaked in output %q", "KEYabc", got)
	}
	want := "{{AV:K}}"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// secrets "secretONE_xyz" and "xyz_secretTWO", fed byte-by-byte -> leaked "secretONE_xyz".
func TestStreamBisect_OverlapPairByteByByte(t *testing.T) {
	s1 := "secretONE_xyz"
	s2 := "xyz_secretTWO"
	m := NewMatcher([]Secret{
		{Name: "ONE", Value: s1},
		{Name: "TWO", Value: s2},
	})
	got := writeChunks(m, splitBytes(s1)...)
	if strings.Contains(got, s1) {
		t.Fatalf("raw secret %q leaked in output %q", s1, got)
	}
	want := "{{AV:ONE}}"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// short-value-is-prefix-of-long-value: secrets "abc" and "abcdefXY", stream
// split "abc"|"defXY". A "mask-first then retain" fix masks "abc" immediately,
// then the suffix "defXY" of the longer secret leaks. The correct fix retains
// "abc" because it could still grow into "abcdefXY".
func TestStreamPrefixOfLonger(t *testing.T) {
	m := NewMatcher([]Secret{
		{Name: "SHORT", Value: "abc"},
		{Name: "LONG", Value: "abcdefXY"},
	})
	got := writeChunks(m, "abc", "defXY")
	if strings.Contains(got, "abcdefXY") {
		t.Fatalf("raw long secret leaked in output %q", got)
	}
	want := "{{AV:LONG}}"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func splitBytes(s string) []string {
	out := make([]string, 0, len(s))
	for i := 0; i < len(s); i++ {
		out = append(out, s[i:i+1])
	}
	return out
}

// TestStreamExhaustiveSplits is the acceptance criterion. For a corpus of tricky
// secrets it builds a haystack embedding each secret with surrounding noise, then
// enumerates ALL 1-way, 2-way, and 3-way splits of the haystack (every combination
// of cut points), feeds each split through a fresh StreamRedactor, and asserts the
// raw secret value never appears as a substring of the concatenated output.
func TestStreamExhaustiveSplits(t *testing.T) {
	secrets := []Secret{
		{Name: "SELF4", Value: "aaaa"},     // self-overlapping
		{Name: "ABAB", Value: "abab"},      // self-overlapping
		{Name: "SHARED1", Value: "KEYxyz"}, // shared affix with SHARED2
		{Name: "SHARED2", Value: "xyzKEY"},
		{Name: "PRE", Value: "tok"},        // short, prefix of PRELONG
		{Name: "PRELONG", Value: "tokQRST"}, // long, starts with PRE
		{Name: "NORMAL", Value: "ghp_ABCDEF123"},
	}
	m := NewMatcher(secrets)

	// Haystack: each secret surrounded by noise that itself contains teasing
	// prefixes/suffixes of the secrets to provoke boundary mistakes.
	var hb strings.Builder
	for _, s := range secrets {
		hb.WriteString("--")
		hb.WriteString(s.Value[:1]) // teaser prefix byte
		hb.WriteString("[")
		hb.WriteString(s.Value)
		hb.WriteString("]")
		hb.WriteString(s.Value[len(s.Value)-1:]) // teaser suffix byte
		hb.WriteString("--")
	}
	haystack := hb.String()
	n := len(haystack)

	rawValues := make([]string, len(secrets))
	for i, s := range secrets {
		rawValues[i] = s.Value
	}

	check := func(t *testing.T, chunks []string) {
		got := writeChunks(m, chunks...)
		for _, raw := range rawValues {
			if strings.Contains(got, raw) {
				t.Fatalf("raw secret %q leaked; split=%v output=%q", raw, chunks, got)
			}
		}
	}

	combos := 0

	// 1-way: the whole haystack as a single write.
	combos++
	check(t, []string{haystack})

	// 2-way: one cut point i in [1, n-1].
	for i := 1; i < n; i++ {
		combos++
		check(t, []string{haystack[:i], haystack[i:]})
	}

	// 3-way: two cut points i < j in [1, n-1].
	for i := 1; i < n; i++ {
		for j := i + 1; j < n; j++ {
			combos++
			check(t, []string{haystack[:i], haystack[i:j], haystack[j:]})
		}
	}

	t.Logf("exercised %d split-combinations over haystack of len %d", combos, n)
}
