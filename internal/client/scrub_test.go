package client

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/beshkenadze/agentvault/internal/daemon"
)

// resolveSecret populates the in-process daemon's session with SECRET=topsecret
// by driving a resolve, so the scrub stream has a value to mask.
func resolveSecret(t *testing.T, cl *Client) {
	t.Helper()
	vals, err := cl.Resolve("smoke", []byte(runManifestYAML))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if vals["SECRET"] != "topsecret" {
		t.Fatalf("resolve values = %+v", vals)
	}
}

// TestScrubMasksStream proves client.Scrub filters a piped stream, masking a
// session value end to end (daemon-side masking; the client only ships bytes).
func TestScrubMasksStream(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	cl := newRunServer(t)
	resolveSecret(t, cl)

	in := strings.NewReader("leak: topsecret here\n")
	var out bytes.Buffer
	if err := cl.Scrub(in, &out); err != nil {
		t.Fatalf("Scrub: %v", err)
	}
	if strings.Contains(out.String(), "topsecret") {
		t.Fatalf("SECURITY: value survived scrub: %q", out.String())
	}
	if want := "leak: {{AV:SECRET}} here\n"; out.String() != want {
		t.Fatalf("scrub output = %q, want %q", out.String(), want)
	}
}

// chunkReader yields its data in fixed-size pieces so a Scrub read boundary can be
// forced to split the secret across two client reads — exercising the streaming
// overlap across the RPC boundary from the client side.
type chunkReader struct {
	data []byte
	size int
	pos  int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	end := r.pos + r.size
	if end > len(r.data) {
		end = len(r.data)
	}
	n := copy(p, r.data[r.pos:end])
	r.pos += n
	return n, nil
}

// TestScrubSplitAcrossReadChunks forces the secret to straddle two client reads;
// the daemon's per-connection StreamRedactor must still mask it.
func TestScrubSplitAcrossReadChunks(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	cl := newRunServer(t)
	resolveSecret(t, cl)

	// "top" lands in read 1, "secret" in read 2 — the secret straddles the cut.
	in := &chunkReader{data: []byte("x topsecret y"), size: 5}
	var out bytes.Buffer
	if err := cl.Scrub(in, &out); err != nil {
		t.Fatalf("Scrub: %v", err)
	}
	if strings.Contains(out.String(), "topsecret") {
		t.Fatalf("SECURITY: split value survived scrub: %q", out.String())
	}
	if want := "x {{AV:SECRET}} y"; out.String() != want {
		t.Fatalf("scrub output = %q, want %q", out.String(), want)
	}
}

// newSecretScrubServer starts an in-process daemon with a session holding ONE issued
// value (name -> value) and returns a client bound to it. It wires the scrub stream
// to that session via SetResolver, so scrub masks the issued value. Unlike
// newRunServer it takes an arbitrary name/value, letting a test issue a 1-byte secret
// to force worst-case placeholder inflation.
func newSecretScrubServer(t *testing.T, name, value string) *Client {
	t.Helper()
	path := shortSocketPath(t)
	srv, err := daemon.New(path)
	if err != nil {
		t.Fatal(err)
	}
	sess := daemon.NewSession(15 * time.Minute)
	sess.Unlock(15 * time.Minute)
	sess.Issue(name, value)
	srv.SetResolver(daemon.NewResolver(nil, daemon.NewStubPresence(), sess))
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	return New(path)
}

// TestScrubChunkCapUnderLineLimit is the reply-inflation cap regression: a large input
// (1 MiB) that is ENTIRELY a 1-byte session secret masks to ~8x its size as the 8-byte
// placeholder "{{AV:S}}", i.e. ~8 MiB of masked output across chunks. With a naive
// 256 KiB chunk, a single masked reply line would exceed the daemon Decoder's 1 MiB
// JSON-RPC cap and the client Decoder would error "token too long". The 64 KiB chunk
// keeps every reply under the cap, so the whole stream must complete cleanly and the
// output must be fully masked (no raw 1-byte secret survives, and the placeholder
// repeats once per input byte).
func TestScrubChunkCapUnderLineLimit(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	// name "X", value "S": a 1-byte secret "S" masks to the 8-byte placeholder
	// "{{AV:X}}" (~8x inflation). The placeholder does NOT contain "S", so a raw "S"
	// in the output would be a genuine leak (not the placeholder's own bytes).
	const secret = "S"
	cl := newSecretScrubServer(t, "X", secret)

	const n = 1 << 20 // 1 MiB of the 1-byte secret repeated -> ~8 MiB masked
	in := bytes.NewReader(bytes.Repeat([]byte(secret), n))
	var out bytes.Buffer
	if err := cl.Scrub(in, &out); err != nil {
		// A "token too long" / bufio.ErrTooLong here is the exact failure the chunk cap
		// prevents; surface it clearly.
		t.Fatalf("Scrub of large 1-byte-secret input failed (chunk cap regression?): %v", err)
	}

	// SECURITY: not a single raw secret byte may survive (the whole input was the secret).
	if bytes.Contains(out.Bytes(), []byte(secret)) {
		t.Fatalf("SECURITY: raw 1-byte secret survived scrub")
	}
	// Fully masked: exactly n placeholders, nothing else.
	if want := strings.Repeat("{{AV:X}}", n); out.String() != want {
		t.Fatalf("masked output length = %d, want %d (n placeholders)", out.Len(), len(want))
	}
}
