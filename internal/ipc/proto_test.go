package ipc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	if err := enc.Encode(Request{ID: 7, Method: "ping"}); err != nil {
		t.Fatal(err)
	}
	// each message is exactly one line
	if bytes.Count(buf.Bytes(), []byte("\n")) != 1 {
		t.Fatalf("expected newline-delimited single line, got %q", buf.String())
	}
	dec := NewDecoder(&buf)
	var got Request
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ID != 7 || got.Method != "ping" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestResponseError(t *testing.T) {
	r := Response{ID: 1, Error: &RPCError{Code: CodeLocked, Message: "vault locked"}}
	b, _ := json.Marshal(r)
	var got Response
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Error == nil || got.Error.Code != CodeLocked {
		t.Fatalf("error not preserved: %+v", got)
	}
}

func TestDecodeSequentialThenEOF(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	for i := uint64(1); i <= 3; i++ {
		if err := enc.Encode(Request{ID: i, Method: "ping"}); err != nil {
			t.Fatal(err)
		}
	}
	dec := NewDecoder(&buf)
	for i := uint64(1); i <= 3; i++ {
		var got Request
		if err := dec.Decode(&got); err != nil {
			t.Fatalf("decode %d: %v", i, err)
		}
		if got.ID != i {
			t.Fatalf("out-of-order: got ID %d, want %d", got.ID, i)
		}
	}
	var extra Request
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("after last message want io.EOF, got %v", err)
	}
}

// An over-limit line must fail loudly (bufio.ErrTooLong), never silently truncate —
// a truncated secret-bearing line would be a redaction hazard. The destination must
// stay zero-valued, and the error must not be mistaken for a clean io.EOF.
func TestDecodeOverLimitFailsLoud(t *testing.T) {
	huge := `{"id":1,"method":"` + strings.Repeat("A", 2*1024*1024) + `"}` + "\n"
	dec := NewDecoder(strings.NewReader(huge))
	var got Request
	err := dec.Decode(&got)
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("over-limit line must error (not nil/EOF), got %v", err)
	}
	if got.ID != 0 || got.Method != "" {
		t.Fatalf("over-limit decode leaked a partial object: %+v", got)
	}
}
