package client

import (
	"bytes"
	"encoding/json"
	"net"
	"reflect"
	"sync"
	"testing"

	"filippo.io/age"

	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/transport"
)

// sopsStub is a daemon stand-in that speaks the ipc framing directly and keeps every
// request verbatim. The other client tests drive a real in-process daemon; these do not,
// because what is under test is the REQUEST the client builds — above all that the
// recipient bytes arrive unaltered — and only a stub that hands back the raw params can
// assert on the bytes themselves rather than on whether an unwrap happened to work.
type sopsStub struct {
	path  string
	reply func(ipc.Request) ipc.Response

	mu   sync.Mutex
	reqs []ipc.Request
}

func newSopsStub(t *testing.T, reply func(ipc.Request) ipc.Response) *sopsStub {
	t.Helper()
	s := &sopsStub{path: shortSocketPath(t), reply: reply}
	ln, err := transport.Listen(s.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go s.serve(ln)
	return s
}

func (s *sopsStub) serve(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed by t.Cleanup
		}
		go func() {
			defer conn.Close()
			var req ipc.Request
			if err := ipc.NewDecoder(conn).Decode(&req); err != nil {
				return
			}
			s.mu.Lock()
			s.reqs = append(s.reqs, req)
			s.mu.Unlock()
			_ = ipc.NewEncoder(conn).Encode(s.reply(req))
		}()
	}
}

// only returns the params of the ONE request the stub received. Insisting on exactly one
// also catches a stray extra dial (an ensureFresh version probe, a retry) that would make
// the byte-identity assertion below read the wrong request.
func (s *sopsStub) only(t *testing.T) ipc.SopsUnwrapParams {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reqs) != 1 {
		t.Fatalf("stub saw %d requests, want 1", len(s.reqs))
	}
	if s.reqs[0].Method != "sops_unwrap" {
		t.Fatalf("method = %q, want sops_unwrap", s.reqs[0].Method)
	}
	var p ipc.SopsUnwrapParams
	if err := json.Unmarshal(s.reqs[0].Params, &p); err != nil {
		t.Fatalf("unmarshal params: %v", err)
	}
	return p
}

// sopsOK replies with fileKey, the daemon's successful unwrap.
func sopsOK(fileKey []byte) func(ipc.Request) ipc.Response {
	return func(req ipc.Request) ipc.Response {
		res, _ := json.Marshal(ipc.SopsUnwrapResult{FileKey: fileKey})
		return ipc.Response{ID: req.ID, Result: res}
	}
}

// TestSopsUnwrapReturnsFileKey is the happy path: the stanzas go out on the "sops_unwrap"
// method field for field, and the daemon's per-file key comes back to the caller.
func TestSopsUnwrapReturnsFileKey(t *testing.T) {
	fileKey := []byte{0x00, 0x7f, 'k', 'e', 'y', 0xff}
	stanzas := []ipc.SopsStanza{
		{Type: "X25519", Args: []string{"OB0mBw9ZQ0h1kEeXbGRhTnU"}, Body: []byte{0xde, 0xad, 0xbe, 0xef}},
		{Type: "scrypt", Args: []string{"salt", "18"}, Body: []byte{0x01}},
	}
	stub := newSopsStub(t, sopsOK(fileKey))

	got, err := New(stub.path).SopsUnwrap([]byte(testRecipient(t).String()), stanzas)
	if err != nil {
		t.Fatalf("SopsUnwrap: %v", err)
	}
	if !bytes.Equal(got, fileKey) {
		t.Fatalf("file key = %x, want %x", got, fileKey)
	}
	if p := stub.only(t); !reflect.DeepEqual(p.Stanzas, stanzas) {
		t.Fatalf("stanzas arrived as %+v, want %+v", p.Stanzas, stanzas)
	}
}

// TestSopsUnwrapRecipientCrossesByteIdentical guards the one trap in this method: the
// recipient is the bech32 "age1…" TEXT living in a []byte, and encoding/json already
// base64s a []byte on its own. Any extra encoding on the client side still round-trips as
// *some* []byte, so the daemon would decode it, fail age.ParseX25519Recipient, and report
// the file as one this vault holds no key for — indistinguishable from a file that
// genuinely is not yours. Hence both halves: the bytes are the caller's, and they still
// parse back into the recipient they came from.
func TestSopsUnwrapRecipientCrossesByteIdentical(t *testing.T) {
	r := testRecipient(t)
	sent := []byte(r.String()) // exactly what age-plugin-av will pass (Task 8)
	stub := newSopsStub(t, sopsOK([]byte("k")))

	if _, err := New(stub.path).SopsUnwrap(sent, nil); err != nil {
		t.Fatalf("SopsUnwrap: %v", err)
	}
	got := stub.only(t).Recipient
	if !bytes.Equal(got, sent) {
		t.Fatalf("recipient arrived as %q, want %q", got, sent)
	}
	parsed, err := age.ParseX25519Recipient(string(got))
	if err != nil {
		t.Fatalf("daemon cannot parse the recipient it received (%q): %v", got, err)
	}
	if parsed.String() != r.String() {
		t.Fatalf("recipient round-tripped to %s, want %s", parsed, r)
	}
}

// TestSopsUnwrapSurfacesRPCError: a daemon rejection reaches the caller as *ipc.RPCError
// with Code AND Message intact. Both are load-bearing — the Code drives exitForError's
// mapping, and the message is the only thing telling the two CodeLocked situations apart
// (a locked vault vs. a dangerous-tier identity whose fresh presence check was skipped
// under no_prompt), which is why Task 8 relays the daemon's text rather than its own.
func TestSopsUnwrapSurfacesRPCError(t *testing.T) {
	const msg = `sops unwrap "prod": dangerous-tier identity needs a fresh presence check, and this caller set no_prompt`
	stub := newSopsStub(t, func(req ipc.Request) ipc.Response {
		return ipc.Response{ID: req.ID, Error: &ipc.RPCError{Code: ipc.CodeLocked, Message: msg}}
	})

	_, err := New(stub.path).SopsUnwrap([]byte(testRecipient(t).String()), nil)
	rpc, ok := err.(*ipc.RPCError)
	if !ok {
		t.Fatalf("err type = %T, want *ipc.RPCError", err)
	}
	if rpc.Code != ipc.CodeLocked || rpc.Message != msg {
		t.Fatalf("err = %+v, want CodeLocked carrying the daemon's message verbatim", rpc)
	}
}

// TestSopsUnwrapThreadsNoPrompt: the agent opt-out must reach the daemon, or an unwrap on
// a locked vault blocks a machine on a Touch ID nobody is there to answer instead of
// returning the clean CodeLocked pause.
func TestSopsUnwrapThreadsNoPrompt(t *testing.T) {
	stub := newSopsStub(t, sopsOK([]byte("k")))

	if _, err := New(stub.path).WithNoPrompt(true).SopsUnwrap([]byte(testRecipient(t).String()), nil); err != nil {
		t.Fatalf("SopsUnwrap: %v", err)
	}
	if !stub.only(t).NoPrompt {
		t.Fatal("NoPrompt did not reach the daemon")
	}
}

// testRecipient returns a real age recipient so the tests exercise the exact value the
// plugin will pass rather than a hand-written "age1…" lookalike.
func testRecipient(t *testing.T) *age.X25519Recipient {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id.Recipient()
}
