package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
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

// onlyParams decodes the params of the ONE request the stub received into into, checking
// the method on the way. Insisting on exactly one also catches a stray extra dial (an
// ensureFresh version probe, a retry) that would make the byte-identity assertions below
// read the wrong request.
func (s *sopsStub) onlyParams(t *testing.T, method string, into any) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reqs) != 1 {
		t.Fatalf("stub saw %d requests, want 1", len(s.reqs))
	}
	if s.reqs[0].Method != method {
		t.Fatalf("method = %q, want %s", s.reqs[0].Method, method)
	}
	if err := json.Unmarshal(s.reqs[0].Params, into); err != nil {
		t.Fatalf("unmarshal params: %v", err)
	}
}

// only is onlyParams for the unwrap RPC, which every test in the first half uses.
func (s *sopsStub) only(t *testing.T) ipc.SopsUnwrapParams {
	t.Helper()
	var p ipc.SopsUnwrapParams
	s.onlyParams(t, "sops_unwrap", &p)
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

// The rest of this file covers the management methods behind `av sops keygen | import |
// ls | rm`. They are driven against the stub for the same reason SopsUnwrap is: what is
// under test is the REQUEST the client builds and the reply it decodes — above all that a
// private key crosses byte-identical and that no method can hand one back.

// sopsReply answers with any result value, marshaled as the daemon would.
func sopsReply(v any) func(ipc.Request) ipc.Response {
	return func(req ipc.Request) ipc.Response {
		res, _ := json.Marshal(v)
		return ipc.Response{ID: req.ID, Result: res}
	}
}

// sopsInfoFor builds the reply the daemon sends for a real identity: the public recipient
// and the pointer sopsplugin.EncodeIdentity renders from it. The pointer is hard-coded as
// its literal prefix + payload here rather than imported, because this package must not
// link sopsplugin — it is compiled into the thin av (TestAvStaysThin).
func sopsInfoFor(t *testing.T, name, tier string) ipc.SopsIdentityInfo {
	t.Helper()
	r := testRecipient(t)
	return ipc.SopsIdentityInfo{
		Name:      name,
		Tier:      tier,
		Recipient: r.String(),
		Identity:  "AGE-PLUGIN-AV-1" + strings.ToUpper(name), // opaque to av: it only ferries it
	}
}

// TestSopsKeygenSendsNameAndTierAndReturnsThePointer: the daemon generates the key, and the
// client hands back the public view of it — including the AGE-PLUGIN-AV-1… pointer, which
// is the field `av sops import` writes into keys.txt and cannot compute for itself.
func TestSopsKeygenSendsNameAndTierAndReturnsThePointer(t *testing.T) {
	want := sopsInfoFor(t, "work", "dangerous")
	stub := newSopsStub(t, sopsReply(want))

	got, err := New(stub.path).SopsKeygen("work", "dangerous")
	if err != nil {
		t.Fatalf("SopsKeygen: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("result = %+v, want %+v", got, want)
	}
	var p ipc.SopsKeygenParams
	stub.onlyParams(t, "sops_keygen", &p)
	if p.Name != "work" || p.Tier != "dangerous" {
		t.Fatalf("params = %+v, want name=work tier=dangerous", p)
	}
}

// TestSopsPutSendsTheKeyByteIdentical is the trap this method has to avoid: the value is an
// AGE-SECRET-KEY-1… private key that `av` reads out of keys.txt and ferries WITHOUT parsing
// it (parsing would mean linking age, which av must not). Anything that reshapes those
// bytes on the way — a second encoding, a trim, a cast through a rune-aware type — still
// arrives as some []byte, so the daemon would simply report "not an age private key" and
// the user would be told their working key is invalid.
func TestSopsPutSendsTheKeyByteIdentical(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	sent := []byte(id.String() + "\n") // exactly what a line of keys.txt yields
	stub := newSopsStub(t, sopsReply(sopsInfoFor(t, "personal", "normal")))

	if _, err := New(stub.path).SopsPut("personal", "normal", sent); err != nil {
		t.Fatalf("SopsPut: %v", err)
	}
	var p ipc.SopsPutParams
	stub.onlyParams(t, "sops_put", &p)
	if !bytes.Equal(p.Value, sent) {
		// SECURITY: neither side is printed — both are the private key.
		t.Fatalf("the key arrived as %d bytes, want the caller's %d unaltered", len(p.Value), len(sent))
	}
	if p.Name != "personal" || p.Tier != "normal" {
		t.Fatalf("params = name %q tier %q, want personal/normal", p.Name, p.Tier)
	}
}

// TestSopsListReturnsIdentities: the listing comes back in the daemon's order (Store.List
// sorts by name) with every field `av sops ls`, `recipient` and `identity` need — which is
// why those last two are printers over this one reply rather than RPCs of their own.
func TestSopsListReturnsIdentities(t *testing.T) {
	want := []ipc.SopsIdentityInfo{sopsInfoFor(t, "personal", "normal"), sopsInfoFor(t, "work", "dangerous")}
	stub := newSopsStub(t, sopsReply(ipc.SopsListResult{Identities: want}))

	got, err := New(stub.path).SopsList()
	if err != nil {
		t.Fatalf("SopsList: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("identities = %+v, want %+v", got, want)
	}
	// SECURITY: the reply type has no key field, so a private key cannot reach `av sops ls`
	// output even if the daemon tried to send one. Asserted by rendering the whole result
	// the way a careless caller would — %+v walks every exported field, so a field added
	// later is covered without this test being taught about it.
	if strings.Contains(fmt.Sprintf("%+v", got), "AGE-SECRET-KEY") {
		t.Fatal("SECURITY: a listing carried something shaped like an age private key")
	}
	var p ipc.SopsListParams
	stub.onlyParams(t, "sops_list", &p)
}

// TestSopsRemoveSendsTheNameAndSurfacesNotFound: rm carries a name and no value, and a name
// nobody stored comes back as *ipc.RPCError with CodeBadRequest — not a silent success.
// `av sops rm` deletes the only copy of a key; reporting "removed" over a typo would leave
// a user believing a key is gone that is still there.
func TestSopsRemoveSendsTheNameAndSurfacesNotFound(t *testing.T) {
	const msg = `sops rm "typo": no such SOPS identity`
	stub := newSopsStub(t, func(req ipc.Request) ipc.Response {
		return ipc.Response{ID: req.ID, Error: &ipc.RPCError{Code: ipc.CodeBadRequest, Message: msg}}
	})

	err := New(stub.path).SopsRemove("typo")
	rpc, ok := err.(*ipc.RPCError)
	if !ok {
		t.Fatalf("err type = %T, want *ipc.RPCError", err)
	}
	if rpc.Code != ipc.CodeBadRequest || rpc.Message != msg {
		t.Fatalf("err = %+v, want CodeBadRequest carrying the daemon's message verbatim", rpc)
	}
	var p ipc.SopsRmParams
	stub.onlyParams(t, "sops_rm", &p)
	if p.Name != "typo" {
		t.Fatalf("name = %q, want typo", p.Name)
	}
}

// TestSopsManageThreadsNoPrompt: every management method must carry the agent opt-out, or
// an `av sops ls` from an agent blocks a machine on a Touch ID nobody is there to answer
// instead of returning the clean CodeLocked pause.
func TestSopsManageThreadsNoPrompt(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		method string
		call   func(*Client) error
		params func() any
	}{
		{"sops_keygen", func(c *Client) error { _, err := c.SopsKeygen("work", ""); return err }, func() any { return &ipc.SopsKeygenParams{} }},
		{"sops_put", func(c *Client) error { _, err := c.SopsPut("work", "", []byte(key.String())); return err }, func() any { return &ipc.SopsPutParams{} }},
		{"sops_list", func(c *Client) error { _, err := c.SopsList(); return err }, func() any { return &ipc.SopsListParams{} }},
		{"sops_rm", func(c *Client) error { return c.SopsRemove("work") }, func() any { return &ipc.SopsRmParams{} }},
	}
	for _, c := range cases {
		t.Run(c.method, func(t *testing.T) {
			stub := newSopsStub(t, sopsReply(sopsInfoFor(t, "work", "normal")))
			if err := c.call(New(stub.path).WithNoPrompt(true)); err != nil {
				t.Fatalf("%s: %v", c.method, err)
			}
			p := c.params()
			stub.onlyParams(t, c.method, p)
			// Every params type spells the field the same way, so one reflective read
			// covers all four without a switch that could quietly skip one.
			if !reflect.ValueOf(p).Elem().FieldByName("NoPrompt").Bool() {
				t.Fatal("NoPrompt did not reach the daemon")
			}
		})
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
