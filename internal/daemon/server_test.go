package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/transport"
)

// shortTempBase is the parent for a temp dir that will hold a unix socket: macOS caps
// sun_path near 104 bytes and t.TempDir()'s /var/folders/... base blows it before the
// test can say anything useful. Windows uses a named pipe with no such cap and has no
// /tmp at all, so there the OS temp dir ("") is both correct and the only thing that
// exists. Same reasoning as cmd/age-plugin-av/main_test.go.
func shortTempBase() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return "/tmp"
}

// shortSocketPath returns a socket path under shortTempBase().
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(shortTempBase(), "avd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "avd.sock")
}

func TestServePing(t *testing.T) {
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	defer srv.Close()

	c, err := transport.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := ipc.NewEncoder(c).Encode(ipc.Request{ID: 1, Method: "ping"}); err != nil {
		t.Fatal(err)
	}
	var resp ipc.Response
	if err := ipc.NewDecoder(c).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	var pong string
	json.Unmarshal(resp.Result, &pong)
	if pong != "pong" {
		t.Fatalf("result = %q, want pong", pong)
	}
}

func TestUnknownMethod(t *testing.T) {
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	defer srv.Close()

	c, err := transport.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ipc.NewEncoder(c).Encode(ipc.Request{ID: 2, Method: "nope"})
	var resp ipc.Response
	ipc.NewDecoder(c).Decode(&resp)
	if resp.Error == nil || resp.Error.Code != ipc.CodeBadRequest {
		t.Fatalf("want CodeBadRequest, got %+v", resp.Error)
	}
}

// TestHandleRejectsUnverifiedPeer exercises the actual security gate in handle():
// when the peer-credential check fails, the connection must be rejected with
// CodeUnauthorized and closed BEFORE any request is dispatched. A foreign UID
// can't be forged locally, so we inject a forced-reject checkPeer via the seam.
func TestHandleRejectsUnverifiedPeer(t *testing.T) {
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	// Override the seam BEFORE Serve(): every peer is now rejected, simulating a
	// foreign UID that the local kernel would never let us forge for real.
	srv.checkPeer = func(net.Conn) error { return fmt.Errorf("forced reject") }
	go srv.Serve()
	defer srv.Close()

	c, err := transport.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Send a ping — it must NEVER be dispatched (no "pong" must ever come back).
	//
	// handle() deliberately never READS from an unverified peer: it writes the rejection
	// and closes with this ping still sitting unread in the server's receive queue. Linux
	// answers unread data with an RST, which both fails this write with EPIPE and can
	// discard the rejection that was already in flight; macOS lets the write land and
	// delivers a clean EOF afterwards. So on Linux the run may end at any of the three
	// points below. Each of them proves the one thing this test is about — the request was
	// never dispatched — and none of them may produce a pong.
	if err := ipc.NewEncoder(c).Encode(ipc.Request{ID: 1, Method: "ping"}); err != nil {
		if !isPeerHangup(err) {
			t.Fatalf("unexpected write error: %v", err)
		}
		return // closed before the request even landed
	}

	dec := ipc.NewDecoder(c)
	var resp ipc.Response
	if err := dec.Decode(&resp); err != nil {
		if !isPeerHangup(err) {
			t.Fatalf("expected an unauthorized response, got decode error: %v", err)
		}
		return // rejection lost to the RST; still nothing dispatched
	}
	// The single response must be the unauthorized rejection, not a pong result.
	if resp.Error == nil || resp.Error.Code != ipc.CodeUnauthorized {
		t.Fatalf("want CodeUnauthorized, got error=%+v result=%s", resp.Error, resp.Result)
	}
	if resp.Result != nil {
		t.Fatalf("rejected peer must not receive a dispatched result, got %s", resp.Result)
	}

	// The connection must then be CLOSED, proving the ping was never dispatched and no
	// "pong" ever follows the rejection. What must not happen is a successful decode.
	var after ipc.Response
	if err := dec.Decode(&after); !isPeerHangup(err) {
		t.Fatalf("conn must be closed after reject, got err=%v resp=%+v", err, after)
	}
}

// isPeerHangup reports whether err is "the server closed the connection" — as opposed to
// a protocol error, which is a real failure.
//
// Which errno that close produces is the platform's choice, not the daemon's: a clean
// io.EOF on macOS, ECONNRESET (reading) or EPIPE (writing) on Linux, where the RST that
// answers the unread request also tears down the buffers. Asserting io.EOF alone encoded
// a macOS detail as if it were the contract, and it failed the first time this suite ran
// on Linux.
func isPeerHangup(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE)
}

// TestSecondInstanceRefuses asserts the single-instance liveness guard: a second
// daemon.New on the same path must refuse (return an error) rather than clobber
// the live daemon's socket. The first server must keep answering ping.
func TestSecondInstanceRefuses(t *testing.T) {
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	defer srv.Close()

	// Second instance must refuse: a live peer answers on the socket.
	if srv2, err := New(path); err == nil {
		srv2.Close()
		t.Fatal("second New must refuse while a live daemon is listening")
	}

	// The original daemon must still be answering on the same socket.
	c, err := transport.Dial(path)
	if err != nil {
		t.Fatalf("first daemon should still be reachable: %v", err)
	}
	defer c.Close()
	if err := ipc.NewEncoder(c).Encode(ipc.Request{ID: 3, Method: "ping"}); err != nil {
		t.Fatal(err)
	}
	var resp ipc.Response
	if err := ipc.NewDecoder(c).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != nil {
		t.Fatalf("first daemon ping failed: %v", resp.Error)
	}
	var pong string
	json.Unmarshal(resp.Result, &pong)
	if pong != "pong" {
		t.Fatalf("first daemon result = %q, want pong", pong)
	}
}
