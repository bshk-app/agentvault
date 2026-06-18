package daemon

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/transport"
)

// TestHandleReapsIdleConn proves the connection idle deadline: a verified peer that
// connects, then sends NOTHING, must have its connection closed by the daemon after
// idleTimeout — so a stalled peer can't park a handle goroutine forever. The timeout
// is injected as a tiny value (the production default is 5 min) to keep the test fast.
func TestHandleReapsIdleConn(t *testing.T) {
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	srv.idleTimeout = 50 * time.Millisecond // tiny injected timeout (default is connIdleTimeout)
	go srv.Serve()
	defer srv.Close()

	c, err := transport.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Send nothing. The daemon's read deadline must fire and close the conn, so a
	// blocking read on our side returns (EOF or a reset) rather than hanging forever.
	// Bound our own read so a regression (no deadline) fails the test instead of
	// hanging it.
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	var resp ipc.Response
	err = ipc.NewDecoder(c).Decode(&resp)
	if err == nil {
		t.Fatalf("idle conn must be closed by daemon, got a response: %+v", resp)
	}
	// A client-side timeout would mean the daemon never closed (deadline didn't fire).
	if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
		t.Fatalf("daemon did not reap the idle conn within the window (client read timed out): %v", err)
	}
	_ = err // EOF / connection reset is the expected reap signal
}

// TestHandleResetsDeadlinePerRequest proves the deadline is reset per request: with
// a small (but non-trivial) idle timeout, a steady drip of requests — each within the
// window but together exceeding it — must ALL succeed, because every request bumps the
// deadline. This guards against a regression that sets one total deadline and kills a
// long but active stream (the `av scrub` flow).
func TestHandleResetsDeadlinePerRequest(t *testing.T) {
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	srv.idleTimeout = 200 * time.Millisecond
	go srv.Serve()
	defer srv.Close()

	c, err := transport.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	enc := ipc.NewEncoder(c)
	dec := ipc.NewDecoder(c)

	// Five pings, each ~120ms apart: total ~600ms > idleTimeout (200ms), but each gap
	// is under it, so the per-request reset keeps the conn alive throughout.
	for i := uint64(1); i <= 5; i++ {
		if err := enc.Encode(ipc.Request{ID: i, Method: "ping"}); err != nil {
			t.Fatalf("ping %d encode: %v", i, err)
		}
		var resp ipc.Response
		if err := dec.Decode(&resp); err != nil {
			t.Fatalf("ping %d decode (deadline reset failed?): %v", i, err)
		}
		var pong string
		json.Unmarshal(resp.Result, &pong)
		if pong != "pong" {
			t.Fatalf("ping %d result = %q, want pong", i, pong)
		}
		time.Sleep(120 * time.Millisecond)
	}
}

// TestHandleNormalRequestWithinTimeout confirms a normal request still works when an
// idle timeout is set (the deadline must not reject an in-window request). It also
// asserts the conn is then reaped after going idle, proving the deadline is active.
func TestHandleNormalRequestWithinTimeout(t *testing.T) {
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	srv.idleTimeout = 100 * time.Millisecond
	go srv.Serve()
	defer srv.Close()

	c, err := transport.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	enc := ipc.NewEncoder(c)
	dec := ipc.NewDecoder(c)

	if err := enc.Encode(ipc.Request{ID: 1, Method: "ping"}); err != nil {
		t.Fatal(err)
	}
	var resp ipc.Response
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("normal in-window request must succeed: %v", err)
	}
	var pong string
	json.Unmarshal(resp.Result, &pong)
	if pong != "pong" {
		t.Fatalf("result = %q, want pong", pong)
	}

	// Now go idle: the daemon must reap the conn after the window elapses. EOF or a
	// reset is the expected reap signal; a client-side timeout means it didn't fire.
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err := dec.Decode(&resp); err == nil {
		t.Fatalf("conn must be reaped after going idle, got: %+v", resp)
	} else if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
		t.Fatalf("daemon did not reap idle conn (client timed out): %v", err)
	}
}
