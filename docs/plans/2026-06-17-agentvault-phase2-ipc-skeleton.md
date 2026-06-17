# AgentVault Phase 2 — IPC Walking Skeleton Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (or subagent-driven-development) to implement this plan task-by-task.

**Goal:** Prove the transport before any secret logic: `av` talks to `avd` over a peer-credential-checked, `0600` unix-domain socket using newline-delimited JSON-RPC, and `av` autostarts `avd` on first use. End state: `av ping` prints `pong` from the daemon.

**Architecture:** Two new binaries (`cmd/avd`, `cmd/av`) over a tiny `internal/ipc` (JSON-RPC framing) and `internal/transport` (socket path, listener `0600`, dialer, `getpeereid` peer-cred check). No backends, no auth, no redaction yet — this is the wiring that every later phase rides on. `avd` runs as a per-user process (a real `launchd` LaunchAgent comes in Phase 5); for now `av` autostarts it as a detached child.

**Tech Stack:** Go 1.26.3, stdlib + `golang.org/x/sys/unix` (for `Getpeereid`; lightweight, not the gitleaks tree). Module `github.com/beshkenadze/agentvault`. macOS only.

**Scope:** Phase 2 only. Phase 1 (redaction core, package `internal/redact` + `internal/detect/gitleaks`) is complete on `main`. Later phases: 3 backends+manifest, 4 session + `av run` (wires redaction layers), 5 Touch ID + dangerous tier, 6 hardening + adapter.

**Design reference:** `docs/plans/2026-06-17-agentvault-design.md` — *IPC* and *Architecture / Division of labour*.

**Carry-forward from Phase 1 final review:**
- Establishing `cmd/av` lets us make the "thin `av` must NOT link gitleaks" invariant **CI-enforced** (Task 1 adds a `go list -deps` guard test). Keep it green every later phase.
- The `Makefile build` target currently builds `./...`; Task 1 restores the per-binary targets now that `cmd/` exists.

---

## Task 1: Binary skeletons + dependency-isolation guard

**Files:**
- Create: `cmd/avd/main.go`
- Create: `cmd/av/main.go`
- Create: `cmd/av/deps_test.go`
- Modify: `Makefile` (restore per-binary build targets)

**Step 1: Write the failing guard test**

`cmd/av/deps_test.go` — enforces that the thin `av` binary never links the gitleaks dependency tree:
```go
package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The av binary must stay thin: it must never transitively import gitleaks or its
// heavy tree (wazero, viper, afero). This guards the architecture invariant from
// the design (gitleaks lives only in avd's path).
func TestAvDoesNotLinkGitleaks(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	for _, bad := range []string{"gitleaks", "wazero", "spf13/viper", "spf13/afero"} {
		if strings.Contains(string(out), bad) {
			t.Errorf("av must not link %q", bad)
		}
	}
}
```

**Step 2: Run it to verify it fails**

Run: `go test ./cmd/av/ -run TestAvDoesNotLinkGitleaks -v`
Expected: FAIL — `cmd/av` has no `main.go` yet (build error / no Go files).

**Step 3: Create minimal binaries**

`cmd/avd/main.go`:
```go
// Command avd is the AgentVault broker daemon.
package main

func main() {
	// Phase 2 fills this in (serve loop). Placeholder so the package builds.
}
```

`cmd/av/main.go`:
```go
// Command av is the thin AgentVault CLI.
package main

func main() {
	// Phase 2 fills this in (client). Placeholder so the package builds.
}
```

**Step 4: Run the guard test to verify it passes**

Run: `go test ./cmd/av/ -v`
Expected: PASS (stub imports nothing heavy).

**Step 5: Restore Makefile per-binary targets**

Replace the `build` target:
```makefile
build:
	go build -o bin/avd ./cmd/avd
	go build -o bin/av ./cmd/av
```

Run: `make build` → creates `bin/avd` and `bin/av`. Expected exit 0.

**Step 6: Commit**

```bash
git add cmd/ Makefile
git commit -m "feat(cmd): av/avd skeletons + av thin-binary dependency guard"
```

---

## Task 2: JSON-RPC framing (`internal/ipc`)

Newline-delimited JSON. One request type, one response type. Trivial parser, minimal surface (design: "Minimal protocol, minimal parser").

**Files:**
- Create: `internal/ipc/proto.go`
- Test: `internal/ipc/proto_test.go`

**Step 1: Write the failing test**

`internal/ipc/proto_test.go`:
```go
package ipc

import (
	"bytes"
	"encoding/json"
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
```

**Step 2: Run test, verify it fails**

Run: `go test ./internal/ipc/ -v`
Expected: FAIL — undefined types.

**Step 3: Implement**

`internal/ipc/proto.go`:
```go
// Package ipc defines AgentVault's newline-delimited JSON-RPC framing.
package ipc

import (
	"bufio"
	"encoding/json"
	"io"
)

// Request is a single client call. Params is method-specific and may be empty.
type Request struct {
	ID     uint64          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response is the daemon's reply. Exactly one of Result/Error is set.
type Response struct {
	ID     uint64          `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *RPCError       `json:"error,omitempty"`
}

// RPCError carries a stable code so the agent can branch (e.g. locked vs denied).
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string { return e.Message }

// Stable error codes (extended in later phases).
const (
	CodeInternal     = 1
	CodeBadRequest   = 2
	CodeLocked       = 3 // vault locked — agent should ask a human to unlock
	CodeDenied       = 4 // dangerous-tier denied / no presence
	CodeUnauthorized = 5 // peer-credential check failed
)

// Encoder writes newline-delimited JSON values. json.Encoder already appends '\n'.
type Encoder struct{ enc *json.Encoder }

func NewEncoder(w io.Writer) *Encoder { return &Encoder{enc: json.NewEncoder(w)} }
func (e *Encoder) Encode(v any) error { return e.enc.Encode(v) }

// Decoder reads newline-delimited JSON values. A bufio.Scanner bounds line length.
type Decoder struct{ sc *bufio.Scanner }

func NewDecoder(r io.Reader) *Decoder {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // 1 MiB max line
	return &Decoder{sc: sc}
}

func (d *Decoder) Decode(v any) error {
	if !d.sc.Scan() {
		if err := d.sc.Err(); err != nil {
			return err
		}
		return io.EOF
	}
	return json.Unmarshal(d.sc.Bytes(), v)
}
```

**Step 4: Run tests, verify pass**

Run: `go test ./internal/ipc/ -v` → PASS.

**Step 5: Commit**

```bash
git add internal/ipc/
git commit -m "feat(ipc): newline-delimited JSON-RPC framing"
```

---

## Task 3: Socket path, listener (0600), dialer (`internal/transport`)

**Files:**
- Create: `internal/transport/socket.go`
- Test: `internal/transport/socket_test.go`

Notes for the engineer:
- macOS rarely sets `$XDG_RUNTIME_DIR`; fall back to `os.UserCacheDir()` (`~/Library/Caches`). Keep the full socket path well under the macOS `sun_path` 104-byte limit (it is: `~/Library/Caches/agentvault/avd.sock`).
- The socket file's mode must be `0600` and its parent dir `0700`. Create the dir first, then `net.Listen("unix", path)`, then `os.Chmod(path, 0600)` (umask can interfere; chmod is explicit).

**Step 1: Write the failing test**

`internal/transport/socket_test.go`:
```go
package transport

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListenCreates0600Socket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "avd.sock")
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket mode = %o, want 600", perm)
	}
}

func TestDialConnects(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "avd.sock")
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()
	c, err := Dial(path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()
}

func TestDefaultSocketPathUnderRuntimeDir(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/tmp/xdg-test")
	p, err := DefaultSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	if want := "/tmp/xdg-test/agentvault/avd.sock"; p != want {
		t.Fatalf("path = %q, want %q", p, want)
	}
}
```

**Step 2: Run test, verify fails**

Run: `go test ./internal/transport/ -v`
Expected: FAIL — undefined `Listen`/`Dial`/`DefaultSocketPath`.

**Step 3: Implement**

`internal/transport/socket.go`:
```go
// Package transport provides AgentVault's local unix-socket listener and dialer,
// with a strict 0600 socket and a peer-credential check (see peercred_*.go).
package transport

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// DefaultSocketPath returns the daemon socket path: $XDG_RUNTIME_DIR/agentvault/avd.sock
// if set, else <user-cache-dir>/agentvault/avd.sock (macOS: ~/Library/Caches/...).
func DefaultSocketPath() (string, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		c, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		base = c
	}
	return filepath.Join(base, "agentvault", "avd.sock"), nil
}

// Listen creates the parent dir (0700), binds a unix socket at path, and chmods it 0600.
// A stale socket file is removed first.
func Listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// Remove a stale socket (caller is responsible for single-instance checks).
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove stale socket: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// Dial connects to the daemon socket.
func Dial(path string) (net.Conn, error) {
	return net.Dial("unix", path)
}
```

**Step 4: Run tests, verify pass**

Run: `go test ./internal/transport/ -v` → PASS.

**Step 5: Commit**

```bash
git add internal/transport/
git commit -m "feat(transport): unix socket listener (0600) + dialer + path resolution"
```

---

## Task 4: Peer-credential check (`getpeereid`, macOS)

The daemon must verify the connecting client runs as the same UID. macOS uses `getpeereid`.

**Files:**
- Create: `internal/transport/peercred_darwin.go` (build tag `//go:build darwin`)
- Test: `internal/transport/peercred_test.go`
- Modify: `go.mod` (add `golang.org/x/sys`)

Notes for the engineer (verify against the platform — this is the trickiest bit):
- Get the raw fd from the accepted `*net.UnixConn` via `SyscallConn()` then `rc.Control(func(fd uintptr){ ... })`, and call `unix.Getpeereid(int(fd))` inside Control (so the fd stays valid).
- Cross-UID rejection can't be exercised under a single test UID. Test the **happy path** (self-connection returns our own UID and `CheckPeer` passes) and unit-test the comparison logic by injecting a UID.

**Step 1: Write the failing test**

`internal/transport/peercred_test.go`:
```go
package transport

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestPeerUIDSelf(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.sock")
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan uint32, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		uid, err := PeerUID(c)
		if err != nil {
			t.Errorf("PeerUID: %v", err)
			got <- ^uint32(0)
			return
		}
		got <- uid
	}()

	c, err := Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if uid := <-got; uid != uint32(os.Getuid()) {
		t.Fatalf("peer uid = %d, want %d", uid, os.Getuid())
	}
}

func TestCheckPeerRejectsOtherUID(t *testing.T) {
	// Pure logic: a different uid must be rejected.
	if checkUID(uint32(os.Getuid())+1, uint32(os.Getuid())) == nil {
		t.Fatal("expected rejection for mismatched uid")
	}
	if err := checkUID(uint32(os.Getuid()), uint32(os.Getuid())); err != nil {
		t.Fatalf("same uid should pass: %v", err)
	}
}
```

**Step 2: Run test, verify fails**

Run: `go test ./internal/transport/ -run 'TestPeer|TestCheckPeer' -v`
Expected: FAIL — `PeerUID`/`checkUID` undefined.

**Step 3: Add dependency**

Run: `go get golang.org/x/sys/unix@latest` (lightweight; confirm it does not pull anything heavy).

**Step 4: Implement**

`internal/transport/peercred_darwin.go`:
```go
//go:build darwin

package transport

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// PeerUID returns the UID of the process on the other end of a unix-socket conn.
func PeerUID(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("not a unix conn: %T", c)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		u, _, e := unix.Getpeereid(int(fd))
		uid, cerr = uint32(u), e
	}); err != nil {
		return 0, err
	}
	return uid, cerr
}

// checkUID returns an error unless peer == self.
func checkUID(peer, self uint32) error {
	if peer != self {
		return fmt.Errorf("peer uid %d != daemon uid %d", peer, self)
	}
	return nil
}

// CheckPeer rejects a connection whose peer UID differs from this process's UID.
func CheckPeer(c net.Conn) error {
	peer, err := PeerUID(c)
	if err != nil {
		return err
	}
	return checkUID(peer, uint32(unix.Getuid()))
}
```

**Step 5: Run tests, verify pass**

Run: `go test ./internal/transport/ -v` → PASS. Run `go vet ./...`.

**Step 6: Commit**

```bash
git add internal/transport/peercred_darwin.go internal/transport/peercred_test.go go.mod go.sum
git commit -m "feat(transport): getpeereid peer-credential check (macOS)"
```

---

## Task 5: avd serve loop + ping handler + graceful shutdown

**Files:**
- Create: `internal/daemon/server.go`
- Test: `internal/daemon/server_test.go`
- Modify: `cmd/avd/main.go`

**Step 1: Write the failing test**

`internal/daemon/server_test.go`:
```go
package daemon

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/transport"
)

func TestServePing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "avd.sock")
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
	dir := t.TempDir()
	path := filepath.Join(dir, "avd.sock")
	srv, _ := New(path)
	go srv.Serve()
	defer srv.Close()

	c, _ := transport.Dial(path)
	defer c.Close()
	ipc.NewEncoder(c).Encode(ipc.Request{ID: 2, Method: "nope"})
	var resp ipc.Response
	ipc.NewDecoder(c).Decode(&resp)
	if resp.Error == nil || resp.Error.Code != ipc.CodeBadRequest {
		t.Fatalf("want CodeBadRequest, got %+v", resp.Error)
	}
}
```

**Step 2: Run, verify fails**

Run: `go test ./internal/daemon/ -v` → FAIL (undefined `New`).

**Step 3: Implement**

`internal/daemon/server.go`:
```go
// Package daemon implements the avd serve loop. Phase 2 handles only "ping";
// later phases add resolve/scrub/lock/etc. on the same dispatch.
package daemon

import (
	"encoding/json"
	"errors"
	"net"

	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/transport"
)

type Server struct {
	ln net.Listener
}

func New(path string) (*Server, error) {
	ln, err := transport.Listen(path)
	if err != nil {
		return nil, err
	}
	return &Server{ln: ln}, nil
}

func (s *Server) Serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return // listener closed
		}
		go s.handle(c)
	}
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	if err := transport.CheckPeer(c); err != nil {
		_ = ipc.NewEncoder(c).Encode(ipc.Response{
			Error: &ipc.RPCError{Code: ipc.CodeUnauthorized, Message: "peer rejected"},
		})
		return
	}
	dec := ipc.NewDecoder(c)
	enc := ipc.NewEncoder(c)
	for {
		var req ipc.Request
		if err := dec.Decode(&req); err != nil {
			return // EOF / closed
		}
		enc.Encode(s.dispatch(req))
	}
}

func (s *Server) dispatch(req ipc.Request) ipc.Response {
	switch req.Method {
	case "ping":
		r, _ := json.Marshal("pong")
		return ipc.Response{ID: req.ID, Result: r}
	default:
		return ipc.Response{ID: req.ID, Error: &ipc.RPCError{
			Code: ipc.CodeBadRequest, Message: "unknown method: " + req.Method,
		}}
	}
}

func (s *Server) Close() error {
	err := s.ln.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
```

`cmd/avd/main.go` — wire it up with signal-based shutdown:
```go
// Command avd is the AgentVault broker daemon.
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/beshkenadze/agentvault/internal/daemon"
	"github.com/beshkenadze/agentvault/internal/transport"
)

func main() {
	path, err := transport.DefaultSocketPath()
	if err != nil {
		log.Fatalf("avd: socket path: %v", err)
	}
	srv, err := daemon.New(path)
	if err != nil {
		log.Fatalf("avd: listen: %v", err)
	}
	go srv.Serve()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	srv.Close()
	os.Remove(path)
}
```

**Step 4: Run, verify pass**

Run: `go test ./internal/daemon/ -v` → PASS. `go build ./...`. `go vet ./...`.

**Step 5: Commit**

```bash
git add internal/daemon/ cmd/avd/main.go
git commit -m "feat(daemon): avd serve loop with ping + peer-cred gate + graceful shutdown"
```

---

## Task 6: av client + autostart

`av ping` connects; if the daemon isn't running, it starts `avd` (detached) and retries.

**Files:**
- Create: `internal/client/client.go`
- Test: `internal/client/client_test.go`
- Modify: `cmd/av/main.go`

Notes for the engineer:
- Autostart must locate the `avd` binary. KISS: look for `avd` in the same directory as the running `av` (`os.Executable()` → sibling), else fall back to `PATH`. Make this overridable via env `AV_AVD_PATH` for tests.
- Start `avd` detached: `cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}`, redirect its stdio away from the agent, and do **not** `Wait`. Then poll-dial the socket with a short timeout (e.g. 2s, 20×100ms).
- Test the client against an in-process `daemon.Server` (no autostart) for the happy path, and test autostart separately by pointing `AV_AVD_PATH` at a built `avd` in a temp dir (an integration test that calls `go build` first, or `t.Skip` if building is too heavy for the unit suite).

**Step 1: Write the failing test (client against a running server)**

`internal/client/client_test.go`:
```go
package client

import (
	"path/filepath"
	"testing"

	"github.com/beshkenadze/agentvault/internal/daemon"
)

func TestPingAgainstRunningServer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "avd.sock")
	srv, err := daemon.New(path)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	defer srv.Close()

	cl := New(path)
	got, err := cl.Ping()
	if err != nil {
		t.Fatal(err)
	}
	if got != "pong" {
		t.Fatalf("ping = %q, want pong", got)
	}
}
```

**Step 2: Run, verify fails**

Run: `go test ./internal/client/ -v` → FAIL (undefined).

**Step 3: Implement**

`internal/client/client.go`:
```go
// Package client is the av-side RPC client with daemon autostart.
package client

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/transport"
)

type Client struct{ path string }

func New(path string) *Client { return &Client{path: path} }

// call dials (autostarting avd if needed), sends one request, returns the response.
func (c *Client) call(req ipc.Request) (ipc.Response, error) {
	conn, err := transport.Dial(c.path)
	if err != nil {
		if serr := autostart(c.path); serr != nil {
			return ipc.Response{}, fmt.Errorf("dial and autostart failed: %w", serr)
		}
		conn, err = dialRetry(c.path, 2*time.Second)
		if err != nil {
			return ipc.Response{}, err
		}
	}
	defer conn.Close()
	if err := ipc.NewEncoder(conn).Encode(req); err != nil {
		return ipc.Response{}, err
	}
	var resp ipc.Response
	if err := ipc.NewDecoder(conn).Decode(&resp); err != nil {
		return ipc.Response{}, err
	}
	return resp, nil
}

func dialRetry(path string, total time.Duration) (conn /* net.Conn */ any, err error) {
	// implement: loop transport.Dial every 100ms until total elapses
	panic("implement: return net.Conn")
}

func (c *Client) Ping() (string, error) {
	resp, err := c.call(ipc.Request{ID: 1, Method: "ping"})
	if err != nil {
		return "", err
	}
	if resp.Error != nil {
		return "", resp.Error
	}
	var pong string
	if err := json.Unmarshal(resp.Result, &pong); err != nil {
		return "", err
	}
	return pong, nil
}
```
(The `dialRetry` signature above is a placeholder — implement it returning `net.Conn`; adjust `call` accordingly. Keep `autostart` in a separate file `autostart_darwin.go` so the detached-process logic is platform-scoped.)

`internal/client/autostart_darwin.go`:
```go
//go:build darwin

package client

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// autostart launches avd detached. It looks for avd via AV_AVD_PATH, then next to
// the running av binary, then on PATH.
func autostart(socketPath string) error {
	bin := os.Getenv("AV_AVD_PATH")
	if bin == "" {
		if self, err := os.Executable(); err == nil {
			cand := filepath.Join(filepath.Dir(self), "avd")
			if _, err := os.Stat(cand); err == nil {
				bin = cand
			}
		}
	}
	if bin == "" {
		bin = "avd" // PATH
	}
	cmd := exec.Command(bin)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	return cmd.Start() // do not Wait
}
```

`cmd/av/main.go`:
```go
// Command av is the thin AgentVault CLI.
package main

import (
	"fmt"
	"os"

	"github.com/beshkenadze/agentvault/internal/client"
	"github.com/beshkenadze/agentvault/internal/transport"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "ping" {
		fmt.Fprintln(os.Stderr, "usage: av ping")
		os.Exit(2)
	}
	path, err := transport.DefaultSocketPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		os.Exit(1)
	}
	out, err := client.New(path).Ping()
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		os.Exit(1)
	}
	fmt.Println(out)
}
```

**Step 4: Run, verify pass**

Run: `go test ./internal/client/ -v` → PASS (happy path). Run `go vet ./...`. Confirm the Task 1 guard test still passes (`av` must still not link gitleaks): `go test ./cmd/av/ -v`.

**Step 5: Commit**

```bash
git add internal/client/ cmd/av/main.go
git commit -m "feat(client): av RPC client with daemon autostart; av ping"
```

---

## Task 7: Autostart integration test + security regression suite

**Files:**
- Create: `internal/client/autostart_test.go` (integration; builds avd)
- Create: `internal/transport/security_test.go`

**Step 1: Autostart integration test**

`internal/client/autostart_test.go`:
```go
package client

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Builds the real avd into a temp dir, points AV_AVD_PATH at it, and verifies a
// cold `Ping` autostarts the daemon and succeeds.
func TestAutostartColdPing(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: builds avd")
	}
	dir := t.TempDir()
	avd := filepath.Join(dir, "avd")
	build := exec.Command("go", "build", "-o", avd, "github.com/beshkenadze/agentvault/cmd/avd")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build avd: %v\n%s", err, out)
	}
	t.Setenv("AV_AVD_PATH", avd)
	t.Setenv("XDG_RUNTIME_DIR", dir) // socket under the temp dir

	cl := New(filepath.Join(dir, "agentvault", "avd.sock"))
	got, err := cl.Ping()
	if err != nil {
		t.Fatalf("cold ping: %v", err)
	}
	if got != "pong" {
		t.Fatalf("ping = %q", got)
	}
	// best-effort: kill the daemon we spawned
	exec.Command("pkill", "-f", avd).Run()
	_ = os.Remove(filepath.Join(dir, "agentvault", "avd.sock"))
}
```
Run: `go test ./internal/client/ -run TestAutostart -v` → PASS (may take a moment to build).

**Step 2: Security regression test**

`internal/transport/security_test.go`:
```go
package transport

import (
	"os"
	"path/filepath"
	"testing"
)

// The socket must be 0600 and its parent dir 0700 — no other local user may connect.
func TestSocketAndDirPermissions(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "agentvault")
	path := filepath.Join(sub, "avd.sock")
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("socket perm = %o, want 600", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(sub); fi.Mode().Perm() != 0o700 {
		t.Errorf("dir perm = %o, want 700", fi.Mode().Perm())
	}
}

// checkUID is the peer-cred decision; a different uid must be refused.
func TestPeerCredRejectsForeignUID(t *testing.T) {
	if err := checkUID(12345, 99999); err == nil {
		t.Fatal("foreign uid must be rejected")
	}
}
```
Run: `go test ./internal/transport/ -v` → PASS.

**Step 3: Full suite + vet**

Run: `go test ./...` and `go vet ./...` → all green. Confirm `go test ./cmd/av/` (gitleaks guard) still passes.

**Step 4: Commit**

```bash
git add internal/client/autostart_test.go internal/transport/security_test.go
git commit -m "test: autostart integration + socket/peer-cred security regressions"
```

---

## Phase 2 — definition of done

- `av ping` prints `pong`, autostarting `avd` when needed (integration test green).
- Socket is `0600`, parent dir `0700`; peer-cred check refuses a foreign UID (logic test); unknown methods return `CodeBadRequest`.
- `go test ./...` and `go vet ./...` green; `make build` produces both binaries.
- The `av` thin-binary dependency guard (`TestAvDoesNotLinkGitleaks`) is green — the architecture invariant is now CI-enforced.

## Roadmap (next)

**Phase 3 — Backends + manifest.** `Backend` interface; mock backend; `age`-file backend (`filippo.io/age`); `agentvault.yaml` parsing (profiles/refs/tiers); `av://` reference parser; test auth stub `AV_TEST_AUTH=allow` (test builds only).

**Phase 4 — Session + `av run` (wire the redaction layers).** Resolve profile→values over IPC; session store + TTL + auto-lock; `av run` injects env, forks child, wraps stdout/stderr in `redact.StreamRedactor` (layer 1); `av scrub` streams stdin→`avd` `Redactor` (layer 2, with the gitleaks detector injected — and consider offset-based masking here per the Phase 1 review note). End-to-end: agent sees `{{AV:NAME}}`, never the value.

**Phase 5 — Touch ID + dangerous tier.** LocalAuthentication via cgo; per-user GUI-session LaunchAgent; per-secret labeled prompts; never-cache/fresh-presence; distinguishable exit codes.

**Phase 6 — Real backends + hardening + adapter.** 1Password (`op`), macOS Keychain; memguard/mlock/no-dump; Secure Enclave key wrap; rate limiting; append-only audit log; remaining CLI verbs; `av init --agent claude-code`; `av read` non-TTY refusal.

## Notes for the executing engineer

- **macOS-specific code goes in `*_darwin.go` with `//go:build darwin`** so Linux/Windows can be added later without touching the cross-platform core.
- **The peer-cred fd extraction and the autostart detach are the two platform-fiddly spots** — verify against the real OS; the code above is correct in shape but adapt if the API differs.
- **Keep `internal/redact` and `cmd/av` gitleaks-free.** Run the guard test after any change that adds imports to the `av` path.
- TDD throughout: red → green → commit, one behavior per task.
