// Package daemon implements the avd serve loop. The dispatch handles "ping",
// "resolve" (broker secrets into the session), and the streaming "scrub"/
// "scrub_flush" (layer-2 redaction); later phases add lock/etc. on the same dispatch.
package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/redact"
	"github.com/beshkenadze/agentvault/internal/transport"
)

// Server owns the unix-socket listener and serves the JSON-RPC dispatch.
type Server struct {
	ln       net.Listener
	lock     *os.File // exclusive flock held for the daemon's lifetime (I-1)
	lockPath string
	// checkPeer gates every connection on a peer-credential check. It defaults to
	// transport.CheckPeer in New; it is an injectable seam so the reject-and-close
	// security path is testable (a foreign UID can't be forged locally).
	checkPeer func(net.Conn) error
	// resolver issues secrets for the "resolve" method. It is injected via
	// SetResolver (nil until wired): production wires NewResolver(realRegistry,
	// NewStubAuthorizer(), session); tests wire a mock-backed one.
	resolver *Resolver
	// session holds the values issued since unlock; the scrub stream masks against
	// it. SetResolver captures the resolver's session so scrub redacts the SAME
	// values resolve issues into (single source of truth).
	session *Session
}

// SetResolver injects the resolver used by the "resolve" method and captures its
// session for the scrub stream. Call it after New and before Serve. Keeping
// New(path) resolver-free preserves the Phase 2 constructor (ping/peer-cred/
// single-instance) unchanged.
func (s *Server) SetResolver(r *Resolver) {
	s.resolver = r
	if r != nil {
		s.session = r.sess
	}
}

// connState is per-connection scrub state. A connection's scrub stream owns one
// StreamRedactor writing into buf; the snapshot of the session matcher is taken
// once at stream start. State is local to handle, so it never leaks across
// connections (each connection gets a fresh, zero-valued connState).
type connState struct {
	sr  *redact.StreamRedactor
	buf *bytes.Buffer
}

// errResp builds an error Response. SECURITY: callers must pass only non-secret
// strings (method/ref/name or err.Error() from the resolver, which excludes
// values); a secret value must never reach this helper.
func errResp(id uint64, code int, msg string) ipc.Response {
	return ipc.Response{ID: id, Error: &ipc.RPCError{Code: code, Message: msg}}
}

// New binds the daemon socket at path, enforcing a single instance per socket.
//
// Single-instance guard (security requirement I-1): a non-blocking exclusive
// flock on "<path>.lock" makes startup atomic across processes. Two avd starting
// concurrently can both pass a try-dial (nobody is listening yet) and then both
// call transport.Listen, with the second silently clobbering the first's socket.
// The kernel-arbitrated flock closes that race: exactly one New acquires the lock
// and listens; the rest fail with EWOULDBLOCK and refuse to start. The try-dial
// below is kept as defense in depth (clear error for the common live-daemon case).
func New(path string) (*Server, error) {
	// The lockfile lives next to the socket, so its parent dir must exist before we
	// can open it. transport.Listen also creates this dir, but the lock must be
	// acquired first — so create it here (0700, same as the socket dir).
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create socket dir: %w", err)
	}
	lockPath := path + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lockfile: %w", err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("avd already running at %s", path)
		}
		return nil, fmt.Errorf("flock lockfile: %w", err)
	}

	// Defense in depth: if a live peer somehow answers (e.g. an avd not using
	// this lock), refuse rather than clobber its endpoint.
	if c, derr := transport.Dial(path); derr == nil {
		c.Close()
		releaseLock(lock, lockPath)
		return nil, fmt.Errorf("avd already running at %s", path)
	}

	ln, err := transport.Listen(path)
	if err != nil {
		releaseLock(lock, lockPath)
		return nil, err
	}
	return &Server{ln: ln, lock: lock, lockPath: lockPath, checkPeer: transport.CheckPeer}, nil
}

// releaseLock drops the flock, closes the fd, and best-effort removes the
// lockfile. Removal is best-effort: a racing New may have re-created it.
func releaseLock(lock *os.File, lockPath string) {
	_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	_ = lock.Close()
	_ = os.Remove(lockPath)
}

// Serve accepts connections until the listener is closed, handling each in a
// goroutine.
func (s *Server) Serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return // listener closed
		}
		go s.handle(c)
	}
}

// handle gates every connection on the peer-credential check FIRST. If the peer
// is unverified, it sends a CodeUnauthorized response and closes the connection
// (reject-and-close) — it never dispatches a request from an unverified peer.
func (s *Server) handle(c net.Conn) {
	defer c.Close()
	if err := s.checkPeer(c); err != nil {
		_ = ipc.NewEncoder(c).Encode(ipc.Response{
			Error: &ipc.RPCError{Code: ipc.CodeUnauthorized, Message: "peer rejected"},
		})
		return
	}
	dec := ipc.NewDecoder(c)
	enc := ipc.NewEncoder(c)
	cs := &connState{} // per-connection scrub state; fresh per connection
	for {
		var req ipc.Request
		if err := dec.Decode(&req); err != nil {
			return // EOF / closed
		}
		if err := enc.Encode(s.dispatch(cs, req)); err != nil {
			return
		}
	}
}

// dispatch routes a request to its handler. cs carries per-connection scrub state;
// the ping/resolve cases ignore it. Handles "ping", "resolve", and the streaming
// "scrub"/"scrub_flush".
func (s *Server) dispatch(cs *connState, req ipc.Request) ipc.Response {
	switch req.Method {
	case "ping":
		r, _ := json.Marshal("pong")
		return ipc.Response{ID: req.ID, Result: r}
	case "resolve":
		var p ipc.ResolveParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return errResp(req.ID, ipc.CodeBadRequest, err.Error())
		}
		if s.resolver == nil {
			return errResp(req.ID, ipc.CodeInternal, "resolver not configured")
		}
		vals, err := s.resolver.Resolve(p.Profile, p.Manifest)
		if err != nil {
			code := ipc.CodeInternal
			switch {
			case errors.Is(err, ErrBadRequest):
				code = ipc.CodeBadRequest // unknown profile / malformed manifest
			case errors.Is(err, ErrLocked):
				code = ipc.CodeLocked
			}
			// err.Error() carries names/refs only (resolver never wraps values).
			return errResp(req.ID, code, err.Error())
		}
		res, _ := json.Marshal(ipc.ResolveResult{Values: vals})
		return ipc.Response{ID: req.ID, Result: res}
	case "scrub":
		var p ipc.ScrubParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return errResp(req.ID, ipc.CodeBadRequest, err.Error())
		}
		if cs.sr == nil {
			// Snapshot the session matcher once at stream start; a value split
			// across chunks is still masked via the retained overlap tail.
			cs.buf = &bytes.Buffer{}
			cs.sr = redact.NewStreamRedactor(s.sessionMatcher(), cs.buf)
		}
		if _, err := cs.sr.Write(p.Data); err != nil {
			// SECURITY: only the (non-secret) downstream error text is returned.
			return errResp(req.ID, ipc.CodeInternal, err.Error())
		}
		masked := append([]byte(nil), cs.buf.Bytes()...)
		cs.buf.Reset()
		res, _ := json.Marshal(ipc.ScrubResult{Masked: masked})
		return ipc.Response{ID: req.ID, Result: res}
	case "scrub_flush":
		var masked []byte
		if cs.sr != nil {
			if err := cs.sr.Close(); err != nil {
				cs.sr, cs.buf = nil, nil
				return errResp(req.ID, ipc.CodeInternal, err.Error())
			}
			masked = append([]byte(nil), cs.buf.Bytes()...)
		}
		cs.sr, cs.buf = nil, nil // reset stream state for any subsequent scrub
		res, _ := json.Marshal(ipc.ScrubResult{Masked: masked})
		return ipc.Response{ID: req.ID, Result: res}
	default:
		return ipc.Response{ID: req.ID, Error: &ipc.RPCError{
			Code: ipc.CodeBadRequest, Message: "unknown method: " + req.Method,
		}}
	}
}

// sessionMatcher returns the exact-match matcher over the session's currently-valid
// issued values. With no session wired it returns an empty matcher (scrub masks
// nothing) rather than panicking — scrub never depends on resolve having run.
func (s *Server) sessionMatcher() *redact.Matcher {
	if s.session == nil {
		return redact.NewMatcher(nil)
	}
	return s.session.Matcher()
}

// Close stops accepting connections and releases the single-instance lock
// (flock + lockfile). A closed listener is not an error.
func (s *Server) Close() error {
	err := s.ln.Close()
	if s.lock != nil {
		releaseLock(s.lock, s.lockPath)
		s.lock = nil
	}
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
