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
	"time"

	"golang.org/x/sys/unix"

	"github.com/beshkenadze/agentvault/internal/audit"
	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/redact"
	"github.com/beshkenadze/agentvault/internal/transport"
)

// unlockTTL is the default window an "unlock" RPC opens the session for. It is the
// single source of truth for the unlock duration; the resolver refreshes the
// deadline per issued value via session.Issue (session.ttl).
const unlockTTL = 15 * time.Minute

// connIdleTimeout bounds how long a connection may sit IDLE between requests
// before the daemon reaps it, so a peer that connects and then stalls can't park
// a goroutine forever. It is deliberately GENEROUS: the deadline is reset per
// request (before each Decode and before each Encode in handle), so a long but
// active stream — `av scrub` piping tool output with gaps — is never killed; only
// a peer that goes silent for the whole window times out. `av run`'s single quick
// resolve RPC is trivially within it.
const connIdleTimeout = 5 * time.Minute

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
	// NewStubPresence(), session); tests wire a mock-backed one.
	resolver *Resolver
	// session holds the values issued since unlock; the scrub stream masks against
	// it. SetResolver captures the resolver's session so scrub redacts the SAME
	// values resolve issues into (single source of truth).
	session *Session
	// presence serves the "unlock" RPC: one Prompt = one native presence check
	// (Touch ID in production, the env-gated stub in tests). It is injected via
	// SetPresence and MUST be the SAME presence the resolver holds, so unlock and
	// dangerous-tier resolve share one auth seam.
	presence Presence
	// audit records ONE metadata-only entry per unlock and lock. Default
	// audit.NopLogger; injected via SetAudit (the real daemon wires a FileLogger).
	// SECURITY: only Kind is recorded for unlock/lock — no value can reach it.
	audit audit.Logger
	// idleTimeout bounds the per-connection idle deadline in handle. It defaults to
	// connIdleTimeout in New; it is an injectable seam so the reap-on-stall path is
	// testable without a multi-minute wait (a test sets a tiny value). It is reset
	// per request, so it gates IDLE time between requests, not total stream time.
	idleTimeout time.Duration
}

// SetPresence injects the presence used by the "unlock" RPC. Call it after New and
// before Serve, with the SAME Presence passed to NewResolver so unlock and
// dangerous-tier resolve share one auth seam.
func (s *Server) SetPresence(p Presence) { s.presence = p }

// SetAudit injects the audit sink used to record unlock/lock events. Pass the SAME
// audit.Logger given to the resolver (WithAudit) so the whole daemon writes one log.
// A nil logger is ignored (the default NopLogger stays). Call after New, before Serve.
func (s *Server) SetAudit(l audit.Logger) {
	if l != nil {
		s.audit = l
	}
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
	return &Server{ln: ln, lock: lock, lockPath: lockPath, checkPeer: transport.CheckPeer, audit: audit.NopLogger{}, idleTimeout: connIdleTimeout}, nil
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
		// Reset the idle deadline per request: a stalled/silent peer is reaped after
		// idleTimeout, but an active stream (each request bumps the deadline) is not.
		// A zero idleTimeout disables the deadline (SetReadDeadline(zero) = no limit).
		_ = c.SetReadDeadline(s.idleDeadline())
		var req ipc.Request
		if err := dec.Decode(&req); err != nil {
			return // EOF / closed / idle deadline exceeded
		}
		_ = c.SetWriteDeadline(s.idleDeadline())
		if err := enc.Encode(s.dispatch(cs, req)); err != nil {
			return
		}
	}
}

// idleDeadline returns the absolute deadline for the next read/write, or the zero
// time (no deadline) when idleTimeout is unset, so handle can call it uniformly.
func (s *Server) idleDeadline() time.Time {
	if s.idleTimeout <= 0 {
		return time.Time{}
	}
	return time.Now().Add(s.idleTimeout)
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
			case errors.Is(err, ErrDenied):
				code = ipc.CodeDenied // dangerous-tier presence denied
			case errors.Is(err, ErrRateLimited):
				code = ipc.CodeRateLimited // issuance budget tripped — session was relocked
			}
			// err.Error() carries names/refs only (resolver never wraps values).
			return errResp(req.ID, code, err.Error())
		}
		res, _ := json.Marshal(ipc.ResolveResult{Values: vals})
		return ipc.Response{ID: req.ID, Result: res}
	case "unlock":
		// The call that fires Touch ID in production: one presence Prompt opens the
		// session for unlockTTL. A denied presence maps to CodeDenied; no presence
		// available (ErrLocked) maps to CodeLocked.
		if s.presence == nil {
			return errResp(req.ID, ipc.CodeInternal, "presence not configured")
		}
		if s.session == nil {
			return errResp(req.ID, ipc.CodeInternal, "session not configured")
		}
		if err := s.presence.Prompt("Unlock AgentVault"); err != nil {
			code := ipc.CodeLocked
			if errors.Is(err, ErrDenied) {
				code = ipc.CodeDenied
			}
			return errResp(req.ID, code, err.Error())
		}
		s.session.Unlock(unlockTTL)
		s.audit.Log(audit.Event{Kind: "unlock"})
		return statusResponse(req.ID, s.session)
	case "lock":
		if s.session == nil {
			return errResp(req.ID, ipc.CodeInternal, "session not configured")
		}
		s.session.Lock()
		s.audit.Log(audit.Event{Kind: "lock"})
		return statusResponse(req.ID, s.session)
	case "status":
		if s.session == nil {
			return errResp(req.ID, ipc.CodeInternal, "session not configured")
		}
		return statusResponse(req.ID, s.session)
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
		masked = s.detectScrub(masked)
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
		masked = s.detectScrub(masked)
		res, _ := json.Marshal(ipc.ScrubResult{Masked: masked})
		return ipc.Response{ID: req.ID, Result: res}
	default:
		return ipc.Response{ID: req.ID, Error: &ipc.RPCError{
			Code: ipc.CodeBadRequest, Message: "unknown method: " + req.Method,
		}}
	}
}

// statusResponse builds the StatusResult reply for unlock/lock/status from the
// session's lock state. SECURITY: it reads ONLY Status() (locked + remaining) — it
// never touches issued values, so no secret can reach the reply.
func statusResponse(id uint64, sess *Session) ipc.Response {
	locked, remaining := sess.Status()
	res, _ := json.Marshal(ipc.StatusResult{
		Locked:           locked,
		RemainingSeconds: int(remaining.Seconds()),
	})
	return ipc.Response{ID: id, Result: res}
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

// detectScrub layers the gitleaks Detector tier (layer 2) on top of an already
// exact-masked scrub region. The StreamRedactor masks issued SESSION values with
// cross-chunk overlap (split-safe); this pass catches DERIVED secrets the daemon
// never issued and dangerous-tier values that are never cached, masking each finding
// as {{AV:REDACTED:<rule>}} via the same longest-first logic redact.Redactor uses.
//
// BOUNDARY LIMITATION (accepted v1 tradeoff): gitleaks runs per flushed region as a
// WHOLE-STRING pass — it is NOT streaming. A DERIVED secret split across two scrub
// chunks may be missed at the seam (only the exact-match session-value tier is
// split-safe via the StreamRedactor's retained overlap tail). Making gitleaks
// streaming is out of scope; keep this comment if revisiting.
//
// A nil Detector (no session, locked/expired session, or none wired) means this pass
// is a no-op, so a locked session masks nothing here — consistent with sessionMatcher
// returning an empty matcher for the exact tier.
func (s *Server) detectScrub(masked []byte) []byte {
	if s.session == nil || len(masked) == 0 {
		return masked
	}
	det := s.session.Detector()
	if det == nil {
		return masked
	}
	r := redact.NewRedactor(nil, redact.Options{Detector: det})
	return []byte(r.Redact(string(masked)))
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
