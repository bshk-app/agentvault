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
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/beshkenadze/agentvault/internal/audit"
	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/redact"
	"github.com/beshkenadze/agentvault/internal/transport"
)

// DefaultTTL is the single source of truth for the session window: it is the TTL
// cmd/avd passes to NewSession AND the window the "unlock" RPC opens the session for,
// so the unlock duration and the session's default TTL can never drift. The resolver
// refreshes the deadline per issued value via session.Issue (session.ttl).
const DefaultTTL = 15 * time.Minute

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
	// reg is the SAME backend registry the resolver holds, captured in SetResolver so
	// the "add"/"rm" methods can reach a writable backend (registry.Writer). It is the
	// write side of resolve's read side: one registry, no second source of truth.
	reg *backend.Registry
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
	// provision serves the "setup" RPC: it creates the local age store (identity +
	// empty vault) and live-wires the file backend. It is INJECTED via SetProvisioner
	// (nil until wired) so this package links neither age nor the enclave — avd, which
	// links both, supplies the real closure (provision.Provision with enclave.Wrap).
	// SECURITY: it takes/returns only ipc.SetupParams/SetupResult — no secret crosses it.
	provision func(ipc.SetupParams) (ipc.SetupResult, error)
	// setupMu serializes the whole setup case: each connection runs in its own goroutine,
	// so two concurrent `av setup` RPCs would otherwise race the provision write AND the
	// live re-wire it triggers (registry Register + session unwrapper swap). Holding it
	// around s.provision(p) makes provisioning + re-wire one critical section.
	setupMu sync.Mutex
	// keyTier records the ACTIVE identity-protection tier the file backend's unwrapper
	// represents ("enclave"/"keychain"/"plaintext", or ""/"none" with no local vault).
	// enclaveAvail reports whether the Secure Enclave is the active protection. Both are
	// set via SetKeyTier whenever avd wires/re-wires a tier, so the future `version` RPC
	// can announce the active tier. SECURITY: metadata only — never a secret. tierMu
	// guards the pair because SetKeyTier (setup goroutine) and a future version RPC
	// (another goroutine) can touch it concurrently.
	tierMu       sync.Mutex
	keyTier      string
	enclaveAvail bool
	// version is avd's own build version (ldflags -X main.version), surfaced by the
	// `version` RPC so `av version` can flag an av/avd mismatch. It is set once via
	// SetVersion at startup (before Serve), so it needs no mutex. SECURITY: metadata only.
	version string
}

// SetVersion records avd's build version for the `version` RPC. cmd/avd calls it in main
// with the ldflags-injected `version` var. It is set once before Serve, so no lock is
// needed. SECURITY: it stores a build-version string, never a secret.
func (s *Server) SetVersion(v string) { s.version = v }

// SetKeyTier records the active identity-protection tier (and whether the Secure Enclave
// is the active protection) for the future `version` RPC. avd calls it whenever it
// wires/re-wires a tier at startup or after a live `setup` — and with ""/"none" when no
// local vault exists. SECURITY: it stores metadata only, never a secret.
func (s *Server) SetKeyTier(tier string, enclaveAvailable bool) {
	s.tierMu.Lock()
	defer s.tierMu.Unlock()
	s.keyTier = tier
	s.enclaveAvail = enclaveAvailable
}

// KeyTier reports the active identity-protection tier and Enclave availability recorded
// by SetKeyTier. It is the read side the future `version` RPC consumes.
func (s *Server) KeyTier() (tier string, enclaveAvailable bool) {
	s.tierMu.Lock()
	defer s.tierMu.Unlock()
	return s.keyTier, s.enclaveAvail
}

// SetProvisioner injects the closure that serves the "setup" RPC. Call it after New and
// before Serve. Keeping it injected (not a local crypto call) is what lets avd own the
// age+enclave linkage while the daemon dispatch stays crypto-free.
func (s *Server) SetProvisioner(f func(ipc.SetupParams) (ipc.SetupResult, error)) {
	s.provision = f
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
		s.reg = r.reg // capture the SAME registry so "add"/"rm" reach its writable backends
	}
}

// ensureUnlocked opens a locked session ON DEMAND before resolve/add/rm touch the vault.
// If the session is already unlocked it is a no-op. Otherwise, when noPrompt is false (a
// human at a TTY) and an unwrapper is wired, it unwraps the vault key with one Touch ID
// (unlockWithUnwrapper) — so the user never has to run `av unlock` first. When noPrompt is
// true (agents, via AV_NO_PROMPT) it returns ErrLocked WITHOUT prompting, so the agent
// gets the clean ErrLocked->exit-69 pause instead of blocking on a biometric. With no
// unwrapper it likewise returns ErrLocked (the plain `av unlock` flow is unchanged).
//
// WHY gate resolve/add/rm on it: this makes the session open on demand with ONE Touch ID
// for the interactive path, while NoPrompt keeps the agent path non-blocking (the clean
// ErrLocked->exit-69 pause). resolve calls it first; add/rm call it after the writable-
// backend lookup, so a routing fault (no vault / read-only backend) still surfaces its
// precise hint before the write's unlock gate. Dangerous-tier fresh-presence inside the
// resolver is untouched: this only opens the SESSION; per-secret dangerous prompts still
// fire in Resolve.
func (s *Server) ensureUnlocked(noPrompt bool) error {
	if s.session == nil {
		return ErrLocked
	}
	if !s.session.Locked() {
		return nil
	}
	if !noPrompt && s.session.HasUnwrapper() {
		return s.session.unlockWithUnwrapper(DefaultTTL) // one Touch ID opens the session
	}
	return ErrLocked
}

// ensureUnlockedResp runs ensureUnlocked and, on failure, maps the error to a ready-to-send
// error Response (ErrLocked->CodeLocked, ErrDenied->CodeDenied, like the resolve path) so
// the three handlers gate uniformly. It returns nil when the session is (now) open.
func (s *Server) ensureUnlockedResp(id uint64, noPrompt bool) *ipc.Response {
	err := s.ensureUnlocked(noPrompt)
	if err == nil {
		return nil
	}
	code := ipc.CodeLocked
	if errors.Is(err, ErrDenied) {
		code = ipc.CodeDenied // a denied Touch ID (the unwrap is the presence proof)
	}
	r := errResp(id, code, err.Error())
	return &r
}

// maxScrubReplyBytes bounds how many RAW masked bytes the daemon emits in a single
// scrub reply, so the JSON-RPC line stays under the Decoder's 1 MiB cap (ipc.NewDecoder)
// no matter how far the input inflated. ScrubResult.Masked is base64-encoded in JSON
// (factor 4/3), so 512 KiB of raw masked bytes is ~683 KiB of base64 plus a few dozen
// bytes of JSON framing — comfortably under 1 MiB. This bound is INPUT- and
// NAME-INDEPENDENT: masking inflation per byte is 7 + len(Name) (placeholder
// "{{AV:"+Name+"}}") and Name is unbounded, so the client chunk size can never bound
// the reply; only splitting the daemon's own output by byte size can.
const maxScrubReplyBytes = 512 * 1024

// connState is per-connection scrub state. A connection's scrub stream owns one
// StreamRedactor writing into buf; the snapshot of the session matcher is taken
// once at stream start. pending holds masked bytes produced but not yet sent (the
// daemon splits its output across replies to keep each line under the JSON-RPC cap).
// State is local to handle, so it never leaks across connections (each connection
// gets a fresh, zero-valued connState).
type connState struct {
	sr      *redact.StreamRedactor
	buf     *bytes.Buffer
	pending []byte
}

// emitScrub pops up to maxScrubReplyBytes from the FRONT of cs.pending and returns a
// ScrubResult reply, setting More when masked bytes remain buffered. It is the single
// place all three scrub methods turn pending bytes into a capped reply (SSOT), so no
// reply line can exceed the Decoder's 1 MiB cap regardless of input inflation.
func emitScrub(id uint64, cs *connState) ipc.Response {
	n := len(cs.pending)
	if n > maxScrubReplyBytes {
		n = maxScrubReplyBytes
	}
	masked := cs.pending[:n:n]
	cs.pending = cs.pending[n:]
	res, _ := json.Marshal(ipc.ScrubResult{Masked: masked, More: len(cs.pending) > 0})
	return ipc.Response{ID: id, Result: res}
}

// errResp builds an error Response. SECURITY: callers must pass only non-secret
// strings (method/ref/name or err.Error() from the resolver, which excludes
// values); a secret value must never reach this helper.
func errResp(id uint64, code int, msg string) ipc.Response {
	return ipc.Response{ID: id, Error: &ipc.RPCError{Code: code, Message: msg}}
}

// errResp2 maps a backend write error to the right RPC code. A missing key on rm is a
// client fault (CodeBadRequest); anything else is internal. SECURITY: a backend Add/
// Remove error carries the NAME only (the backend never wraps the value), so err.Error()
// is safe to return; backend is the backend id, also non-secret.
func errResp2(id uint64, backendID string, err error) ipc.Response {
	code := ipc.CodeInternal
	if errors.Is(err, backend.ErrNotFound) {
		code = ipc.CodeBadRequest
	}
	return errResp(id, code, fmt.Sprintf("%s: %v", backendID, err))
}

// writer resolves the writable backend for "add"/"rm". It returns either the Writer
// (rejection nil) or a ready-to-send error Response and nil Writer: the registry not
// being wired is CodeInternal; an unknown or READ-ONLY backend is CodeBadRequest
// ("read-only" / "no such backend") — the latter is how a write against 1p/keychain
// fails fast instead of half-mutating an external store. The "file" backend is the
// special zero-config case: when it is missing there is no local vault yet, so the
// rejection points the user at `av setup` (still CodeBadRequest, so av exits 2).
func (s *Server) writer(id uint64, backendID string) (backend.Writer, *ipc.Response) {
	if s.reg == nil {
		r := errResp(id, ipc.CodeInternal, "registry not configured")
		return nil, &r
	}
	w, ok := s.reg.Writer(backendID)
	if !ok {
		msg := fmt.Sprintf("backend %q is read-only or not registered", backendID)
		if backendID == "file" {
			msg = "no local vault — run 'av setup' first"
		}
		r := errResp(id, ipc.CodeBadRequest, msg)
		return nil, &r
	}
	return w, nil
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
// "scrub"/"scrub_flush"/"scrub_drain".
func (s *Server) dispatch(cs *connState, req ipc.Request) ipc.Response {
	switch req.Method {
	case "ping":
		r, _ := json.Marshal("pong")
		return ipc.Response{ID: req.ID, Result: r}
	case "version":
		// Pure metadata: avd's build version + the active tier + Enclave availability. No
		// session, resolver, or provisioner is required (version must work even with no
		// local vault), and no secret can reach this reply. An unset tier ("" — no local
		// vault) is reported as "none" so the client never special-cases the empty string.
		tier, ea := s.KeyTier()
		if tier == "" {
			tier = "none"
		}
		res, _ := json.Marshal(ipc.VersionResult{Version: s.version, Tier: tier, EnclaveAvailable: ea})
		return ipc.Response{ID: req.ID, Result: res}
	case "resolve":
		var p ipc.ResolveParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return errResp(req.ID, ipc.CodeBadRequest, err.Error())
		}
		if s.resolver == nil {
			return errResp(req.ID, ipc.CodeInternal, "resolver not configured")
		}
		// Open the session on demand (one Touch ID) unless the caller opted out via
		// NoPrompt — see ensureUnlocked. A locked agent run thus gets CodeLocked (exit 69).
		if rejection := s.ensureUnlockedResp(req.ID, p.NoPrompt); rejection != nil {
			return *rejection
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
		// The call that fires Touch ID in production: one presence proof opens the
		// session for DefaultTTL. A denied proof maps to CodeDenied; no proof available
		// (ErrLocked) maps to CodeLocked.
		if s.session == nil {
			return errResp(req.ID, ipc.CodeInternal, "session not configured")
		}
		if s.session.HasUnwrapper() {
			// WHY: with an Enclave-wrapped vault identity the unwrap (a single Touch ID
			// via the Secure Enclave) IS the presence proof — so we DON'T also call
			// s.presence.Prompt here, otherwise the user would face two prompts for one
			// unlock. A failed/denied unwrap leaves the session locked (Task 3 ordering).
			// Dangerous-tier resolve still uses s.presence for fresh per-access prompts —
			// the resolver is untouched; only this unlock branch swaps to unwrap.
			if err := s.session.unlockWithUnwrapper(DefaultTTL); err != nil {
				code := ipc.CodeLocked
				if errors.Is(err, ErrDenied) {
					code = ipc.CodeDenied
				}
				return errResp(req.ID, code, err.Error())
			}
			s.audit.Log(audit.Event{Kind: "unlock"})
			return statusResponse(req.ID, s.session)
		}
		// No wrapped identity: the existing plain presence-prompt unlock.
		if s.presence == nil {
			return errResp(req.ID, ipc.CodeInternal, "presence not configured")
		}
		if err := s.presence.Prompt("Unlock AgentVault"); err != nil {
			code := ipc.CodeLocked
			if errors.Is(err, ErrDenied) {
				code = ipc.CodeDenied
			}
			return errResp(req.ID, code, err.Error())
		}
		s.session.Unlock(DefaultTTL)
		s.audit.Log(audit.Event{Kind: "unlock"})
		return statusResponse(req.ID, s.session)
	case "lock":
		if s.session == nil {
			return errResp(req.ID, ipc.CodeInternal, "session not configured")
		}
		s.session.Lock()
		s.audit.Log(audit.Event{Kind: "lock"})
		return statusResponse(req.ID, s.session)
	case "add":
		var p ipc.AddParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return errResp(req.ID, ipc.CodeBadRequest, err.Error())
		}
		// Resolve the writable backend FIRST so a routing/config fault (unknown / read-only
		// backend, or no local vault yet) surfaces its precise hint regardless of lock state;
		// THEN open the session on demand before the actual write (one Touch ID, or CodeLocked
		// for an agent via NoPrompt). Order: backend hint before the write's unlock gate.
		w, rejection := s.writer(req.ID, p.Backend)
		if rejection != nil {
			return *rejection
		}
		if rejection := s.ensureUnlockedResp(req.ID, p.NoPrompt); rejection != nil {
			return *rejection
		}
		// SECURITY: p.Value is the secret; it flows ONLY into the backend's Add. It is
		// never logged and never reaches an error (Add wraps the name only). The audit
		// entry below records the name/backend, never the value.
		if err := w.Add(p.Locator, string(p.Value)); err != nil {
			return errResp2(req.ID, p.Backend, err)
		}
		s.audit.Log(audit.Event{Kind: "add", Name: p.Locator, Profile: p.Backend})
		ok, _ := json.Marshal("ok")
		return ipc.Response{ID: req.ID, Result: ok}
	case "rm":
		var p ipc.RmParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return errResp(req.ID, ipc.CodeBadRequest, err.Error())
		}
		// Backend-resolution hint first (see "add"), then the on-demand unlock before Remove.
		w, rejection := s.writer(req.ID, p.Backend)
		if rejection != nil {
			return *rejection
		}
		if rejection := s.ensureUnlockedResp(req.ID, p.NoPrompt); rejection != nil {
			return *rejection
		}
		if err := w.Remove(p.Locator); err != nil {
			return errResp2(req.ID, p.Backend, err)
		}
		s.audit.Log(audit.Event{Kind: "rm", Name: p.Locator, Profile: p.Backend})
		ok, _ := json.Marshal("ok")
		return ipc.Response{ID: req.ID, Result: ok}
	case "setup":
		var p ipc.SetupParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return errResp(req.ID, ipc.CodeBadRequest, err.Error())
		}
		if s.provision == nil {
			return errResp(req.ID, ipc.CodeInternal, "setup not configured")
		}
		// The provisioner creates the store and live-wires the file backend. SECURITY:
		// SetupResult carries on-disk PATHS only (no identity/vault bytes), and a
		// provision error is path/reason text from a crypto-free seam — never a secret.
		// WHY setupMu: two concurrent setup RPCs (each a separate handle goroutine) must
		// not interleave the provision write and its live re-wire — serialize the pair.
		s.setupMu.Lock()
		res, err := s.provision(p)
		s.setupMu.Unlock()
		if err != nil {
			return errResp(req.ID, ipc.CodeInternal, err.Error())
		}
		out, _ := json.Marshal(res)
		return ipc.Response{ID: req.ID, Result: out}
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
		// Buffer the masked bytes and emit only a capped slice this reply; the client
		// drains the rest via "scrub_drain". Splitting the daemon's OWN output keeps
		// every reply under the cap no matter how far masking inflated the input.
		cs.pending = append(cs.pending, masked...)
		return emitScrub(req.ID, cs)
	case "scrub_flush":
		var masked []byte
		if cs.sr != nil {
			if err := cs.sr.Close(); err != nil {
				cs.sr, cs.buf, cs.pending = nil, nil, nil
				return errResp(req.ID, ipc.CodeInternal, err.Error())
			}
			masked = append([]byte(nil), cs.buf.Bytes()...)
		}
		cs.sr, cs.buf = nil, nil // reset stream state for any subsequent scrub
		masked = s.detectScrub(masked)
		cs.pending = append(cs.pending, masked...)
		// More may stay true here: the client keeps draining via "scrub_drain" until it
		// clears, so even the flushed tail can exceed one reply for a high-inflation name.
		return emitScrub(req.ID, cs)
	case "scrub_drain":
		// Emit the next capped slice of already-masked bytes the daemon buffered for this
		// stream (no new input). The client loops this while the reply's More is set.
		return emitScrub(req.ID, cs)
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
