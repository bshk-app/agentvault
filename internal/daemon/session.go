package daemon

import (
	"sync"
	"time"

	"github.com/beshkenadze/agentvault/internal/redact"
)

// Session holds the secret values issued since unlock. It builds the redactor used by
// the scrub service and expires after a TTL. Safe for concurrent use.
//
// Phase 5: a session has an explicit unlock state. A fresh NewSession is LOCKED until
// Unlock is called; while locked (or once the unlock TTL elapses) the redactor/matcher
// mask nothing and the session is treated as closed. Unlock opens it for a TTL; Lock
// (av lock / auto-lock) and TTL expiry both re-lock and clear issued values.
type Session struct {
	ttl time.Duration
	now func() time.Time

	mu       sync.Mutex
	unlocked bool // fresh sessions are locked until Unlock
	deadline time.Time
	issued   map[string]string // logical name -> value (for redaction + {{AV:NAME}})
	det      redact.Detector   // optional gitleaks detector for layer 2
}

// NewSession returns a LOCKED session with the given default TTL. The session must be
// opened with Unlock before issued values are honored.
func NewSession(ttl time.Duration) *Session {
	return &Session{ttl: ttl, now: time.Now, issued: map[string]string{}}
}

// WithDetector sets the gitleaks detector used by the scrub redactor.
func (s *Session) WithDetector(d redact.Detector) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.det = d
	return s
}

// Unlock opens the session for the given TTL: it marks the session unlocked, sets the
// deadline to now+ttl, and clears any stale values left from a previously-expired
// window so they cannot resurface.
func (s *Session) Unlock(ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issued = map[string]string{}
	s.unlocked = true
	s.deadline = s.now().Add(ttl)
}

// Locked reports whether the session is closed: never unlocked, explicitly locked, or
// past its unlock deadline (expiry re-locks).
func (s *Session) Locked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lockedLocked()
}

func (s *Session) lockedLocked() bool { return !s.unlocked || s.expiredLocked() }

// Status reports whether the session is locked and, if unlocked and not expired, the
// time remaining until it re-locks. It NEVER returns issued values.
func (s *Session) Status() (locked bool, remaining time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lockedLocked() {
		return true, 0
	}
	return false, s.deadline.Sub(s.now())
}

// Issue records a name->value pair into an open session, refreshing the deadline.
//
// Defense-in-depth: a value is NEVER written into a locked or expired session, even if
// a caller forgets the Locked() guard. If the session is closed Issue is a no-op (and
// it clears any stale values from a just-expired window so they cannot resurface). This
// self-defense backstops the resolver's normal-tier guard and guarantees a locked
// session can hold no maskable secret.
func (s *Session) Issue(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lockedLocked() {
		s.issued = map[string]string{} // drop any stale values; do not record into a closed session
		return
	}
	s.issued[name] = value
	s.deadline = s.now().Add(s.ttl)
}

// Expired reports whether the session's TTL has elapsed.
func (s *Session) Expired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.expiredLocked()
}

func (s *Session) expiredLocked() bool { return !s.now().Before(s.deadline) }

// Redactor returns a redactor over the currently-valid issued values (empty if the
// session is locked or expired, so a closed session masks nothing).
func (s *Session) Redactor() *redact.Redactor {
	s.mu.Lock()
	defer s.mu.Unlock()
	var secrets []redact.Secret
	if !s.lockedLocked() {
		for name, val := range s.issued {
			secrets = append(secrets, redact.Secret{Name: name, Value: val})
		}
	}
	return redact.NewRedactor(secrets, redact.Options{Detector: s.det})
}

// Matcher returns the exact-match matcher over the currently-valid issued values
// (empty if the session is locked or expired). It mirrors Redactor but returns the
// layer-2 streaming matcher for use with redact.NewStreamRedactor, so a secret split
// across scrub chunks is still masked. NOTE: layer-2 streaming masks by EXACT-MATCH
// over session values only; gitleaks-on-scrub (the Detector tier) is deferred to
// Phase 6.
func (s *Session) Matcher() *redact.Matcher {
	s.mu.Lock()
	defer s.mu.Unlock()
	var secrets []redact.Secret
	if !s.lockedLocked() {
		for name, val := range s.issued {
			secrets = append(secrets, redact.Secret{Name: name, Value: val})
		}
	}
	return redact.NewMatcher(secrets)
}

// Lock re-locks the session and clears all issued values (used by av lock / TTL expiry
// / Phase 5 auto-lock).
func (s *Session) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unlocked = false
	for k := range s.issued {
		delete(s.issued, k)
	}
}
