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
//
// Phase 6 (memguard-style at-rest protection): issued values are held in lockedValue
// buffers — the bytes are mlocked (no swap) on Issue and ZEROIZED (overwritten with
// zeros, then munlocked) on Lock / expiry-driven clear / re-issue. This protects the
// canonical AT-REST stored value.
//
// DOCUMENTED LIMITATION (scope honesty): the redactor's Matcher needs CLEARTEXT to
// build its masking forms, so Redactor()/Matcher() read each buffer's String() into a
// transient normal-Go-memory copy while building redact.Secret. Those transient
// cleartext FORMS (and the derived encodings the matcher generates) are NOT protected —
// protecting every transient copy is out of scope because the masker fundamentally
// needs cleartext to match. memguard here protects the at-rest session values, not the
// matcher's transient working set.
type Session struct {
	ttl time.Duration
	now func() time.Time

	mu       sync.Mutex
	unlocked bool // fresh sessions are locked until Unlock
	deadline time.Time
	issued   map[string]*lockedValue // logical name -> protected value (mlock + zeroize)
	det      redact.Detector         // optional gitleaks detector for layer 2
}

// NewSession returns a LOCKED session with the given default TTL. The session must be
// opened with Unlock before issued values are honored.
func NewSession(ttl time.Duration) *Session {
	return &Session{ttl: ttl, now: time.Now, issued: map[string]*lockedValue{}}
}

// WithDetector sets the gitleaks detector used by the scrub redactor.
func (s *Session) WithDetector(d redact.Detector) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.det = d
	return s
}

// destroyIssuedLocked zeroizes (and munlocks) every protected buffer, then resets the
// map. SSOT for every clear path (Unlock / Issue-into-closed / Lock): a value is never
// merely dropped, it is overwritten. Caller must hold s.mu.
func (s *Session) destroyIssuedLocked() {
	for _, lv := range s.issued {
		lv.Destroy()
	}
	s.issued = map[string]*lockedValue{}
}

// Unlock opens the session for the given TTL: it marks the session unlocked, sets the
// deadline to now+ttl, and clears (zeroizing) any stale values left from a
// previously-expired window so they cannot resurface.
func (s *Session) Unlock(ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.destroyIssuedLocked()
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
		s.destroyIssuedLocked() // zeroize+drop stale values; do not record into a closed session
		return
	}
	if prior := s.issued[name]; prior != nil {
		prior.Destroy() // zeroize the buffer being replaced — never leak it
	}
	s.issued[name] = newLockedValue(value)
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
		for name, lv := range s.issued {
			// Transient cleartext: lv.String() copies into normal Go memory only for the
			// span of building the redact.Secret (the documented matcher-forms limitation).
			secrets = append(secrets, redact.Secret{Name: name, Value: lv.String()})
		}
	}
	return redact.NewRedactor(secrets, redact.Options{Detector: s.det})
}

// Matcher returns the exact-match matcher over the currently-valid issued values
// (empty if the session is locked or expired). It mirrors Redactor but returns the
// layer-2 streaming matcher for use with redact.NewStreamRedactor, so a secret split
// across scrub chunks is still masked. NOTE: the STREAMING tier masks by EXACT-MATCH
// over session values only (split-safe); the gitleaks Detector tier is layered on top
// per flushed region in the scrub handler (see Session.Detector + server.go).
func (s *Session) Matcher() *redact.Matcher {
	s.mu.Lock()
	defer s.mu.Unlock()
	var secrets []redact.Secret
	if !s.lockedLocked() {
		for name, lv := range s.issued {
			// Transient cleartext (documented matcher-forms limitation): see Redactor.
			secrets = append(secrets, redact.Secret{Name: name, Value: lv.String()})
		}
	}
	return redact.NewMatcher(secrets)
}

// Detector returns the session's layer-2 gitleaks detector for the scrub net, or nil
// when the session is locked/expired or no detector was wired. A nil return means the
// scrub path masks nothing via the detector tier — so a locked session masks nothing
// (neither exact-match issued values nor gitleaks findings).
func (s *Session) Detector() redact.Detector {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lockedLocked() {
		return nil
	}
	return s.det
}

// Lock re-locks the session and ZEROIZES + clears all issued values (used by av lock /
// TTL expiry / Phase 5 auto-lock / rate-limit force-relock). Each protected buffer is
// overwritten with zeros and munlocked — the secret is destroyed, not merely dropped.
func (s *Session) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unlocked = false
	s.destroyIssuedLocked()
}
