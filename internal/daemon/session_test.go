package daemon

import (
	"bytes"
	"testing"
	"time"
)

func TestSessionIssueAndRedactor(t *testing.T) {
	s := NewSession(15 * time.Minute)
	s.Unlock(15 * time.Minute)
	s.Issue("GITHUB_TOKEN", "ghp_secret")
	s.Issue("STRIPE", "sk_live_x")

	r := s.Redactor() // *redact.Redactor over all issued values
	got := r.Redact("token=ghp_secret and sk_live_x")
	if got == "token=ghp_secret and sk_live_x" {
		t.Fatalf("issued values not masked: %q", got)
	}
}

// A fresh NewSession is LOCKED until Unlock is called (Phase 5 invariant: the
// implicit "open" session of Phase 4 is replaced by an explicit unlock step).
func TestSessionFreshIsLocked(t *testing.T) {
	s := NewSession(15 * time.Minute)
	if !s.Locked() {
		t.Fatal("fresh session must be locked until Unlock")
	}
	locked, remaining := s.Status()
	if !locked {
		t.Fatal("Status on a fresh session must report locked")
	}
	if remaining != 0 {
		t.Fatalf("locked session must report 0 remaining, got %v", remaining)
	}
}

// Unlock opens the session for a TTL: Locked()==false and Status reports the
// remaining time close to the TTL. Uses an injected clock for determinism.
func TestSessionUnlock(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	cur := base
	s := NewSession(time.Minute)
	s.now = func() time.Time { return cur }

	s.Unlock(15 * time.Minute)
	if s.Locked() {
		t.Fatal("session must be unlocked after Unlock")
	}
	locked, remaining := s.Status()
	if locked {
		t.Fatal("Status must report unlocked after Unlock")
	}
	if remaining != 15*time.Minute {
		t.Fatalf("remaining = %v, want 15m", remaining)
	}
}

// Lock after Unlock re-locks the session, clears issued values, and the redactor
// then masks nothing.
func TestSessionLockReLocks(t *testing.T) {
	s := NewSession(15 * time.Minute)
	s.Unlock(15 * time.Minute)
	s.Issue("TOKEN", "ghp_secret")
	if s.Redactor().Redact("ghp_secret") == "ghp_secret" {
		t.Fatal("unlocked session must mask issued value")
	}

	s.Lock()
	if !s.Locked() {
		t.Fatal("session must be locked after Lock")
	}
	if got := s.Redactor().Redact("ghp_secret"); got != "ghp_secret" {
		t.Fatalf("locked session must mask nothing, got %q", got)
	}
	if got := s.Matcher(); got == nil {
		t.Fatal("Matcher must be non-nil even when locked")
	}
	locked, remaining := s.Status()
	if !locked || remaining != 0 {
		t.Fatalf("Status after Lock = (%v, %v), want (true, 0)", locked, remaining)
	}
}

// Once the unlock TTL elapses the session re-locks: Locked()==true, Status
// reports 0 remaining, and the redactor masks nothing. No wall-clock sleep.
func TestSessionUnlockExpiryReLocks(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	cur := base
	s := NewSession(time.Minute)
	s.now = func() time.Time { return cur }

	s.Unlock(10 * time.Minute)
	s.Issue("TOKEN", "ghp_secret")
	if s.Locked() {
		t.Fatal("must be unlocked right after Unlock")
	}

	cur = base.Add(11 * time.Minute) // advance past the unlock deadline
	if !s.Locked() {
		t.Fatal("session must re-lock once the unlock TTL elapses")
	}
	locked, remaining := s.Status()
	if !locked || remaining != 0 {
		t.Fatalf("expired Status = (%v, %v), want (true, 0)", locked, remaining)
	}
	if got := s.Redactor().Redact("ghp_secret"); got != "ghp_secret" {
		t.Fatalf("expired session must mask nothing, got %q", got)
	}
}

func TestSessionExpiryClears(t *testing.T) {
	s := NewSession(0) // already-expired TTL
	s.Unlock(0)
	s.Issue("X", "v")
	if !s.Expired() {
		t.Fatal("zero TTL should be expired immediately")
	}
	// After expiry, the redactor must not mask the old value.
	if r := s.Redactor(); r.Redact("v") != "v" {
		t.Fatal("expired session must not mask old values")
	}
}

// Defense-in-depth: Issue into a LOCKED session is a no-op. Even if a caller forgets
// the Locked() guard, a value can never be written into (and thus made maskable by) a
// closed session.
func TestSessionIssueIntoLockedIsNoOp(t *testing.T) {
	s := NewSession(15 * time.Minute) // fresh => locked, never unlocked
	s.Issue("TOKEN", "ghp_secret")
	if got := s.Redactor().Redact("ghp_secret"); got != "ghp_secret" {
		t.Fatalf("value issued into a locked session must not be maskable, got %q", got)
	}
	if !s.Locked() {
		t.Fatal("Issue must not unlock a locked session")
	}
}

// Issue into an UNLOCKED-but-EXPIRED session is also a no-op (the expired window is a
// closed session); it must not refresh the deadline back to life.
func TestSessionIssueIntoExpiredIsNoOp(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	cur := base
	s := NewSession(10 * time.Minute)
	s.now = func() time.Time { return cur }
	s.Unlock(10 * time.Minute)

	cur = base.Add(11 * time.Minute) // past the unlock deadline => expired/locked
	s.Issue("TOKEN", "ghp_secret")
	if !s.Locked() {
		t.Fatal("Issue into an expired session must not revive it")
	}
	if got := s.Redactor().Redact("ghp_secret"); got != "ghp_secret" {
		t.Fatalf("value issued into an expired session must not be maskable, got %q", got)
	}
}

// A value issued in an expired window must NOT resurface after a re-issue: once the
// TTL lapses, Issue clears the stale set before recording the new value, so the old
// secret is dropped (not merely hidden). Uses an injected clock — no wall-clock sleep.
func TestSessionReissueAfterExpiryDropsOldValue(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	cur := base
	s := NewSession(10 * time.Minute)
	s.now = func() time.Time { return cur }
	s.Unlock(10 * time.Minute) // open the session against the fake clock

	s.Issue("OLD", "oldval") // first Issue rebases the deadline onto the fake clock
	if s.Expired() {
		t.Fatal("must not be expired immediately after issue")
	}

	cur = base.Add(11 * time.Minute) // advance past the deadline
	if !s.Expired() {
		t.Fatal("must be expired once the TTL elapses")
	}

	s.Unlock(10 * time.Minute) // re-open against the advanced clock
	s.Issue("NEW", "newval")   // expired path must clear OLD before recording NEW
	r := s.Redactor()
	if got := r.Redact("oldval"); got != "oldval" {
		t.Fatalf("stale value from an expired window resurfaced: %q", got)
	}
	if got := r.Redact("newval"); got == "newval" {
		t.Fatalf("new value not masked after re-issue: %q", got)
	}
}

// ZEROIZE on Lock (load-bearing): after Lock() the at-rest buffer that held the
// issued value must be overwritten with zeros — the secret is destroyed, not merely
// dereferenced. We hold a reference to the protected buffer captured BEFORE Lock and
// assert its backing bytes are all zero afterward. This is the observable proof of
// memguard-style zeroize that the no-resurface tests (above) only prove indirectly.
func TestSessionLockZeroizesBuffer(t *testing.T) {
	s := NewSession(15 * time.Minute)
	s.Unlock(15 * time.Minute)
	s.Issue("TOKEN", "ghp_secret_value")

	buf := s.issued["TOKEN"] // capture the live buffer before Lock destroys the map entry
	if buf == nil {
		t.Fatal("Issue must store a protected buffer for the value")
	}
	if buf.String() != "ghp_secret_value" {
		t.Fatalf("buffer String() = %q, want the issued value", buf.String())
	}
	// Capture the backing array NOW; Destroy zeroes it in place but nils lv.buf, so we
	// must hold the slice header before Lock to observe the zeroed bytes after.
	backing := buf.bytesForTest()
	if len(backing) == 0 {
		t.Fatal("buffer must hold the value bytes before Lock")
	}

	s.Lock()

	if !allZero(backing) {
		t.Fatalf("Lock must zeroize the buffer bytes, got %v", backing)
	}
}

// ZEROIZE on TTL-expiry-driven clear: Issue into an expired window clears (and
// destroys) the stale buffer. Capture the stale buffer before the expired Issue and
// assert it was zeroized, not just dropped.
func TestSessionExpiryClearZeroizesBuffer(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	cur := base
	s := NewSession(10 * time.Minute)
	s.now = func() time.Time { return cur }
	s.Unlock(10 * time.Minute)

	s.Issue("OLD", "stale_secret")
	stale := s.issued["OLD"]
	if stale == nil {
		t.Fatal("Issue must store a protected buffer")
	}
	backing := stale.bytesForTest()

	cur = base.Add(11 * time.Minute) // advance past the deadline => expired/closed
	s.Issue("OLD", "ignored")        // expired Issue is a no-op that clears+destroys the stale set

	if !allZero(backing) {
		t.Fatalf("expired-clear must zeroize the stale buffer, got %v", backing)
	}
}

// Re-issuing the same NAME must destroy (zeroize) the prior buffer for that name, not
// leak it.
func TestSessionReissueSameNameZeroizesPrior(t *testing.T) {
	s := NewSession(15 * time.Minute)
	s.Unlock(15 * time.Minute)
	s.Issue("TOKEN", "first_value")
	prior := s.issued["TOKEN"]
	backing := prior.bytesForTest()

	s.Issue("TOKEN", "second_value") // replace must Destroy the prior buffer

	if !allZero(backing) {
		t.Fatalf("re-issue of same name must zeroize the prior buffer, got %v", backing)
	}
	if got := s.Redactor().Redact("second_value"); got == "second_value" {
		t.Fatal("new value for re-issued name must be masked")
	}
}

func allZero(b []byte) bool {
	return bytes.Equal(b, make([]byte, len(b)))
}
