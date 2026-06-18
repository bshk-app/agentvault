package daemon

import (
	"fmt"
	"sync"
	"time"
)

// Rate-limit defaults: at most maxIssuancesPerWindow secret issuances may be brokered
// within any rateLimitWindow. The threat is MASS ENUMERATION — a compromised agent
// draining the vault by issuing secret after secret — so the limiter counts EVERY
// issuance (any tier). These are the single source of truth for the issuance budget.
const (
	maxIssuancesPerWindow = 30
	rateLimitWindow       = 60 * time.Second
)

// rateLimiter is a fixed-window counter over secret issuances. The window opens on the
// first issuance and resets once the injected clock passes windowStart+rateLimitWindow;
// up to maxIssuancesPerWindow issuances are permitted per window. The clock is injectable
// (mirrors Session.now) so tests are deterministic without wall-clock sleeps.
//
// Safe for concurrent use: the daemon serves connections in goroutines and one limiter
// is shared across all of them (the issuance budget is global, not per-connection — that
// is the point of bounding mass enumeration).
type rateLimiter struct {
	now func() time.Time

	mu          sync.Mutex
	windowStart time.Time
	count       int
}

// newRateLimiter returns a limiter with the default budget and the real clock.
func newRateLimiter() *rateLimiter {
	return &rateLimiter{now: time.Now}
}

// allow records one issuance and reports whether it is within the current window's
// budget. It returns false once the window's count would exceed maxIssuancesPerWindow;
// the window resets (count back to 1) once the clock passes windowStart+rateLimitWindow.
//
// On the tripping call the count is NOT incremented past the limit, so reason() reports
// the exact threshold that was hit.
func (r *rateLimiter) allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if r.count == 0 || !now.Before(r.windowStart.Add(rateLimitWindow)) {
		// First issuance, or the previous window has elapsed: open a fresh window.
		r.windowStart = now
		r.count = 1
		return true
	}
	if r.count >= maxIssuancesPerWindow {
		return false
	}
	r.count++
	return true
}

// reason returns a SECRET-FREE description of the trip for the alert hook / audit log.
// It names only the threshold and the window — never a logical name, ref, or value.
func (r *rateLimiter) reason() string {
	return fmt.Sprintf("rate limit exceeded: %d issuances in %s", maxIssuancesPerWindow, rateLimitWindow)
}
