package daemon

import (
	"testing"
	"time"
)

// Under the threshold, every issuance is allowed. Exactly maxIssuancesPerWindow
// calls within one window must all return true.
func TestRateLimiterUnderThreshold(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	cur := base
	rl := newRateLimiter()
	rl.now = func() time.Time { return cur }

	for i := 0; i < maxIssuancesPerWindow; i++ {
		if !rl.allow() {
			t.Fatalf("issuance %d/%d within window must be allowed", i+1, maxIssuancesPerWindow)
		}
	}
}

// The (N+1)th issuance within the same window trips the limiter: allow() returns
// false. The reason string is secret-free by construction (it names only counts
// and the window), asserted here so a regression that interpolates a value fails.
func TestRateLimiterTripsOverThreshold(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	cur := base
	rl := newRateLimiter()
	rl.now = func() time.Time { return cur }

	for i := 0; i < maxIssuancesPerWindow; i++ {
		if !rl.allow() {
			t.Fatalf("issuance %d must be allowed", i+1)
		}
	}
	if rl.allow() {
		t.Fatal("issuance over threshold must be denied")
	}

	reason := rl.reason()
	if reason == "" {
		t.Fatal("reason must describe the trip")
	}
	for _, secret := range []string{"ghp_", "dk_", "pk_", "sk_"} {
		if containsStr(reason, secret) {
			t.Fatalf("reason must be secret-free, got %q", reason)
		}
	}
}

// After the window elapses (advance the injected clock past windowStart+window),
// the limiter resets and issuance is allowed again.
func TestRateLimiterWindowResets(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	cur := base
	rl := newRateLimiter()
	rl.now = func() time.Time { return cur }

	for i := 0; i < maxIssuancesPerWindow; i++ {
		rl.allow()
	}
	if rl.allow() {
		t.Fatal("must be tripped at the end of the burst")
	}

	cur = base.Add(rateLimitWindow + time.Second) // past the window
	if !rl.allow() {
		t.Fatal("issuance must be allowed again after the window resets")
	}
}

func containsStr(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
