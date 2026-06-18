package daemon

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/beshkenadze/agentvault/internal/backend"
)

// manyNormalManifest builds a manifest whose single profile issues n normal-tier
// secrets, all resolving to distinct values through the mock backend. It lets a test
// drive more than maxIssuancesPerWindow issuances in a single Resolve call so the
// limiter trips mid-loop.
func manyNormalManifest(n int) (yaml string, data map[string]string) {
	data = map[string]string{}
	yaml = "profiles:\n  burst:\n"
	for i := 0; i < n; i++ {
		ref := fmt.Sprintf("R%d", i)
		val := fmt.Sprintf("ghp_val_%d", i)
		data[ref] = val
		yaml += fmt.Sprintf("    NAME_%d:\n      ref: av://mock/%s\n      tier: normal\n", i, ref)
	}
	return yaml, data
}

// newRateLimitFixture builds a resolver whose limiter and session share one fake
// clock, with a capturing alert hook, so a burst beyond the threshold can be driven
// deterministically. The session is unlocked against the same clock. The returned
// *[]string is the captured alert reasons.
func newRateLimitFixture(t *testing.T, data map[string]string) (*Resolver, *Session, *[]string) {
	t.Helper()
	cur := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return cur }

	reg := backend.NewRegistry()
	reg.Register("mock", mockBE{data: data})

	sess := NewSession(15 * time.Minute)
	sess.now = clock
	sess.Unlock(15 * time.Minute)

	var alerts []string
	rl := newRateLimiter()
	rl.now = clock

	rv := NewResolver(reg, NewStubPresence(), sess,
		WithRateLimiter(rl),
		WithAlertHook(func(reason string) { alerts = append(alerts, reason) }),
	)
	return rv, sess, &alerts
}

// A burst over the threshold within the window trips the limiter on the issuance
// that crosses it: Resolve returns ErrRateLimited with a nil result, the session is
// RE-LOCKED, and the alert hook fired exactly once with a secret-free reason.
func TestResolveRateLimitTripsRelocksAndAlerts(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	yaml, data := manyNormalManifest(maxIssuancesPerWindow + 5)
	rv, sess, alerts := newRateLimitFixture(t, data)

	vals, err := rv.Resolve("burst", []byte(yaml))
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("want ErrRateLimited, got err=%v vals=%+v", err, vals)
	}
	if vals != nil {
		t.Fatalf("rate-limited resolve must return no values, got %+v", vals)
	}
	if !sess.Locked() {
		t.Fatal("session must be RE-LOCKED after a rate-limit trip (blast-radius)")
	}
	if len(*alerts) != 1 {
		t.Fatalf("alert hook must fire exactly once, got %d", len(*alerts))
	}
	reason := (*alerts)[0]
	if reason == "" {
		t.Fatal("alert reason must be non-empty")
	}
	// The reason must be SECRET-FREE: none of the issued values may appear in it.
	for _, v := range data {
		if containsStr(reason, v) {
			t.Fatalf("SECURITY: alert reason leaked a secret value: %q", reason)
		}
	}
}

// Under the threshold a normal Resolve succeeds and fires no alert: the limiter is
// transparent below the limit.
func TestResolveUnderRateLimitSucceeds(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	yaml, data := manyNormalManifest(maxIssuancesPerWindow - 1)
	rv, sess, alerts := newRateLimitFixture(t, data)

	vals, err := rv.Resolve("burst", []byte(yaml))
	if err != nil {
		t.Fatalf("under-threshold resolve must succeed, got %v", err)
	}
	if len(vals) != maxIssuancesPerWindow-1 {
		t.Fatalf("want %d values, got %d", maxIssuancesPerWindow-1, len(vals))
	}
	if sess.Locked() {
		t.Fatal("under-threshold resolve must not lock the session")
	}
	if len(*alerts) != 0 {
		t.Fatalf("no alert under the threshold, got %d", len(*alerts))
	}
}

// The default resolver (no WithRateLimiter / WithAlertHook) keeps a no-op alert and
// a default limiter, so the existing call sites and tests compile and pass unchanged.
func TestResolveDefaultAlertIsNoOp(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	rv, sess := newResolverFixture() // uses the 3-arg NewResolver
	sess.Unlock(15 * time.Minute)

	if _, err := rv.Resolve("smoke", []byte(manifestYAML)); err != nil {
		t.Fatalf("default resolver must resolve normally, got %v", err)
	}
}
