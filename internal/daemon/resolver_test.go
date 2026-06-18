package daemon

import (
	"errors"
	"testing"
	"time"

	"github.com/beshkenadze/agentvault/internal/backend"
)

type mockBE struct{ data map[string]string }

func (m mockBE) Resolve(loc string) (backend.Secret, error) {
	v, ok := m.data[loc]
	if !ok {
		return backend.Secret{}, backend.ErrNotFound
	}
	return backend.Secret{Value: v}, nil
}
func (m mockBE) List(string) ([]backend.Meta, error) { return nil, nil }

// countingPresence is a Presence stub that counts Prompt calls so a test can assert
// the fresh-per-secret invariant: each dangerous entry must trigger its own Prompt.
type countingPresence struct{ n int }

func (c *countingPresence) Prompt(string) error { c.n++; return nil }

const manifestYAML = `profiles:
  smoke:
    GITHUB_TOKEN:
      ref: av://mock/GH
      tier: normal
`

const dangerousManifestYAML = `profiles:
  danger:
    DEPLOY_KEY:
      ref: av://mock/DK
      tier: dangerous
`

const mixedManifestYAML = `profiles:
  mixed:
    GITHUB_TOKEN:
      ref: av://mock/GH
      tier: normal
    DEPLOY_KEY:
      ref: av://mock/DK
      tier: dangerous
`

const twoDangerousManifestYAML = `profiles:
  danger2:
    DEPLOY_KEY:
      ref: av://mock/DK
      tier: dangerous
    PROD_KEY:
      ref: av://mock/PK
      tier: dangerous
`

// newResolverFixture builds a resolver over a mock backend with GH+DK values and a
// fresh (LOCKED) session, so each test controls unlock state explicitly.
func newResolverFixture() (*Resolver, *Session) {
	reg := backend.NewRegistry()
	reg.Register("mock", mockBE{data: map[string]string{"GH": "ghp_xyz", "DK": "dk_DANGEROUS", "PK": "pk_DANGEROUS"}})
	sess := NewSession(15 * time.Minute)
	return NewResolver(reg, NewStubPresence(), sess), sess
}

func TestResolveProfile(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	rv, sess := newResolverFixture()
	sess.Unlock(15 * time.Minute) // normal-tier requires an unlocked session

	vals, err := rv.Resolve("smoke", []byte(manifestYAML))
	if err != nil {
		t.Fatal(err)
	}
	if vals["GITHUB_TOKEN"] != "ghp_xyz" {
		t.Fatalf("values = %+v", vals)
	}
	// normal-tier value must be CACHED in the session redactor
	if sess.Redactor().Redact("ghp_xyz") == "ghp_xyz" {
		t.Fatal("normal-tier resolved value not recorded in session")
	}
}

// normal-tier resolve into a LOCKED session must fail with ErrLocked, resolve
// nothing, and cache nothing — the agent must `av unlock` first (never prompt mid-run).
func TestResolveNormalLockedFails(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	rv, sess := newResolverFixture() // session left LOCKED

	vals, err := rv.Resolve("smoke", []byte(manifestYAML))
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked, got err=%v vals=%+v", err, vals)
	}
	if vals != nil {
		t.Fatalf("locked normal resolve must return no values, got %+v", vals)
	}
	if sess.Redactor().Redact("ghp_xyz") != "ghp_xyz" {
		t.Fatal("nothing must be cached after a locked resolve")
	}
}

// THE security heart: dangerous-tier resolve with presence allowing returns the
// value for the single run but it is NEVER written to the session — the redactor and
// matcher must NOT mask it afterwards (unmasked == not cached).
func TestResolveDangerousNeverCached(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	rv, sess := newResolverFixture()
	sess.Unlock(15 * time.Minute) // even with an open session, dangerous is never cached

	const value = "dk_DANGEROUS"
	vals, err := rv.Resolve("danger", []byte(dangerousManifestYAML))
	if err != nil {
		t.Fatal(err)
	}
	if vals["DEPLOY_KEY"] != value {
		t.Fatalf("dangerous value not returned for the run: %+v", vals)
	}
	// LOAD-BEARING never-cached assertion: unmasked by both layers => not cached.
	if got := sess.Redactor().Redact(value); got != value {
		t.Fatalf("SECURITY: dangerous value was cached in session redactor: %q", got)
	}
	if got := sess.Matcher().Mask(value); got != value {
		t.Fatalf("SECURITY: dangerous value was cached in session matcher: %q", got)
	}
}

// dangerous-tier with presence denying (no AV_TEST_AUTH) must fail with ErrDenied,
// return no values, and cache nothing.
func TestResolveDangerousDeniedFails(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "") // stub denies
	rv, sess := newResolverFixture()
	sess.Unlock(15 * time.Minute)

	vals, err := rv.Resolve("danger", []byte(dangerousManifestYAML))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("want ErrDenied, got err=%v vals=%+v", err, vals)
	}
	if vals != nil {
		t.Fatalf("denied resolve must return no values, got %+v", vals)
	}
	if sess.Redactor().Redact("dk_DANGEROUS") != "dk_DANGEROUS" {
		t.Fatal("nothing must be cached after a denied dangerous resolve")
	}
}

// Mixed profile, unlocked, presence allows: the normal value is cached, the
// dangerous value is returned but NOT cached. Key by name (map iteration is random).
func TestResolveMixedNormalCachedDangerousNot(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	rv, sess := newResolverFixture()
	sess.Unlock(15 * time.Minute)

	vals, err := rv.Resolve("mixed", []byte(mixedManifestYAML))
	if err != nil {
		t.Fatal(err)
	}
	if vals["GITHUB_TOKEN"] != "ghp_xyz" || vals["DEPLOY_KEY"] != "dk_DANGEROUS" {
		t.Fatalf("both values must be returned for the run: %+v", vals)
	}
	red := sess.Redactor()
	if red.Redact("ghp_xyz") == "ghp_xyz" {
		t.Fatal("normal-tier value must be cached in the mixed profile")
	}
	if got := red.Redact("dk_DANGEROUS"); got != "dk_DANGEROUS" {
		t.Fatalf("SECURITY: dangerous value cached in mixed profile: %q", got)
	}
	// The dangerous value must also be absent from the LAYER-2 Matcher (scrub
	// stream), not just the redactor: an unchanged Mask output == not cached.
	if got := sess.Matcher().Mask("dk_DANGEROUS"); got != "dk_DANGEROUS" {
		t.Fatalf("SECURITY: dangerous value cached in mixed-profile matcher: %q", got)
	}
}

// TestResolveDangerousFreshPerSecret pins the fresh-per-secret invariant: a profile
// with TWO dangerous entries must trigger EXACTLY two Prompt calls (one per secret),
// never a single shared check. Uses a counting presence to assert the count directly.
func TestResolveDangerousFreshPerSecret(t *testing.T) {
	reg := backend.NewRegistry()
	reg.Register("mock", mockBE{data: map[string]string{"DK": "dk_DANGEROUS", "PK": "pk_DANGEROUS"}})
	cp := &countingPresence{}
	sess := NewSession(15 * time.Minute)
	sess.Unlock(15 * time.Minute)
	rv := NewResolver(reg, cp, sess)

	vals, err := rv.Resolve("danger2", []byte(twoDangerousManifestYAML))
	if err != nil {
		t.Fatal(err)
	}
	if vals["DEPLOY_KEY"] != "dk_DANGEROUS" || vals["PROD_KEY"] != "pk_DANGEROUS" {
		t.Fatalf("both dangerous values must be returned: %+v", vals)
	}
	if cp.n != 2 {
		t.Fatalf("two dangerous entries must trigger exactly 2 Prompt calls, got %d", cp.n)
	}
	// Neither dangerous value may be cached.
	if got := sess.Matcher().Mask("dk_DANGEROUS"); got != "dk_DANGEROUS" {
		t.Fatalf("SECURITY: dangerous value cached: %q", got)
	}
	if got := sess.Matcher().Mask("pk_DANGEROUS"); got != "pk_DANGEROUS" {
		t.Fatalf("SECURITY: dangerous value cached: %q", got)
	}
}

func TestResolveDeniedWhenLocked(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "") // not allowed
	rv, _ := newResolverFixture()
	if _, err := rv.Resolve("smoke", []byte(manifestYAML)); err == nil {
		t.Fatal("locked presence must fail resolve")
	}
}

// Unknown profile / malformed manifest stays a client fault (ErrBadRequest), even
// with an unlocked session and presence allowing.
func TestResolveUnknownProfileBadRequest(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	rv, sess := newResolverFixture()
	sess.Unlock(15 * time.Minute)
	if _, err := rv.Resolve("nope", []byte(manifestYAML)); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("unknown profile must be ErrBadRequest, got %v", err)
	}
}
