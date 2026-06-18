package daemon

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beshkenadze/agentvault/internal/audit"
	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/transport"
)

// bufLogger is a buffer-backed audit.Logger for the daemon wiring tests. It captures
// every Event in order; raw() returns the marshaled JSONL so the no-value security
// test can scan the WHOLE audit output for a leaked value.
type bufLogger struct {
	mu     sync.Mutex
	events []audit.Event
}

func (b *bufLogger) Log(e audit.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, e)
}

func (b *bufLogger) all() []audit.Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]audit.Event, len(b.events))
	copy(out, b.events)
	return out
}

// raw marshals every captured event to JSONL — the same bytes a FileLogger would
// write — so a test can assert a secret value appears NOWHERE in the audit output.
func (b *bufLogger) raw(t *testing.T) string {
	t.Helper()
	var sb strings.Builder
	for _, e := range b.all() {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		sb.Write(line)
		sb.WriteByte('\n')
	}
	return sb.String()
}

func (b *bufLogger) kinds() []string {
	var ks []string
	for _, e := range b.all() {
		ks = append(ks, e.Kind)
	}
	return ks
}

// TestAuditIssueEvents: a normal-tier resolve produces exactly one Kind:"issue" entry
// carrying name/tier/profile — and the value never appears in the audit output.
func TestAuditIssueEvents(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	reg := backend.NewRegistry()
	const value = "ghp_SECRET_VALUE_xyz"
	reg.Register("mock", mockBE{data: map[string]string{"GH": value}})
	sess := NewSession(15 * time.Minute)
	sess.Unlock(15 * time.Minute)
	log := &bufLogger{}
	rv := NewResolver(reg, NewStubPresence(), sess, WithAudit(log))

	if _, err := rv.Resolve("smoke", []byte(manifestYAML)); err != nil {
		t.Fatal(err)
	}

	evs := log.all()
	if len(evs) != 1 {
		t.Fatalf("want exactly 1 audit event, got %d: %+v", len(evs), evs)
	}
	e := evs[0]
	if e.Kind != "issue" || e.Name != "GITHUB_TOKEN" || e.Tier != "normal" || e.Profile != "smoke" {
		t.Fatalf("issue event wrong: %+v", e)
	}
	if strings.Contains(log.raw(t), value) {
		t.Fatalf("SECURITY: audit output leaked the secret value")
	}
}

// TestAuditDangerousIssueAndDenied: a dangerous-tier resolve issues ONE entry per
// dangerous touch when allowed; with presence denying it records ONE Kind:"denied".
func TestAuditDangerousIssueAndDenied(t *testing.T) {
	reg := backend.NewRegistry()
	const value = "dk_DANGEROUS_VALUE"
	reg.Register("mock", mockBE{data: map[string]string{"DK": value}})

	// Allowed: one issue entry per dangerous touch.
	t.Run("issued", func(t *testing.T) {
		t.Setenv("AV_TEST_AUTH", "allow")
		sess := NewSession(15 * time.Minute)
		sess.Unlock(15 * time.Minute)
		log := &bufLogger{}
		rv := NewResolver(reg, NewStubPresence(), sess, WithAudit(log))

		if _, err := rv.Resolve("danger", []byte(dangerousManifestYAML)); err != nil {
			t.Fatal(err)
		}
		evs := log.all()
		if len(evs) != 1 || evs[0].Kind != "issue" || evs[0].Tier != "dangerous" || evs[0].Name != "DEPLOY_KEY" {
			t.Fatalf("want 1 dangerous issue entry, got %+v", evs)
		}
		if strings.Contains(log.raw(t), value) {
			t.Fatalf("SECURITY: audit output leaked the dangerous value")
		}
	})

	// Denied: one denied entry, no issue.
	t.Run("denied", func(t *testing.T) {
		t.Setenv("AV_TEST_AUTH", "") // stub denies
		sess := NewSession(15 * time.Minute)
		sess.Unlock(15 * time.Minute)
		log := &bufLogger{}
		rv := NewResolver(reg, NewStubPresence(), sess, WithAudit(log))

		if _, err := rv.Resolve("danger", []byte(dangerousManifestYAML)); err == nil {
			t.Fatal("denied resolve must error")
		}
		evs := log.all()
		if len(evs) != 1 || evs[0].Kind != "denied" || evs[0].Name != "DEPLOY_KEY" || evs[0].Tier != "dangerous" {
			t.Fatalf("want 1 denied entry, got %+v", evs)
		}
		if strings.Contains(log.raw(t), value) {
			t.Fatalf("SECURITY: audit output leaked the dangerous value on denial")
		}
	})
}

// TestAuditAlertEvent: WithAudit routes the rate-limit trip into a Kind:"alert"
// secret-free entry, and the trip's issued values appear nowhere in the audit output.
func TestAuditAlertEvent(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	yaml, data := manyNormalManifest(maxIssuancesPerWindow + 3)

	cur := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return cur }
	reg := backend.NewRegistry()
	reg.Register("mock", mockBE{data: data})
	sess := NewSession(15 * time.Minute)
	sess.now = clock
	sess.Unlock(15 * time.Minute)
	rl := newRateLimiter()
	rl.now = clock
	log := &bufLogger{}
	rv := NewResolver(reg, NewStubPresence(), sess, WithRateLimiter(rl), WithAudit(log))

	if _, err := rv.Resolve("burst", []byte(yaml)); err == nil {
		t.Fatal("burst must trip the limiter")
	}

	// Exactly one "alert" entry must appear (after the under-budget issue entries).
	var alerts int
	for _, e := range log.all() {
		if e.Kind == "alert" {
			alerts++
			if e.Detail == "" {
				t.Fatal("alert entry must carry a secret-free reason in Detail")
			}
		}
	}
	if alerts != 1 {
		t.Fatalf("want exactly 1 alert entry, got %d (kinds=%v)", alerts, log.kinds())
	}
	raw := log.raw(t)
	for _, v := range data {
		if strings.Contains(raw, v) {
			t.Fatalf("SECURITY: audit output leaked a secret value on rate-limit alert")
		}
	}
}

// TestAuditUnlockLockEvents: over the socket, unlock then lock each produce exactly
// one corresponding audit entry via the Server's SetAudit.
func TestAuditUnlockLockEvents(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	reg := backend.NewRegistry()
	reg.Register("mock", mockBE{data: map[string]string{"GH": "ghp_xyz"}})
	sess := NewSession(15 * time.Minute)
	presence := NewStubPresence()
	log := &bufLogger{}
	srv.SetPresence(presence)
	srv.SetResolver(NewResolver(reg, presence, sess, WithAudit(log)))
	srv.SetAudit(log)
	go srv.Serve()

	rpcOK(t, path, "unlock")
	rpcOK(t, path, "lock")

	kinds := log.kinds()
	if len(kinds) != 2 || kinds[0] != "unlock" || kinds[1] != "lock" {
		t.Fatalf("want [unlock lock] audit entries, got %v", kinds)
	}
}

// rpcOK sends one no-param request and fails on any RPC error.
func rpcOK(t *testing.T, path, method string) {
	t.Helper()
	c, err := transport.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := ipc.NewEncoder(c).Encode(ipc.Request{ID: 1, Method: method}); err != nil {
		t.Fatal(err)
	}
	var resp ipc.Response
	if err := ipc.NewDecoder(c).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != nil {
		t.Fatalf("%s rpc error: %+v", method, resp.Error)
	}
}
