// Command avd is the AgentVault broker daemon.
package main

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"filippo.io/age"

	"github.com/beshkenadze/agentvault/internal/audit"
	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/backend/agefile"
	"github.com/beshkenadze/agentvault/internal/daemon"
	"github.com/beshkenadze/agentvault/internal/transport"
)

// sessionTTL is how long an issued value stays in the session redactor before the
// session clears (15 min per the design; auto-lock-on-screen-lock is Phase 5).
const sessionTTL = 15 * time.Minute

func main() {
	path, err := transport.DefaultSocketPath()
	if err != nil {
		log.Fatalf("avd: socket path: %v", err)
	}
	srv, err := daemon.New(path)
	if err != nil {
		log.Fatalf("avd: listen: %v", err)
	}

	// Wire the resolver so `resolve` can broker secrets and `scrub` can mask them
	// against the same session. cmd/avd only assembles plumbing — it never reads a
	// secret value itself; the agefile backend decrypts inside avd on demand.
	reg := backend.NewRegistry()
	registerBackends(reg)
	sess := daemon.NewSession(sessionTTL)

	// One presence instance is shared by BOTH the unlock RPC (SetPresence) and the
	// dangerous-tier resolver (NewResolver), so unlock and dangerous-tier resolve go
	// through the same auth seam. Production uses real Touch ID; AV_TEST_AUTH=allow
	// selects the env-gated stub so e2e/CI stay automatable without a biometric prompt.
	presence := selectPresence()

	// Append-only audit log (default-on for the real daemon): one metadata-only entry
	// per dangerous touch — issuance, unlock, lock, rate-limit alert, denied access. It
	// lives alongside the socket (user dir, 0600). SECURITY: only names/tiers/profiles/
	// reasons are written — NEVER a value (audit.Event has no value field). On open
	// failure we fall back to the NopLogger rather than refuse to start: audit is
	// defense-in-depth, not a hard dependency of brokering.
	auditLog := openAuditLog(path)
	srv.SetResolver(daemon.NewResolver(reg, presence, sess, daemon.WithAudit(auditLog)))
	srv.SetPresence(presence)
	srv.SetAudit(auditLog)

	// Auto-lock observers (screen-lock/sleep on darwin; no-op elsewhere) re-lock the
	// SAME session. stop() removes them on shutdown.
	stopAutoLock := daemon.StartAutoLock(sess)

	go srv.Serve()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	stopAutoLock()
	srv.Close()
	os.Remove(path)
}

// selectPresence returns the presence the daemon authorizes with: the env-gated
// stub when AV_TEST_AUTH=allow (e2e/CI, no biometric prompt), otherwise the real
// Touch ID backend. A missing Touch ID backend (e.g. a non-darwin/non-cgo build)
// is fatal — avd must never run without a real presence check in production.
//
// SECURITY: nothing here logs a secret value; only the selection and any
// construction error (which carries no key material) are logged.
func selectPresence() daemon.Presence {
	if os.Getenv("AV_TEST_AUTH") == "allow" {
		log.Printf("avd: using stub presence (AV_TEST_AUTH=allow)")
		return daemon.NewStubPresence()
	}
	p, err := daemon.NewTouchIDPresence()
	if err != nil {
		log.Fatalf("avd: presence: %v", err)
	}
	return p
}

// openAuditLog opens the append-only audit log next to the socket (audit.jsonl in the
// same user dir, which daemon.New already created 0700). On any open error it logs the
// reason (no key material) and returns a NopLogger so the daemon still runs — audit is
// defense-in-depth, never a blocker for brokering.
func openAuditLog(socketPath string) audit.Logger {
	auditPath := filepath.Join(filepath.Dir(socketPath), "audit.jsonl")
	l, err := audit.NewFileLogger(auditPath)
	if err != nil {
		log.Printf("avd: audit log disabled: %v", err)
		return audit.NopLogger{}
	}
	log.Printf("avd: audit log enabled")
	return l
}

// registerBackends registers the secret backends configured via env. Phase 4 wires
// only the age-file backend ("file") when both AV_AGE_IDENTITY and AV_AGE_VAULT are
// set; if either is unset it skips registration (the daemon still runs, and a
// resolve of av://file/... returns a "no backend registered" error). It logs which
// ids were registered to the daemon's own stderr — NEVER a secret value.
//
// SECURITY: the identity is loaded here only to construct the backend; the plaintext
// vault is decrypted lazily inside the backend on each Resolve. Phase 6 wraps the
// identity in the Secure Enclave; this function is the seam for that change.
func registerBackends(reg *backend.Registry) {
	idPath := os.Getenv("AV_AGE_IDENTITY")
	vaultPath := os.Getenv("AV_AGE_VAULT")
	if idPath == "" || vaultPath == "" {
		log.Printf("avd: no file backend (set AV_AGE_IDENTITY and AV_AGE_VAULT to enable)")
		return
	}

	id, err := loadAgeIdentity(idPath)
	if err != nil {
		// The error carries only the path and a parse reason, never key material.
		log.Printf("avd: file backend disabled: %v", err)
		return
	}
	reg.Register("file", agefile.New(id, vaultPath))
	log.Printf("avd: registered backends: file")
}

// loadAgeIdentity reads an age identity file and returns its first identity.
// age.ParseIdentities(io.Reader) ([]age.Identity, error) parses the standard age
// identity file format (one "AGE-SECRET-KEY-..." per line, '#'-comments allowed).
func loadAgeIdentity(path string) (age.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, errNoIdentity
	}
	return ids[0], nil
}

// errNoIdentity is returned when the identity file parses but contains no identity.
var errNoIdentity = ageError("no age identity found in AV_AGE_IDENTITY file")

// ageError is a tiny no-secret error type for identity-loading failures.
type ageError string

func (e ageError) Error() string { return string(e) }
