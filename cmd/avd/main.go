// Command avd is the AgentVault broker daemon.
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"filippo.io/age"

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
	auth := daemon.NewStubAuthorizer()
	srv.SetResolver(daemon.NewResolver(reg, auth, sess))

	go srv.Serve()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	srv.Close()
	os.Remove(path)
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
