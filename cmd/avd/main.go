// Command avd is the AgentVault broker daemon.
package main

import (
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"filippo.io/age"

	"github.com/beshkenadze/agentvault/internal/audit"
	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/backend/agefile"
	"github.com/beshkenadze/agentvault/internal/backend/keychain"
	"github.com/beshkenadze/agentvault/internal/backend/onepassword"
	"github.com/beshkenadze/agentvault/internal/config"
	"github.com/beshkenadze/agentvault/internal/daemon"
	"github.com/beshkenadze/agentvault/internal/detect/gitleaks"
	"github.com/beshkenadze/agentvault/internal/enclave"
	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/provision"
	"github.com/beshkenadze/agentvault/internal/transport"
)

func main() {
	path, err := transport.DefaultSocketPath()
	if err != nil {
		log.Fatalf("avd: socket path: %v", err)
	}
	srv, err := daemon.New(path)
	if err != nil {
		log.Fatalf("avd: listen: %v", err)
	}

	// daemon.DefaultTTL is the single source of truth for the session window: the
	// same const the unlock RPC uses (server.go), so the session TTL and the unlock
	// duration can never drift. Issued values clear after this window; auto-lock on
	// screen-lock/sleep (StartAutoLock below, landed in Phase 5) re-locks earlier.
	//
	// The session is created BEFORE registerBackends because the Enclave-identity path
	// wires its lazy unwrapper INTO this session (the session is the agefile backend's
	// IdentitySource): the key is unwrapped on unlock and zeroized on lock, never held
	// by the backend. The wrap/unwrap pair comes from one seam (enclaveFuncs) so the
	// startup path and the live `setup` provisioner share identical crypto (DRY).
	sess := daemon.NewSession(daemon.DefaultTTL)
	wrap, unwrap := enclaveFuncs()

	// Wire the resolver so `resolve` can broker secrets and `scrub` can mask them
	// against the same session. cmd/avd only assembles plumbing — it never reads a
	// secret value itself; the agefile backend decrypts inside avd on demand.
	reg := backend.NewRegistry()
	registerBackends(reg, sess, unwrap)

	// Layer-2 net: wire the gitleaks detector into the session so scrub catches
	// DERIVED secrets the daemon never issued and dangerous-tier values that are never
	// cached (exact-match issued values are the split-safe layer-1 streaming tier).
	// gitleaks stays in avd's path ONLY — the thin av never links it. A build failure
	// here is fatal: avd must not run with a broken layer-2 net (the construction error
	// carries no secret material).
	det, err := gitleaks.New()
	if err != nil {
		log.Fatalf("avd: gitleaks detector: %v", err)
	}
	sess.WithDetector(det)

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

	// The `setup` RPC provisions the local age store and LIVE-wires the file backend so a
	// following `av add`/`av run` works with NO daemon restart. It reuses the SAME
	// wrap/unwrap seam and default paths as registerBackends (DRY) — avd owns the
	// age+enclave linkage while the daemon dispatch stays crypto-free.
	srv.SetProvisioner(makeProvisioner(reg, sess, wrap, unwrap))

	// Auto-lock observers (screen-lock/sleep on darwin; no-op elsewhere) re-lock the
	// SAME session. stop() removes them on shutdown.
	stopAutoLock := daemon.StartAutoLock(sess)

	go srv.Serve()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	stopAutoLock()
	srv.Close()
	if c, ok := auditLog.(io.Closer); ok {
		c.Close() // flush/close the audit fd (NopLogger is not a Closer)
	}
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

// registerBackends registers the secret backends. The age-file backend ("file") is
// wired from EITHER explicit env (AV_AGE_VAULT + an identity) OR — when none of those
// env vars are set — AUTO-DISCOVERED at the config defaults (config.DefaultVaultPath +
// identity.enc/identity.txt), so a `brew install → av setup` store needs zero env. If
// neither a configured nor a discovered store exists, the file backend is simply skipped
// (the daemon still runs; `av setup` can provision it live). The 1Password ("1p") and
// keychain backends are registered UNCONDITIONALLY: both are lazy — they never touch
// their CLI at registration time, only on Resolve — so wiring them costs nothing until a
// matching ref is resolved. It logs which ids were registered to the daemon's own stderr
// — NEVER a secret value.
//
// IDENTITY PRECEDENCE (env wins over auto-discovery; within each, Enclave wins over
// plaintext — the hardened path NEVER silently degrades to plaintext):
//  1. AV_AGE_IDENTITY_ENCLAVE (HARDENED, preferred): a path to a wrapped-identity BLOB
//     produced by enclave.Wrap. LAZY + session-coupled: we do NOT unwrap at startup
//     (that would fire a Touch ID at daemon launch / login). Instead we set the SESSION
//     unwrapper (the unwrap runs on `av unlock`, where the Touch ID IS the presence
//     proof) and register agefile.New(sess, ...) so the session is the IdentitySource —
//     the key lives in the session (zeroized on lock), never held by the backend.
//  2. AV_AGE_IDENTITY (FALLBACK): a path to a plaintext age identity file. EAGER load
//     into a Static source (no session unwrapper) — keeps the daemon runnable on
//     non-Enclave setups and in CI/e2e.
//  3. AUTO-DISCOVERY (only when ALL AV_AGE_* are unset): the default store under
//     config.DefaultConfigDir(). identity.enc (Enclave, lazy/session-coupled) is
//     preferred over identity.txt (plaintext, eager); the vault must also exist.
//
// SECURITY: the Enclave path loads NO key material at startup; the plaintext path loads
// the identity only to construct the backend, and the vault is decrypted lazily inside
// the backend on each Resolve. Identity bytes never appear in a log or error; errors
// carry only a path/reason or an OSStatus, never key material.
func registerBackends(reg *backend.Registry, sess *daemon.Session, unwrap func([]byte) ([]byte, error)) {
	registered := []string{}

	vaultPath := os.Getenv("AV_AGE_VAULT")
	enclavePath := os.Getenv("AV_AGE_IDENTITY_ENCLAVE")
	idPath := os.Getenv("AV_AGE_IDENTITY")

	// When NONE of the AV_AGE_* env vars are set, fall back to the auto-discovered
	// default store: a vault + an identity (Enclave-wrapped preferred) already on disk.
	if vaultPath == "" && enclavePath == "" && idPath == "" {
		vaultPath, enclavePath, idPath = discoverDefaultStore()
	}

	switch {
	case vaultPath == "" || (enclavePath == "" && idPath == ""):
		log.Printf("avd: no file backend (run `av setup`, or set AV_AGE_VAULT and AV_AGE_IDENTITY_ENCLAVE [hardened] or AV_AGE_IDENTITY [plaintext])")
	case enclavePath != "":
		// HARDENED path: lazy, session-coupled — no startup unwrap, no login Touch ID.
		wireEnclaveBackend(reg, sess, unwrap, enclavePath, vaultPath)
		registered = append(registered, "file")
	default:
		// FALLBACK path: eager plaintext load into a Static source.
		if err := wirePlaintextBackend(reg, idPath, vaultPath); err != nil {
			// The error carries only a path/reason, never key material.
			log.Printf("avd: file backend disabled: %v", err)
		} else {
			registered = append(registered, "file")
		}
	}

	// Lazy: registering does not invoke `op`. Resolve of av://1p/... shells out to the
	// real `op read` and needs `op` installed + signed in (verified manually, not in CI).
	reg.Register("1p", onepassword.New())
	registered = append(registered, "1p")

	// Lazy: registering does not invoke `security`. Resolve of av://keychain/... shells
	// out to the real `security find-generic-password` and needs macOS + a populated
	// keychain (verified manually, not in CI). On non-darwin builds keychain.New() is the
	// stub whose Resolve errors "requires macOS", so registration is safe everywhere.
	reg.Register("keychain", keychain.New())
	registered = append(registered, "keychain")

	log.Printf("avd: registered backends: %s", strings.Join(registered, " "))
}

// discoverDefaultStore probes the config-default store directory for an existing vault
// + identity and returns the paths to wire, mirroring the env precedence (Enclave wins
// over plaintext). It returns empty strings for anything missing, so the caller's
// "vault == \"\" || no identity" guard skips the file backend when no store exists yet
// (the common pre-`av setup` state). It NEVER creates anything — `av setup` provisions;
// this only discovers.
func discoverDefaultStore() (vaultPath, enclavePath, idPath string) {
	vault := config.DefaultVaultPath()
	if !fileExists(vault) {
		return "", "", "" // no vault → nothing to wire (e.g. before `av setup`)
	}
	if enc := config.DefaultEnclaveIdentityPath(); fileExists(enc) {
		log.Printf("avd: auto-discovered default store (Enclave identity)")
		return vault, enc, ""
	}
	if plain := config.DefaultPlaintextIdentityPath(); fileExists(plain) {
		log.Printf("avd: auto-discovered default store (plaintext identity)")
		return vault, "", plain
	}
	return "", "", "" // vault present but no identity → can't wire a reader
}

// fileExists reports whether path is an existing file (any stat success). A transient
// stat error is treated as "absent" so discovery fails safe (skip the backend) rather
// than wiring a path we can't read.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// wireEnclaveBackend wires the HARDENED file backend WITHOUT unwrapping at startup. It
// installs a session unwrapper that, on `av unlock`, reads the wrapped blob and unwraps
// it (a Touch ID in production, identity-passthrough under AV_TEST_ENCLAVE=stub), then
// registers agefile.New(sess, vaultPath) so the SESSION is the IdentitySource: the key
// is held in the session (zeroized on lock), never by the backend.
//
// The unwrapper maps an enclave user-cancel / Touch-ID denial to daemon.ErrDenied via
// mapEnclaveErr so the unlock handler reports CodeDenied; any other failure stays as-is
// (→ CodeLocked). SECURITY: the blob and unwrapped bytes never reach a log or error.
func wireEnclaveBackend(reg *backend.Registry, sess *daemon.Session, unwrap func([]byte) ([]byte, error), encPath, vaultPath string) {
	log.Printf("avd: file backend identity: Secure Enclave (hardened; Touch ID on unlock, lazy)")
	sess.WithUnwrapper(func() ([]byte, error) {
		blob, err := os.ReadFile(encPath)
		if err != nil {
			return nil, err
		}
		b, err := unwrap(blob)
		if err != nil {
			return nil, mapEnclaveErr(err)
		}
		return b, nil
	})
	reg.Register("file", agefile.New(sess, vaultPath))
}

// wirePlaintextBackend wires the FALLBACK file backend by EAGERLY loading the plaintext
// identity into a Static source (no session unwrapper). It surfaces a load error so the
// caller can log it and skip the backend rather than wiring an unreadable vault.
func wirePlaintextBackend(reg *backend.Registry, idPath, vaultPath string) error {
	log.Printf("avd: file backend identity: plaintext file (fallback; run `av setup` without --plaintext to harden)")
	id, err := loadAgeIdentity(idPath)
	if err != nil {
		return err
	}
	reg.Register("file", agefile.New(agefile.Static{ID: id}, vaultPath))
	return nil
}

// mapEnclaveErr classifies an enclave Unwrap failure for the unlock handler. A user
// cancel / Touch-ID denial (enclave.IsUserCanceled, matched on the structured OSStatus —
// never a string) becomes daemon.ErrDenied → CodeDenied, so a cancelled unlock reads as
// "denied". Any other failure (Enclave unreachable, tampered blob, read error) is
// returned UNCHANGED → CodeLocked. nil passes through. On non-darwin/non-cgo builds
// enclave.IsUserCanceled is always false, so this is a no-op there.
func mapEnclaveErr(err error) error {
	if err == nil {
		return nil
	}
	if enclave.IsUserCanceled(err) {
		return daemon.ErrDenied
	}
	return err
}

// makeProvisioner returns the closure that serves the `setup` RPC: it provisions the
// local age store (provision.Provision with the injected Wrap) and, on success, LIVE-
// wires the file backend so a following `av add`/`av run` works with NO daemon restart.
// It reuses the SAME wrap/unwrap seam and config default paths as registerBackends (DRY)
// — no duplicated path logic.
//
// Live re-wiring (only when r.Created — a fresh provision or --rotate): for the wrapped
// (default) store it sets the session unwrapper for the new identity.enc and registers
// agefile.New(sess, vault); for a --plaintext store it eagerly loads identity.txt into a
// Static source. Registry.Register overwrites by id, so re-running setup (e.g. --rotate)
// cleanly replaces the "file" backend. An idempotent Created:false result skips the
// re-wire: the backend is already wired (startup auto-discovery or a prior setup).
//
// SECURITY: only ipc.SetupParams/SetupResult cross this seam (booleans + on-disk paths);
// no secret material is logged, returned, or embedded in an error.
func makeProvisioner(reg *backend.Registry, sess *daemon.Session, wrap, unwrap func([]byte) ([]byte, error)) func(ipc.SetupParams) (ipc.SetupResult, error) {
	return func(p ipc.SetupParams) (ipc.SetupResult, error) {
		// Tier selection: keep today's behavior — plaintext when the client asks for it,
		// otherwise the enclave path with the injected Wrap. Task 3 wires KeychainStore and
		// the keychain unwrapper; until then KeychainStore stays nil (so the keychain tier
		// is unreachable here) and we never request it.
		tier := provision.Tier("")
		if p.Plaintext {
			tier = provision.TierPlaintext
		}
		r, err := provision.Provision(provision.Options{
			Rotate: p.Rotate,
			Tier:   tier,
			Wrap:   wrap, // Dir defaults to config.DefaultConfigDir() inside Provision
		})
		if err != nil {
			return ipc.SetupResult{}, err
		}
		// (Re)wire the file backend LIVE against the freshly provisioned store, but ONLY
		// when this call actually created/rotated it (r.Created). On an idempotent
		// Created:false result the backend is already wired — at startup (auto-discovery)
		// or by a prior setup — so re-registering it would be redundant churn and the
		// "file backend identity: ..." log line would be misleading. Skip it.
		if r.Created {
			if r.Tier == provision.TierPlaintext {
				if werr := wirePlaintextBackend(reg, r.IdentityPath, r.VaultPath); werr != nil {
					return ipc.SetupResult{}, werr
				}
			} else {
				wireEnclaveBackend(reg, sess, unwrap, r.IdentityPath, r.VaultPath)
			}
		}
		return ipc.SetupResult{VaultPath: r.VaultPath, IdentityPath: r.IdentityPath, Created: r.Created}, nil
	}
}

// enclaveFuncs returns the wrap/unwrap pair the daemon seals/unseals the vault identity
// with. It is the SSOT used by BOTH startup wiring (registerBackends) and the live
// `setup` provisioner (makeProvisioner), so the two never diverge.
//
// TEST SEAM (mirrors AV_TEST_AUTH=allow): when AV_TEST_ENCLAVE=stub it returns
// identity-PASSTHROUGH funcs — Wrap returns its input unchanged and Unwrap returns its
// input unchanged — and logs a LOUD warning, EXACTLY like selectPresence logs the stub
// presence. This lets CI/e2e exercise setup→unlock→run with no Secure Enclave. It is
// test-only and env-gated, the same risk profile as AV_TEST_AUTH=allow: the identity is
// NOT hardware-protected under the stub. Otherwise it returns the real enclave.Wrap and
// a closure over enclave.Unwrap (so makeProvisioner can take a func value either way).
func enclaveFuncs() (wrap, unwrap func([]byte) ([]byte, error)) {
	if os.Getenv("AV_TEST_ENCLAVE") == "stub" {
		log.Printf("avd: using stub enclave (AV_TEST_ENCLAVE=stub) — identity NOT hardware-protected")
		identity := func(b []byte) ([]byte, error) { return b, nil }
		return identity, identity
	}
	return enclave.Wrap, func(b []byte) ([]byte, error) { return enclave.Unwrap(b) }
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
