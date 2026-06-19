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
	"github.com/beshkenadze/agentvault/internal/keystore"
	"github.com/beshkenadze/agentvault/internal/provision"
	"github.com/beshkenadze/agentvault/internal/transport"
)

// version is avd's build version, overridden at build time via
// `-ldflags "-X main.version=<tag>"` (see the Makefile / release Formula). It defaults
// to "dev" for plain `go build`. The `version` RPC reports it so `av version` can flag
// an av/avd mismatch (a stale daemon after an upgrade).
var version = "dev"

func main() {
	path, err := transport.DefaultSocketPath()
	if err != nil {
		log.Fatalf("avd: socket path: %v", err)
	}
	srv, err := daemon.New(path)
	if err != nil {
		log.Fatalf("avd: listen: %v", err)
	}
	srv.SetVersion(version) // surfaced by the `version` RPC (ldflags-injected build tag)

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
	store, read := keystoreFuncs()

	// One presence instance is shared by BOTH the unlock RPC (SetPresence) and the
	// dangerous-tier resolver (NewResolver), so unlock and dangerous-tier resolve go
	// through the same auth seam. Production uses real Touch ID; AV_TEST_AUTH=allow
	// selects the env-gated stub so e2e/CI stay automatable without a biometric prompt.
	// It is created BEFORE registerBackends because the non-enclave discovery tiers
	// (keychain/plaintext) wrap THIS presence into their session unwrappers (one touch
	// per unlock; see tierUnwrapper).
	presence := selectPresence()

	// Wire the resolver so `resolve` can broker secrets and `scrub` can mask them
	// against the same session. cmd/avd only assembles plumbing — it never reads a
	// secret value itself; the agefile backend decrypts inside avd on demand.
	reg := backend.NewRegistry()
	registerBackends(reg, sess, srv, unwrap, read, presence)

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
	srv.SetProvisioner(makeProvisioner(reg, sess, srv, wrap, unwrap, store, read, presence))

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
func registerBackends(reg *backend.Registry, sess *daemon.Session, srv *daemon.Server, unwrap func([]byte) ([]byte, error), read func() ([]byte, error), presence daemon.Presence) {
	registered := []string{}

	vaultPath := os.Getenv("AV_AGE_VAULT")
	enclavePath := os.Getenv("AV_AGE_IDENTITY_ENCLAVE")
	idPath := os.Getenv("AV_AGE_IDENTITY")

	// Active tier for the future `version` RPC: assume "no local vault" until a backend is
	// wired below. SetKeyTier is also called by makeProvisioner after a live `setup`.
	srv.SetKeyTier("none", false)

	switch {
	case vaultPath != "" || enclavePath != "" || idPath != "":
		// EXPLICIT env wiring (AV_AGE_*): the original env path, unchanged. The keychain
		// tier is NOT reachable via env (no AV_AGE_* names it) — it is a discovery/`setup`
		// tier only. enclave/plaintext here keep their original eager/lazy behavior.
		switch {
		case vaultPath == "" || (enclavePath == "" && idPath == ""):
			log.Printf("avd: no file backend (run `av setup`, or set AV_AGE_VAULT and AV_AGE_IDENTITY_ENCLAVE [hardened] or AV_AGE_IDENTITY [plaintext])")
		case enclavePath != "":
			// HARDENED path: lazy, session-coupled — no startup unwrap, no login Touch ID.
			wireEnclaveBackend(reg, sess, unwrap, enclavePath, vaultPath)
			srv.SetKeyTier(string(provision.TierEnclave), true)
			registered = append(registered, "file")
		default:
			// FALLBACK path: eager plaintext load into a Static source.
			if err := wirePlaintextBackend(reg, idPath, vaultPath); err != nil {
				// The error carries only a path/reason, never key material.
				log.Printf("avd: file backend disabled: %v", err)
			} else {
				srv.SetKeyTier(string(provision.TierPlaintext), false)
				registered = append(registered, "file")
			}
		}
	default:
		// AUTO-DISCOVERY (no AV_AGE_* at all): detect the tier under the config-default
		// store and wire its per-tier session unwrapper (DRY with the live `setup` path).
		if tier, vp := discoverDefaultStore(read); tier != "" {
			wireTier(reg, sess, srv, tier, vp, unwrap, read, presence)
			registered = append(registered, "file")
		} else {
			log.Printf("avd: no file backend (run `av setup`, or set AV_AGE_VAULT and AV_AGE_IDENTITY_ENCLAVE [hardened] or AV_AGE_IDENTITY [plaintext])")
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

// discoverDefaultStore probes the config-default store directory for an existing vault +
// identity and returns the protection TIER plus the vault path to wire. It mirrors the
// provision tier precedence (identity.enc→enclave, else a keychain item→keychain, else
// identity.txt→plaintext). It returns "" tier when no usable store exists (no vault, or a
// vault with no readable identity), so the caller skips the file backend in the common
// pre-`av setup` state. It NEVER creates anything — `av setup` provisions; this only
// discovers.
//
// Keychain detection reads the keychain item and DISCARDS the bytes immediately (only its
// presence matters): a backend.ErrNotFound means absent, any read SUCCESS means present.
// SECURITY: the read identity bytes are never held, logged, or returned here — only the
// boolean "present" survives.
func discoverDefaultStore(read func() ([]byte, error)) (tier provision.Tier, vaultPath string) {
	vault := config.DefaultVaultPath()
	if !fileExists(vault) {
		return "", "" // no vault → nothing to wire (e.g. before `av setup`)
	}
	if fileExists(config.DefaultEnclaveIdentityPath()) {
		log.Printf("avd: auto-discovered default store (Enclave identity)")
		return provision.TierEnclave, vault
	}
	if keychainHasIdentity(read) {
		log.Printf("avd: auto-discovered default store (keychain identity)")
		return provision.TierKeychain, vault
	}
	if fileExists(config.DefaultPlaintextIdentityPath()) {
		log.Printf("avd: auto-discovered default store (plaintext identity)")
		return provision.TierPlaintext, vault
	}
	return "", "" // vault present but no identity → can't wire a reader
}

// keychainHasIdentity reports whether a keychain identity item is present by attempting a
// read and discarding the bytes. A backend.ErrNotFound is "absent" (false); a successful
// read is "present" (true). Any OTHER error (permission/transport, or the non-darwin
// "requires macOS" stub) is treated as "absent" so discovery fails safe — we never wire a
// keychain tier we can't actually read. SECURITY: the read bytes are dropped on the floor;
// only the boolean escapes.
func keychainHasIdentity(read func() ([]byte, error)) bool {
	b, err := read()
	for i := range b {
		b[i] = 0 // best-effort scrub the discarded copy; presence is all we keep
	}
	return err == nil
}

// fileExists reports whether path is an existing file (any stat success). A transient
// stat error is treated as "absent" so discovery fails safe (skip the backend) rather
// than wiring a path we can't read.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// tierUnwrapper builds the session unwrapper (the func() ([]byte,error) for
// sess.WithUnwrapper) for a discovered/provisioned TIER. It is the SSOT the startup
// discovery path and the live `setup` provisioner both use, so the two never diverge:
//
//   - enclave: read identity.enc and unwrap it. The Secure-Enclave Unwrap SELF-PROMPTS
//     (the key ACL fires Touch ID), so this path does NOT call presence.Prompt — the
//     unwrap IS the presence proof. mapEnclaveErr turns a user-cancel into ErrDenied.
//   - keychain: prompt presence (one Touch ID), then read the identity from the keychain.
//   - plaintext: prompt presence (one Touch ID), then read identity.txt.
//
// The non-enclave tiers call presence.Prompt THEMSELVES so unlockWithUnwrapper stays
// uniform (it just calls the unwrapper) and every tier yields exactly one touch per
// unlock. SECURITY: the identity bytes flow only back to the session — never to a log or
// error; the enclave blob/unwrapped bytes likewise never reach a log.
func tierUnwrapper(tier provision.Tier, encPath, idTxtPath string, presence daemon.Presence, unwrap func([]byte) ([]byte, error), read func() ([]byte, error)) func() ([]byte, error) {
	switch tier {
	case provision.TierKeychain:
		return func() ([]byte, error) {
			if err := presence.Prompt("Unlock AgentVault"); err != nil {
				return nil, err
			}
			return read()
		}
	case provision.TierPlaintext:
		return func() ([]byte, error) {
			if err := presence.Prompt("Unlock AgentVault"); err != nil {
				return nil, err
			}
			return os.ReadFile(idTxtPath)
		}
	default: // enclave: self-prompting via the key ACL; no presence.Prompt here.
		return func() ([]byte, error) {
			blob, err := os.ReadFile(encPath)
			if err != nil {
				return nil, err
			}
			b, err := unwrap(blob)
			return b, mapEnclaveErr(err)
		}
	}
}

// wireTier installs the per-tier session unwrapper (tierUnwrapper) and registers the file
// backend against the session for a discovered/provisioned store, then records the active
// tier for the future `version` RPC. It is the SSOT shared by startup auto-discovery and
// the live `setup` provisioner (DRY): both pass the config-default identity paths so the
// closures read the right file/keychain on unlock. SECURITY: no key material is logged
// here; only the chosen tier is.
func wireTier(reg *backend.Registry, sess *daemon.Session, srv *daemon.Server, tier provision.Tier, vaultPath string, unwrap func([]byte) ([]byte, error), read func() ([]byte, error), presence daemon.Presence) {
	encPath := config.DefaultEnclaveIdentityPath()
	idTxtPath := config.DefaultPlaintextIdentityPath()
	switch tier {
	case provision.TierKeychain:
		log.Printf("avd: file backend identity: login keychain (Touch ID on unlock, lazy)")
	case provision.TierPlaintext:
		log.Printf("avd: file backend identity: plaintext file (Touch ID on unlock; run `av setup` without --plaintext to harden)")
	default:
		log.Printf("avd: file backend identity: Secure Enclave (hardened; Touch ID on unlock, lazy)")
	}
	sess.WithUnwrapper(tierUnwrapper(tier, encPath, idTxtPath, presence, unwrap, read))
	reg.Register("file", agefile.New(sess, vaultPath))
	srv.SetKeyTier(string(tier), tier == provision.TierEnclave)
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
// local age store (provision.Provision with the injected Wrap + KeychainStore seams) and,
// on success, LIVE-wires the file backend so a following `av add`/`av run` works with NO
// daemon restart. It reuses the SAME wrap/unwrap + keystore seams and the per-tier
// unwrapper builder as registerBackends (DRY) — no duplicated crypto or path logic.
//
// Tier selection from SetupParams: an explicit p.Tier wins; otherwise the legacy
// p.Plaintext bool maps to Tier=plaintext (back-compat); otherwise "" = auto
// (Enclave→keychain, never plaintext). p.RequireEnclave forbids the Enclave→keychain
// downgrade. The injected Wrap (enclave) and KeychainStore (keychain) let provision pick
// the best available tier — on this build's stub/real Wrap a failure auto-falls-back to
// the keychain.
//
// Live re-wiring (only when r.Created — a fresh provision or --rotate): wireTier installs
// the per-tier session unwrapper for r.Tier and registers agefile.New(sess, vault).
// Registry.Register overwrites by id, so re-running setup (e.g. --rotate) cleanly replaces
// the "file" backend and SetKeyTier updates the active tier. An idempotent Created:false
// result skips the re-wire: the backend is already wired (startup auto-discovery or a
// prior setup).
//
// SECURITY: only ipc.SetupParams/SetupResult cross this seam (booleans/tier name + on-disk
// paths); no secret material is logged, returned, or embedded in an error.
func makeProvisioner(reg *backend.Registry, sess *daemon.Session, srv *daemon.Server, wrap, unwrap func([]byte) ([]byte, error), store func([]byte) error, read func() ([]byte, error), presence daemon.Presence) func(ipc.SetupParams) (ipc.SetupResult, error) {
	return func(p ipc.SetupParams) (ipc.SetupResult, error) {
		// Explicit tier wins; the legacy Plaintext bool is its back-compat alias; else auto.
		tier := provision.Tier(p.Tier)
		if tier == "" && p.Plaintext {
			tier = provision.TierPlaintext
		}
		r, err := provision.Provision(provision.Options{
			Rotate:         p.Rotate,
			Tier:           tier,
			RequireEnclave: p.RequireEnclave,
			Wrap:           wrap,  // Dir defaults to config.DefaultConfigDir() inside Provision
			KeychainStore:  store, // keychain sink for the keychain tier / Enclave downgrade
		})
		if err != nil {
			return ipc.SetupResult{}, err
		}
		// (Re)wire the file backend LIVE against the freshly provisioned store, but ONLY
		// when this call actually created/rotated it (r.Created). On an idempotent
		// Created:false result the backend is already wired — at startup (auto-discovery)
		// or by a prior setup — so re-registering it would be redundant churn and the
		// "file backend identity: ..." log line would be misleading. Skip it. wireTier is
		// the SAME helper startup discovery uses, so the unwrapper for r.Tier is identical.
		if r.Created {
			wireTier(reg, sess, srv, r.Tier, r.VaultPath, unwrap, read, presence)
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

// keystoreFuncs returns the keychain store/read pair the keychain tier persists and reads
// the vault identity with. It is the SSOT used by BOTH startup discovery (registerBackends
// → keychainHasIdentity / the keychain unwrapper) and the live `setup` provisioner
// (makeProvisioner → provision.Options.KeychainStore), so the two never diverge —
// mirroring enclaveFuncs.
//
// TEST SEAM (mirrors AV_TEST_ENCLAVE=stub / AV_TEST_AUTH=allow): when AV_TEST_KEYSTORE=<dir>
// is set it returns FILE-backed stubs — store writes <dir>/identity (0600), read reads it
// back (a missing file maps to backend.ErrNotFound so discovery sees "absent") — and logs
// a LOUD warning. This lets CI/e2e exercise the keychain tier hermetically WITHOUT touching
// the real login keychain. It is test-only and env-gated, the SAME risk profile as the
// enclave stub: the identity is NOT keychain-protected under the stub, it is a plain 0600
// file in the test dir. Otherwise it returns the real keystore.New() Store/Read.
func keystoreFuncs() (store func([]byte) error, read func() ([]byte, error)) {
	if dir := os.Getenv("AV_TEST_KEYSTORE"); dir != "" {
		log.Printf("avd: using stub keystore (AV_TEST_KEYSTORE=%s) — identity NOT keychain-protected", dir)
		path := filepath.Join(dir, "identity")
		store = func(b []byte) error { return os.WriteFile(path, b, 0o600) }
		read = func() ([]byte, error) {
			b, err := os.ReadFile(path)
			if os.IsNotExist(err) {
				return nil, backend.ErrNotFound // absent → discovery sees "no keychain identity"
			}
			return b, err
		}
		return store, read
	}
	ks := keystore.New()
	return ks.Store, ks.Read
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
