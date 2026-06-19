# Zero-config writable store + session-coupled Enclave identity — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to
> implement this plan task-by-task, with a code review between tasks. Commit on `main`
> (this project's convention — do NOT create a branch). 1Password signing may be
> locked: if a commit fails with "1Password: failed to fill whole buffer", commit with
> `git -c commit.gpgsign=false` (NEVER `--no-verify`); the human re-signs later.

**Goal:** After `brew install → brew services start → av setup`, `av add`/`av rm`/
`av run` work with zero hand-configuration, with the vault key Secure-Enclave-wrapped
and unwrapped only inside the unlocked session.

**Architecture:** The age identity moves out of the agefile backend into the daemon
session. `agefile.New(src IdentitySource, vaultPath)` fetches the identity per
operation from the session, which unwraps the Enclave blob on `av unlock` and zeroizes
it on lock. `av setup` is an RPC: `avd` (which links age+enclave) provisions the store
and wires the backend live. The daemon auto-discovers default paths so no env is needed.

**Tech stack:** Go 1.26 (cgo darwin), filippo.io/age, internal/enclave, unix mlock.

Design: `docs/plans/2026-06-19-agentvault-zero-config-store-design.md`.

**Invariants to keep green throughout:** `go test ./... -race`, `go vet ./...`,
`CGO_ENABLED=1 go build ./...`, `CGO_ENABLED=0 go build ./...`,
`GOOS=linux go build ./...`, and `cmd/av/deps_test.go::TestAvStaysThin` (av must NOT
link age/enclave — so `av setup` is an RPC, never local crypto).

---

### Task 1: Default config paths

**Files:**
- Create: `internal/config/paths.go`
- Test: `internal/config/paths_test.go`

**Step 1 — failing test** (`paths_test.go`): assert `DefaultConfigDir()` honors
`XDG_CONFIG_HOME` when set (`<xdg>/agentvault`) and falls back to
`<home>/.config/agentvault` when unset; assert `DefaultVaultPath()` ends with
`agentvault/vault.age` and `DefaultEnclaveIdentityPath()` ends with
`agentvault/identity.enc`, `DefaultPlaintextIdentityPath()` ends with
`agentvault/identity.txt`. Use `t.Setenv`.

**Step 2 — run** → FAIL (package missing).

**Step 3 — implement** (`paths.go`):
```go
// Package config resolves AgentVault's default on-disk locations (vault + identity).
// SSOT for the zero-config store paths the daemon auto-discovers and `av setup` writes.
package config

import (
	"os"
	"path/filepath"
)

// DefaultConfigDir is $XDG_CONFIG_HOME/agentvault, else ~/.config/agentvault.
func DefaultConfigDir() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "agentvault")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "agentvault")
}

func DefaultVaultPath() string             { return filepath.Join(DefaultConfigDir(), "vault.age") }
func DefaultEnclaveIdentityPath() string   { return filepath.Join(DefaultConfigDir(), "identity.enc") }
func DefaultPlaintextIdentityPath() string { return filepath.Join(DefaultConfigDir(), "identity.txt") }
```

**Step 4 — run** → PASS. **Step 5 — commit** `feat(config): default vault/identity paths`.

---

### Task 2: `IdentitySource` seam in agefile

**Files:**
- Modify: `internal/backend/agefile/agefile.go`
- Modify: `internal/backend/agefile/agefile_test.go`, `agefile_write_test.go` (use `Static`)
- Modify caller: `cmd/avd/main.go` (`agefile.New(agefile.Static(id), vaultPath)`)
- Test: `internal/backend/agefile/identitysource_test.go`

**Step 1 — failing test** (`identitysource_test.go`): a source whose `Identity()`
returns `(nil, someErr)` makes `Resolve`/`Add`/`Remove` return that error (errors.Is).
A `Static(id)` source behaves exactly like the old fixed-identity backend.

**Step 2 — run** → FAIL (`New` signature, `Static`, `IdentitySource` missing).

**Step 3 — implement** in `agefile.go`:
```go
// IdentitySource yields the age identity the file backend decrypts/encrypts with, or
// an error (e.g. daemon.ErrLocked when the session is locked). Fetched PER operation so
// the key can live in the session and be zeroized on lock, not held by the backend.
type IdentitySource interface{ Identity() (age.Identity, error) }

// Static wraps a fixed identity as an IdentitySource (tests, plaintext/env path).
type Static struct{ ID age.Identity }
func (s Static) Identity() (age.Identity, error) { return s.ID, nil }

type Backend struct {
	src  IdentitySource
	path string
	wmu  sync.Mutex
}

func New(src IdentitySource, path string) *Backend { return &Backend{src: src, path: path} }
```
- `load()`: `id, err := b.src.Identity(); if err != nil { return nil, err }` then
  `age.Decrypt(f, id)`.
- `recipient()`: `id, err := b.src.Identity()` then type-assert `*age.X25519Identity`.
- `Resolve`/`Add`/`Remove` unchanged except they now surface the source error.

Update `cmd/avd/main.go`: `reg.Register("file", agefile.New(agefile.Static(id), vaultPath))`.
Update existing agefile tests: `New(id, path)` → `New(Static(id), path)`.

**Step 4 — run** `go test ./internal/backend/agefile/... -race` → PASS.
**Step 5 — commit** `refactor(agefile): identity via IdentitySource (per-op, not held)`.

---

### Task 3: Session holds the unwrapped identity

**Files:**
- Modify: `internal/daemon/session.go` (import `filippo.io/age`)
- Test: `internal/daemon/session_identity_test.go`

**Step 1 — failing test**: a session configured `WithUnwrapper(stub)` where stub
returns a known identity's bytes:
- after `UnlockWithIdentity` (or `Unlock` driving the unwrapper — see Task 4 for who
  calls it), `Identity()` returns a non-nil `age.Identity`;
- after `Lock()`, `Identity()` returns `ErrLocked` and the captured identity buffer is
  zeroized (`bytesForTest` all-zero);
- with NO unwrapper and locked, `Identity()` returns `ErrLocked`.

**Step 2 — run** → FAIL.

**Step 3 — implement** in `session.go`:
- Add fields: `unwrapper func() ([]byte, error)`, `identity *lockedValue`.
- `func (s *Session) WithUnwrapper(f func() ([]byte, error)) *Session` (sets it).
- `func (s *Session) HasUnwrapper() bool`.
- `func (s *Session) setIdentityLocked(b []byte)`: destroy any prior, store
  `newLockedValue(string(b))`.
- `func (s *Session) Identity() (age.Identity, error)`:
  ```go
  s.mu.Lock(); defer s.mu.Unlock()
  if s.lockedLocked() || s.identity == nil { return nil, ErrLocked }
  ids, err := age.ParseIdentities(strings.NewReader(s.identity.String()))
  if err != nil { return nil, err }
  if len(ids) == 0 { return nil, ErrLocked }
  return ids[0], nil
  ```
- In `destroyIssuedLocked()` ALSO destroy the identity: `if s.identity != nil { s.identity.Destroy(); s.identity = nil }` (so Unlock-stale-clear, Lock, and Issue-into-closed all zeroize the key — SSOT).
- Add `func (s *Session) unlockWithUnwrapper(ttl) error`: calls `s.unwrapper()`, on
  success `Unlock(ttl)` then `setIdentityLocked(bytes)`. (Server calls this in Task 4.)
  Order: unwrap BEFORE Unlock so a failed unwrap leaves the session locked.

`ErrLocked` already exists (presence.go). Confirm import.

**Step 4 — run** `go test ./internal/daemon/... -race` → PASS.
**Step 5 — commit** `feat(session): hold Enclave-unwrapped identity, zeroize on lock`.

---

### Task 4: Unlock unification (unwrap = presence)

**Files:**
- Modify: `internal/daemon/server.go` (`unlock` case)
- Test: `internal/daemon/server_unlock_test.go`

**Step 1 — failing test**: with a session `WithUnwrapper(stub)` and an INJECTED
presence that records calls: unlock calls the unwrapper, does NOT call
`presence.Prompt`, and afterwards `session.Identity()` succeeds. With NO unwrapper:
unlock calls `presence.Prompt` (existing behavior) and Identity() stays `ErrLocked`.
A failing unwrapper (returns `ErrDenied`) → response `CodeDenied`, session stays locked.

**Step 2 — run** → FAIL.

**Step 3 — implement** the `unlock` case:
```go
case "unlock":
	if s.session == nil { return errResp(req.ID, ipc.CodeInternal, "session not configured") }
	if s.session.HasUnwrapper() {
		if err := s.session.unlockWithUnwrapper(DefaultTTL); err != nil {
			code := ipc.CodeLocked
			if errors.Is(err, ErrDenied) { code = ipc.CodeDenied }
			return errResp(req.ID, code, err.Error())
		}
		s.audit.Log(audit.Event{Kind: "unlock"})
		return statusResponse(req.ID, s.session)
	}
	if s.presence == nil { return errResp(req.ID, ipc.CodeInternal, "presence not configured") }
	if err := s.presence.Prompt("Unlock AgentVault"); err != nil { /* existing mapping */ }
	s.session.Unlock(DefaultTTL)
	s.audit.Log(audit.Event{Kind: "unlock"})
	return statusResponse(req.ID, s.session)
```
NOTE: dangerous-tier resolve STILL uses `presence` for fresh per-access prompts — leave
the resolver untouched; only `unlock` changes.

**Step 4 — run** `go test ./internal/daemon/... -race` → PASS.
**Step 5 — commit** `feat(daemon): unlock unwraps the Enclave identity as the presence proof`.

---

### Task 5: `setup` RPC — provisioning

**Files:**
- Modify: `internal/ipc/proto.go` (SetupParams/SetupResult)
- Create: `internal/provision/provision.go` + `provision_test.go`
- Modify: `internal/daemon/server.go` (add `setup` case + `SetProvisioner`)
- Modify: `internal/client/client.go` (`Setup` method)

**Step 1 — proto** (`ipc/proto.go`): add
```go
type SetupParams struct{ Rotate, Plaintext bool }
type SetupResult struct{ VaultPath, IdentityPath string; Created bool }
```

**Step 2 — provision package** — failing test first (`provision_test.go`): with an
INJECTED wrap func (stub that returns its input prefixed, so no real Enclave needed),
`Provision` writes `identity.enc` + `vault.age` (mode 0600) under a temp dir, is
idempotent (`Created=false`, files untouched on re-run), `Rotate:true` regenerates,
`Plaintext:true` writes `identity.txt` (no wrap) instead of `identity.enc`, and the
vault decrypts back to an empty map with the generated identity.

**Step 3 — implement** `provision.go`:
```go
// Package provision creates the local age store for `av setup`: an X25519 identity
// (Enclave-wrapped by default) + an empty age vault. Linked only by avd — never by av.
package provision

type Options struct {
	Dir         string                       // default config.DefaultConfigDir()
	Rotate      bool
	Plaintext   bool
	Wrap        func([]byte) ([]byte, error) // injected: enclave.Wrap in prod, stub in tests
}
type Result struct{ VaultPath, IdentityPath string; Created bool }

func Provision(o Options) (Result, error) {
	// 1. resolve paths (Dir or config defaults); 0700 dir.
	// 2. if vault+identity exist and !Rotate -> Created:false, return (idempotent).
	// 3. age.GenerateX25519Identity(); idBytes := []byte(id.String()+"\n")
	// 4. plaintext: write identity.txt 0600; else blob,_ := o.Wrap(idBytes); write identity.enc 0600.
	// 5. agefile.EncryptVault(emptyVaultFile, id.Recipient(), map[string]string{}) atomically (temp+rename, 0600).
	// 6. Result{Created:true,...}.
}
```
Reuse `agefile.EncryptVault`. Atomic write (temp+fsync+rename) for the vault.

**Step 4 — daemon setup case + hook**: add to `Server`:
```go
provision func(ipc.SetupParams) (ipc.SetupResult, error)
func (s *Server) SetProvisioner(f func(ipc.SetupParams) (ipc.SetupResult, error)) { s.provision = f }
```
`case "setup"`: unmarshal params; if `s.provision == nil` → CodeInternal; call it; map
an "already provisioned" sentinel to a normal result with `Created:false`; marshal
SetupResult. (No secret in params/result — only paths + a bool.)

**Step 5 — client** (`client.go`): `func (c *Client) Setup(p ipc.SetupParams) (ipc.SetupResult, error)` via `call("setup", ...)`.

**Step 6 — run** `go test ./internal/provision/... ./internal/daemon/... ./internal/client/... -race` → PASS.
**Step 7 — commit** `feat(setup): setup RPC + provision package (Enclave-wrapped age store)`.

---

### Task 6: avd wiring — auto-discovery + live provisioner

**Files:**
- Modify: `cmd/avd/main.go`
- Test: extend `internal/client/e2e_test.go` (setup→add→unlock→run with a stub unwrapper/wrap)

**Step 1 — failing e2e** (`e2e_test.go`): spins real avd (test build) with a STUB
wrap/unwrap (a build-tag/env seam mirroring `AV_TEST_AUTH=allow`), runs `av setup`,
then `av add NPM=secret`, `av unlock`, `av run` masks the value. Assert no file backend
before setup; present after.

**Step 2 — implement** `cmd/avd/main.go`:
- `registerBackends`: when `AV_AGE_VAULT`/`AV_AGE_IDENTITY*` unset, fall back to
  `config.DefaultVaultPath()` + `config.DefaultEnclaveIdentityPath()`
  (or `DefaultPlaintextIdentityPath()`); if present, wire the file backend.
- For the Enclave path: DO NOT unwrap at startup. Instead set the session unwrapper:
  `sess.WithUnwrapper(func() ([]byte, error) { blob,_ := os.ReadFile(encPath); return enclave.Unwrap(blob) })`
  and register `agefile.New(sess, vaultPath)` (session is the IdentitySource).
- For the plaintext path (fallback/env): keep eager load → `agefile.New(agefile.Static(id), vaultPath)`.
- Wire `srv.SetProvisioner(func(p) { r := provision.Provision(... Wrap: enclave.Wrap ...);
  then live-register file backend + set session unwrapper for the new store; return r })`.
- A non-darwin/non-cgo `enclave.Wrap`/`Unwrap` already returns "unavailable" → setup of
  the Enclave path errors clearly there (we only ship darwin+cgo).

**Step 3 — run** full gate (`-race`, vet, cgo on/off, linux cross-compile, e2e) → PASS.
**Step 4 — commit** `feat(avd): auto-discover default store + live setup provisioner`.

---

### Task 7: `av setup` CLI + helpful `av add` error

**Files:**
- Modify: `cmd/av/main.go` (add `setup` subcommand; usage)
- Modify: `internal/client/client.go` if needed
- Test: `cmd/av/deps_test.go` stays green (TestAvStaysThin); add a small parse test if warranted

**Step 1 — implement** `av setup [--rotate] [--plaintext]`: parse flags → `client.Setup`
→ print `created <vault>` / `already provisioned at <vault>` (paths only). Map RPC
errors via `exitForError`.

**Step 2 — helpful add error**: `server.writer` already returns CodeBadRequest
"backend ... read-only or not registered" → in `cmd/av` `exitForError`/add path, when
backend is `file` and unregistered, the message should guide to `av setup`. Simplest:
have the daemon's `writer` return, for an unregistered `file` backend specifically,
`"no local vault — run 'av setup' first"`. Add a daemon test for that message + exit 2.

**Step 3 — run** `go test ./... -race` + `TestAvStaysThin` → PASS (av still thin: setup
is pure RPC, no age/enclave import).
**Step 4 — commit** `feat(av): av setup subcommand + 'run av setup' hint`.

---

### Task 8: Docs + formula caveats + README

**Files:**
- Create: `README.md`
- Modify: tap formula caveats (separate repo) — mention `av setup`
- Modify: `docs/launchagent.md` if it references manual avd

**Step 1** — write `README.md`: what it is, install (`brew install
beshkenadze/tap/agentvault`, `brew trust`), real flow (`brew services start
agentvault → av setup → av add → av run`), backends table (age/keychain/1p,
read/write), security model, manual-verification pointer, macOS-only note.

**Step 2** — commit `docs: README + av setup flow`.

---

### Final review

After Task 8: dispatch a final code-review subagent over the whole change against this
plan + the design doc; then run the full gate once more; then
superpowers:finishing-a-development-branch. Re-sign any unsigned commits once 1Password
is unlocked (see header).
