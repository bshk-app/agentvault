# SOPS age-plugin Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Let a developer keep their SOPS age private key inside AgentVault instead of plaintext in `keys.txt`, so `sops`, `helm secrets`, and `kustomize`+ksops decrypt through the daemon without the key ever reaching disk, `environ`, or their memory.

**Architecture:** A new binary `age-plugin-av` implements the age plugin `identity-v1` protocol using the framework in `filippo.io/age/plugin`. Its `Unwrap` forwards the file's header stanzas to `avd` over the existing socket; `avd` performs the X25519 unwrap inside its mlock'd, presence-gated session and returns only the per-file key. Encrypted files keep their ordinary `age1…` recipients, so Flux and teammates are unaffected — only the developer's identity string changes to `AGE-PLUGIN-AV-1…`, which is a pointer, not a secret.

**Tech Stack:** Go, `filippo.io/age` v1.3.1 (already in `go.mod` — no new dependency), the existing `internal/ipc` JSON-over-socket protocol, `internal/daemon` session/presence machinery, `internal/backend/agefile` vault storage.

**Design document:** `docs/plans/2026-07-26-sops-age-plugin-design.md`. Read it before starting.

---

## Background you need before Task 1

**The repo layout that matters:**

| Path | What it is |
|---|---|
| `internal/ipc/proto.go` | Request/Response types and the `Code*` constants. Every RPC param struct lives here. |
| `internal/daemon/server.go:418` | `dispatch` — the `switch req.Method` where a new RPC case goes. |
| `internal/client/client.go` | The `av`-side client. One method per RPC, all shaped like `Add` at line 285. |
| `cmd/av/main.go:49` | The `switch os.Args[1]` command table. |
| `internal/config/paths.go` | Platform paths. Has `//go:build !windows`; `paths_windows.go` is the sibling. |
| `internal/config/sops.go` | Where *sops* keeps its `keys.txt`, under sops's rules — deliberately separate from AgentVault's own paths above. |
| `internal/backend/agefile/agefile.go` | The vault: `Resolve`, `Add`, `Remove`, `List`. |

**Error codes.** `internal/ipc/proto.go`: `CodeInternal=1`, `CodeBadRequest=2`, `CodeLocked=3`, `CodeDenied=4`, `CodeUnauthorized=5`, `CodeRateLimited=6`. `cmd/av/main.go`: `exitGeneric=1`, `exitBadRequest=2`, `exitLocked=69`, `exitDenied=77`.

**Commands you will run constantly:**

```bash
make test        # go test ./...
make vet         # go vet ./...
make cross-test  # compile tests for linux+windows without running them
```

**Conventions to match.** Comments in this repo explain *why*, not *what*, and they are dense on anything security-relevant. Errors never carry secret values — only names. Match that or the review will bounce it.

---

## Task 1: Spike — prove a plugin receives standard X25519 stanzas

**This task gates every other task.** The whole design assumes age hands a plugin the ordinary `X25519` stanzas from a file's header. `filippo.io/age/plugin/client.go` appears to forward every stanza without filtering, but that is a reading of source, not an observation. If this test cannot pass, encrypted files would have to be re-keyed to a plugin recipient, Flux and every teammate would break, and **the design must be revisited before writing anything else.**

**Files:**
- Create: `internal/sopsplugin/testdata/plugin/main.go`
- Create: `internal/sopsplugin/spike_test.go`

**Step 1: Write the throwaway test plugin**

It is under `testdata/` on purpose: the go tool skips `testdata` directories when expanding `./...`, so this never ships in a build, but `go build ./internal/sopsplugin/testdata/plugin` still works when named explicitly.

```go
// Command age-plugin-avtest is a TEST-ONLY age plugin used by the spike in
// internal/sopsplugin. It proves that the age plugin protocol delivers ordinary
// X25519 stanzas to a plugin. It takes its identity from AV_TEST_PLUGIN_KEY and
// is never built into a release — see the testdata/ placement.
package main

import (
	"fmt"
	"os"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

type identity struct{ inner *age.X25519Identity }

// Unwrap receives EVERY stanza in the file header, including plain X25519 ones,
// and delegates to the standard age identity.
func (i *identity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	return i.inner.Unwrap(stanzas)
}

func main() {
	p, err := plugin.New("avtest")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	p.HandleIdentity(func(_ []byte) (age.Identity, error) {
		inner, err := age.ParseX25519Identity(os.Getenv("AV_TEST_PLUGIN_KEY"))
		if err != nil {
			return nil, err
		}
		return &identity{inner: inner}, nil
	})
	os.Exit(p.Main())
}
```

**Step 2: Write the failing test**

```go
// Package sopsplugin holds the AgentVault age plugin's daemon-facing logic.
package sopsplugin_test

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// TestPluginUnwrapsStandardX25519Stanza is the load-bearing test of the SOPS design.
// It encrypts to an ORDINARY age1... recipient (no plugin on the write side) and
// decrypts through a plugin. Passing means SOPS files keep their normal recipients, so
// Flux, CI, and teammates decrypt them unchanged. Failing invalidates the design.
func TestPluginUnwrapsStandardX25519Stanza(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin discovery on Windows is verified by the smoke script, not here")
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt with a STANDARD recipient. This is the crux: nothing here knows about plugins.
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, "spike payload"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Build the test plugin and put it on PATH under the name age discovers it by.
	dir := t.TempDir()
	build := exec.Command("go", "build", "-o", filepath.Join(dir, "age-plugin-avtest"), "./testdata/plugin")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build test plugin: %v\n%s", err, out)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("AV_TEST_PLUGIN_KEY", id.String())

	pid, err := plugin.NewIdentity(plugin.EncodeIdentity("avtest", id.Recipient().(*age.X25519Recipient).Bytes()), nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.Decrypt(bytes.NewReader(ct.Bytes()), pid)
	if err != nil {
		t.Fatalf("decrypt through plugin: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "spike payload" {
		t.Fatalf("got %q, want %q", got, "spike payload")
	}
}
```

**Step 3: Run it**

```bash
go test ./internal/sopsplugin/ -run TestPluginUnwrapsStandardX25519Stanza -v
```

Expect it to compile-fail or fail first. Then make it pass.

**Two API details to resolve while making it pass**, both by reading `go doc`:

```bash
go doc filippo.io/age/plugin.EncodeIdentity
go doc filippo.io/age/plugin.NewIdentity
go doc filippo.io/age.X25519Recipient
```

- `plugin.NewIdentity` takes a `*plugin.ClientUI`. Passing `nil` may panic; if so, construct a minimal UI whose callbacks return errors — the spike needs no interaction.
- Getting the raw 32 bytes out of an `age.X25519Recipient` may need a different accessor than `.Bytes()`. If none is exported, parse them out of the bech32 `age1…` string, or simply pass an empty `data` slice — the test plugin ignores `data` anyway. **Do not add a dependency to work around this.**

**Step 4: STOP and evaluate**

- **Test passes** → the design holds. Commit and continue to Task 2.
- **The plugin never receives the `X25519` stanza** → stop. Report it. The design needs rework; do not start Task 2.

**Step 5: Commit**

```bash
git add internal/sopsplugin/
git commit -m "test: prove an age plugin can unwrap standard X25519 stanzas"
```

---

## Task 2: Identity encoding

`AGE-PLUGIN-AV-1…` names the recipient, so `avd` knows which stored key a file wants before prompting for presence.

**As implemented, the payload is the recipient's bech32 `age1…` text, not raw bytes.** `age.X25519Recipient` in v1.3.1 exports only `ParseX25519Recipient`, `String`, and `Wrap` — there is no byte accessor, and age's bech32 helper is an internal package. Recovering 32 raw bytes would mean reimplementing bech32 or taking a dependency, neither of which is worth ~50 bytes in a string nobody types.

**Consequence for Task 6:** `ipc.SopsUnwrapParams.Recipient` carries ASCII, not a 32-byte point. Compare recipients by `String()`, or parse with `age.ParseX25519Recipient` first — do not assume a fixed-length slice.

The field is `[]byte`, and Go marshals `[]byte` to **base64** over JSON, so what crosses the wire is base64-of-ASCII and the daemon decodes it back to the `age1…` text. The trap is `bytes.Equal(p.Recipient, someRawKey)`: it compares bech32 text against raw bytes and silently never matches. Compare on `String()` or on parsed recipients.

**Files:**
- Create: `internal/sopsplugin/identity.go`
- Create: `internal/sopsplugin/identity_test.go`

**Step 1: Write the failing test**

```go
func TestEncodeDecodeIdentityRoundTrip(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	s := sopsplugin.EncodeIdentity(id.Recipient())
	if !strings.HasPrefix(s, "AGE-PLUGIN-AV-1") {
		t.Fatalf("got %q, want an AGE-PLUGIN-AV-1 prefix", s)
	}
	got, err := sopsplugin.DecodeIdentity(s)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != id.Recipient().String() {
		t.Fatalf("round trip changed the recipient: %s != %s", got, id.Recipient())
	}
}

func TestDecodeIdentityRejectsOtherPlugins(t *testing.T) {
	if _, err := sopsplugin.DecodeIdentity(plugin.EncodeIdentity("yubikey", []byte("x"))); err == nil {
		t.Fatal("want an error for a foreign plugin identity, got nil")
	}
}
```

**Step 2: Run it, confirm it fails**

```bash
go test ./internal/sopsplugin/ -run TestEncodeDecodeIdentity -v
```

**Step 3: Implement**

```go
// PluginName is the age plugin name. age discovers the binary as "age-plugin-av"
// and encodes identities as "AGE-PLUGIN-AV-1..." from this one constant.
const PluginName = "av"

// EncodeIdentity renders the pointer a user puts in keys.txt. It carries the RECIPIENT
// (a public key), never a private key: without a running avd and a presence check it
// decrypts nothing, so it is safe to commit, paste, or share.
func EncodeIdentity(r *age.X25519Recipient) string { ... }

// DecodeIdentity parses a pointer back into the recipient it names. It rejects
// identities belonging to other plugins so a misconfigured keys.txt fails clearly
// instead of reaching the daemon.
func DecodeIdentity(s string) (*age.X25519Recipient, error) { ... }
```

Build both on `plugin.EncodeIdentity` / `plugin.ParseIdentity`.

**Step 4: Run, confirm pass. Step 5: Commit**

```bash
git add internal/sopsplugin/
git commit -m "feat(sops): encode AGE-PLUGIN-AV identity pointers"
```

---

## Task 3: `keys.txt` discovery

SOPS looks in a different place on each platform, and macOS is not the obvious one — it prefers `XDG_CONFIG_HOME` and falls back to `~/Library/Application Support`, not `~/.config`.

**Files:**
- Create: `internal/config/sops.go`, `internal/config/sops_test.go`

New files rather than the build-tagged `paths.go` / `paths_windows.go` pair: sops expresses this same split with a runtime `runtime.GOOS == "darwin"` check rather than build tags, so mirroring that keeps the correspondence to `sops/age/keysource.go` auditable in one place, and taking `goos` as a parameter lets every platform's row execute on every host instead of only the one it was compiled for.

**Step 1: Write the failing tests** — table-driven, driving `HOME` and `XDG_CONFIG_HOME` with `t.Setenv`:

| GOOS | `XDG_CONFIG_HOME` | Expected |
|---|---|---|
| linux | set | `$XDG_CONFIG_HOME/sops/age/keys.txt` |
| linux | unset | `$HOME/.config/sops/age/keys.txt` |
| darwin | set | `$XDG_CONFIG_HOME/sops/age/keys.txt` |
| darwin | unset | `$HOME/Library/Application Support/sops/age/keys.txt` |
| windows | — | `%AppData%\sops\age\keys.txt` |

**Step 2–4:** Run, implement `SopsKeysFilePath() string`, run again.

**Step 5: Commit**

```bash
git add internal/config/
git commit -m "feat(config): resolve the SOPS keys.txt path per platform"
```

---

## Task 4: Store SOPS identities in the vault

Identities live in the existing vault (`vault.age`) under a reserved `sops/` prefix. Do **not** create a second encrypted file — that would duplicate the atomic write, flock, and encryption in `internal/backend/agefile/agefile.go`.

**Files:**
- Create: `internal/sopsplugin/store.go`, `internal/sopsplugin/store_test.go`

**Step 1: Write failing tests** covering: `Put` then `Get` round-trips a private key; `List` returns names and recipients but **never** a private key; `FindByRecipient` returns the identity matching a recipient; `FindByRecipient` returns `backend.ErrNotFound` for an unknown recipient.

**Step 2: Run, confirm failure.**

**Step 3: Implement** over `backend.Backend` + `backend.Writer`:

```go
// namespace prefixes every SOPS identity stored in the shared vault. `av read` refuses
// names under it, which is what keeps a SOPS private key from being printed the way an
// ordinary secret can be.
const namespace = "sops/"
```

`FindByRecipient` lists the namespace, parses each stored `AGE-SECRET-KEY-1…`, derives its recipient, and compares. Deriving is cheap and the vault is already decrypted at that point, so no public index is needed.

**Step 4: Run, confirm pass. Step 5: Commit**

```bash
git add internal/sopsplugin/
git commit -m "feat(sops): store SOPS identities under a reserved vault namespace"
```

---

## Task 5: Block `av read` on the `sops/` namespace

The namespace is only meaningful if something enforces it.

**Files:**
- Modify: `cmd/av/read_test.go`, then `cmd/av/main.go` (`runRead`, line 212) or the daemon resolve path — whichever the existing tests indicate is the enforcement point.

**Step 1:** Test that `av read sops/mykey` exits `exitBadRequest` with a message naming `av sops`, not a value.
**Step 2:** Run, confirm failure. **Step 3:** Implement. **Step 4:** Run, confirm pass.

**Step 5: Commit**

```bash
git commit -am "feat(sops): refuse av read on the sops/ namespace"
```

---

## Task 6: The `sops_unwrap` RPC

**Files:**
- Modify: `internal/ipc/proto.go`
- Modify: `internal/daemon/server.go` (new case in `dispatch`, line 418)
- Create: `internal/daemon/sops_rpc_test.go` (mirror `internal/daemon/addrm_rpc_test.go`)

**Step 1: Add the wire types** to `internal/ipc/proto.go`:

```go
// SopsStanza is one age header stanza, ferried verbatim between age-plugin-av and the
// daemon. Body is ciphertext, not a secret value, but it is still never logged.
type SopsStanza struct {
	Type string   `json:"type"`
	Args []string `json:"args"`
	Body []byte   `json:"body"`
}

// SopsUnwrapParams asks the daemon to unwrap a file key. Recipient names WHICH stored
// SOPS identity to use, so the daemon can reject a file this key was never encrypted to
// before spending a presence prompt on it.
type SopsUnwrapParams struct {
	Recipient []byte       `json:"recipient"`
	Stanzas   []SopsStanza `json:"stanzas"`
	NoPrompt  bool         `json:"no_prompt,omitempty"`
}

// SopsUnwrapResult carries the per-FILE key. It decrypts exactly one file and is
// useless for any other, which is the entire point of brokering here rather than
// handing over the identity.
type SopsUnwrapResult struct {
	FileKey []byte `json:"file_key"`
}
```

**Step 2: Write failing RPC tests.** Copy the harness from `internal/daemon/addrm_rpc_test.go`. Cover:

1. A stored identity unwraps a stanza produced for its own recipient.
2. An unknown recipient returns `CodeBadRequest` — and **no presence prompt fires**. Assert on the stub presence counter; this is the guard that stops a `kustomize build` over a large repo from prompting for files that are not yours.
3. A locked session with `NoPrompt: true` returns `CodeLocked` and does not prompt.
4. A locked session with `NoPrompt: false` prompts once, then succeeds.
5. The audit log records the identity name and outcome, and **contains neither the file key nor the private key**. Assert the negative explicitly.

**Step 3: Run, confirm failure.**

**Step 4: Implement the dispatch case.** Model it on `case "add"` at `server.go:527` — resolve the target first so a routing fault reports precisely regardless of lock state, then `ensureUnlockedResp` before the operation:

```go
case "sops_unwrap":
	var p ipc.SopsUnwrapParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return errResp(req.ID, ipc.CodeBadRequest, err.Error())
	}
	// Identify the key BEFORE unlocking: a file encrypted to someone else must fail
	// fast and silently rather than cost the user a Touch ID. See test 2.
	...
	if rejection := s.ensureUnlockedResp(req.ID, p.NoPrompt); rejection != nil {
		return *rejection
	}
	// SECURITY: fileKey is a secret. It goes into the response and nowhere else —
	// never into a log line, never into an error.
	...
```

**Step 5: Run, confirm pass. Step 6: Commit**

```bash
git add internal/ipc/ internal/daemon/
git commit -m "feat(daemon): add the sops_unwrap RPC"
```

---

## Task 7: Client method

**Files:**
- Modify: `internal/client/client.go`
- Create: `internal/client/sops_test.go`

Follow `Add` at `client.go:285` exactly — `ensureFresh`, marshal params, `call`, return `resp.Error` if set.

```go
git commit -am "feat(client): add SopsUnwrap"
```

---

## Task 8: The `age-plugin-av` binary

**Files:**
- Create: `cmd/age-plugin-av/main.go`
- Create: `cmd/age-plugin-av/main_test.go`

**Step 1: Write the failing end-to-end test.** This is Task 1's spike pointed at the real binary and a real ephemeral daemon. Reuse the daemon harness from `internal/client/e2e_test.go`. Assert: a file encrypted to a standard `age1…` recipient, whose key is stored in the vault, decrypts through `age-plugin-av`.

**Step 2: Run, confirm failure.**

**Step 3: Implement.** The framework does the protocol; this is nearly all the code:

```go
// Command age-plugin-av is AgentVault's age plugin. age discovers it by filename, so it
// MUST stay named age-plugin-av. It holds no key and performs no cryptography: it
// forwards the file's header stanzas to avd, which unwraps them inside its mlock'd
// session and returns only the per-file key.
package main

func main() {
	p, err := plugin.New(sopsplugin.PluginName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "age-plugin-av:", err)
		os.Exit(1)
	}
	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		return &daemonIdentity{recipient: data}, nil
	})
	os.Exit(p.Main())
}
```

**Step 4: Handle the locked-vault message.** SOPS collects identity-loading errors and reports them only if decryption fails outright, so a bare error surfaces as an opaque "failed to decrypt". Return an error whose text is self-explanatory in that context:

```
AgentVault: vault locked — ask a human to run `av unlock`
```

Under `AV_NO_PROMPT=1` (see `noPrompt()` at `cmd/av/main.go:387`) the plugin must return this immediately rather than block. Add a test asserting the message reaches the caller and that the process exits rather than hanging.

**Step 5: Run, confirm pass. Step 6: Commit**

```bash
git add cmd/age-plugin-av/
git commit -m "feat: add the age-plugin-av binary"
```

---

## Task 9: The `av sops` commands

Build these one subcommand at a time, test-first, committing each. Register them under a single `case "sops":` in the `cmd/av/main.go:49` switch.

```
av sops import [--from PATH] [--name NAME]
av sops keygen NAME [--tier normal|dangerous]
av sops ls
av sops recipient NAME
av sops identity NAME
av sops rm NAME
```

Order and specifics:

1. **`keygen`** — easiest, no filesystem interaction. Generate, store, print the `age1…` recipient with a one-line hint to add it to `.sops.yaml`.
2. **`ls`** — names, recipients, tiers. Test that no private key appears in the output.
3. **`recipient`** / **`identity`** — one-line printers.
4. **`rm`** — **guarded.** Deleting the only copy of a key that files are encrypted to destroys those files permanently. Require an interactive confirmation; refuse outright when stdin is not a TTY unless `--force` is passed. Test both paths.
5. **`import`** — the most involved. Read the key from `--from`, or from the first `config.SopsKeysFileCandidates()` entry that exists; store it; then rewrite **that same file** with the pointer:

```
# managed by AgentVault — this is a pointer, not a key.
# recipient: age1abc…
# useless without a running avd + your presence check.
AGE-PLUGIN-AV-1QQQ…
```

`import` must report which file it found before touching it and ask whether to keep a backup, and it must never delete a key silently. Test: an existing `keys.txt` with two keys imports both; a missing file reports every location it checked — use `config.SopsKeysFileCandidates()`, which is ordered and already accounts for `SOPS_AGE_KEY_FILE`.

**Rewrite the file you actually read the key from. Never `config.SopsKeysFilePath()` blindly.** `SOPS_AGE_KEY_FILE` is *additive, not an override*: sops opens it **and** the user-config-dir file, as two independent readers. So take a user with `SOPS_AGE_KEY_FILE=~/mykeys.txt`. `import` finds their key there — correctly, it is candidate 0 — but if it then writes the pointer to `SopsKeysFilePath()`, the pointer lands in the config-dir file and `~/mykeys.txt` is left untouched. sops now reads both: the plaintext key is still sitting on disk, still decrypting every file, the plugin is never once exercised, and the user has been told their key is in the vault when it is not. **That is the whole feature failing silently while reporting success** — and nothing in normal use will reveal it, because everything still decrypts. Carry the path the key came from (`--from`, or whichever candidate matched) through to the rewrite and write to exactly that.

**"Found nothing" is not the same as "you have no key."** Task 3 established that sops reads its identity from four places, and only two are filesystem paths. A user whose key comes from `SOPS_AGE_KEY` (inline key text) or `SOPS_AGE_KEY_CMD` (a command that prints one) has a working setup that a path search cannot see. Reporting a bare "no keys.txt found" to that user is wrong and will send them hunting for a file that was never supposed to exist. When neither env var is set, say which paths were checked; when either *is* set, say so and explain that importing means moving the key into the vault and dropping that variable.

Also detect the `sops` version and warn when it is below 3.10, which is where plugin support landed. An obscure decryption failure later is much worse than a clear warning now.

**Step: update usage.** `usage()` at `cmd/av/main.go:84` is one long string. Add the `sops` lines there or `av sops` stays invisible.

Commit after each subcommand.

---

## Task 10: Build and packaging

**Files:**
- Modify: `Makefile`
- Modify: `packaging/agentvault-cask.json` and the Homebrew formula
- Modify: `scripts/release-signed.sh`

**Step 1:** Add to the `build` target, matching the two existing lines:

```make
	go build -ldflags "-X main.version=$(VERSION)" -o bin/age-plugin-av ./cmd/age-plugin-av
```

**Step 2:** Confirm `make build && make test && make vet && make cross-test` all pass.

**Step 3:** Ship the binary in the same directory as `av`. age discovers plugins on `PATH` by filename, so an install that misses it produces a confusing "no identity matched" rather than a missing-file error.

**Step 4: Commit**

```bash
git commit -am "build: ship the age-plugin-av binary"
```

---

## Task 11: Smoke script

**Files:**
- Create: `scripts/smoke-sops.sh`

Model it on `scripts/smoke-backends.sh` — read its header first and match the style: ephemeral daemon on a temp socket, `AV_TEST_AUTH=allow` by default, `REAL_AUTH=1` for the real presence path, torn down on exit, re-runnable, touching nothing real.

Cover, skipping each when the tool is absent:

1. `sops -d` on a file encrypted to a standard recipient.
2. `sops updatekeys` — it decrypts and re-encrypts, so it should work unchanged, but it is unverified.
3. `helm secrets template`.
4. `kustomize build --enable-alpha-plugins` with ksops.
5. A locked vault under `AV_NO_PROMPT=1` produces the readable message, not a hang.

```bash
git add scripts/smoke-sops.sh
git commit -m "test: add the SOPS real-tool smoke script"
```

---

## Task 12: Documentation

**Files:**
- Modify: `README.md` — a `SOPS` section after `Backends`, plus the `av sops` lines in the CLI block.
- Create: `docs/sops.md` — the walkthrough: import, `.sops.yaml`, helm/kustomize usage, rotation via `keygen` + `updatekeys`, and troubleshooting.
- Modify: `docs/security-model.md` — what brokering the SOPS key does and does not protect.

Be accurate about scope in `docs/security-model.md`. This protects the key from `sops`, `helm`, `kustomize`, and everything else in the process tree. It does **not** protect the decrypted *output* — `helm secrets` still writes plaintext values into temporary files, and that is outside AgentVault's boundary. Say so plainly rather than let a reader infer more than the feature delivers.

```bash
git commit -am "docs: document the SOPS age-plugin integration"
```

---

## Deferred to phase 2

The `av://sops/<file>#<dotted.key>` reader backend. It shells out to `sops -d`, exactly as `internal/backend/onepassword` and `internal/backend/bitwarden` shell out to `op read` and `bw get`.

**Design hazard to carry forward:** it is re-entrant. `avd` spawns `sops`, which calls back into `avd` for `sops_unwrap`. A handler holding a lock while waiting on the subprocess deadlocks the daemon. Hold no lock across the `exec`.

## Open risks

- **Windows plugin discovery.** Untested. Verify before claiming Windows parity.
- **`sops updatekeys` through the plugin.** Should work; confirm in Task 11.
- **`plugin.ClientUI` in Task 1.** May not accept `nil`. Read `go doc` rather than guessing.
