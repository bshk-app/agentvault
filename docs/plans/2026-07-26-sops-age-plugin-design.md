# AgentVault — SOPS integration via an age plugin

**Status:** Approved (design phase)
**Date:** 2026-07-26
**Author:** Aleksandr

## Problem

Teams that encrypt Kubernetes manifests with SOPS + age keep the private key in
`~/.config/sops/age/keys.txt`, plaintext, mode 0600. Every process the user runs can
read it. It survives in Time Machine snapshots, in backups, in `$HISTFILE` when someone
pastes it. `helm secrets`, `kustomize` + ksops, and `sops` itself all load it on every
invocation, so the exposure is continuous rather than occasional.

AgentVault already solves this shape of problem for environment variables. It already
speaks age — `filippo.io/age` backs the local vault, and the vault identity is wrapped
by the Secure Enclave or the OS keyring and unwrapped only into an mlock'd, presence-
gated, TTL-bounded session. The SOPS key deserves the same protection.

Goal: **the developer's SOPS age key never exists as plaintext on disk, in `environ`,
or in the memory of `sops`, `helm`, or `kustomize` — and no encrypted file, `.sops.yaml`
rule, or teammate's workflow changes.**

## Scope

In:

- `age-plugin-av`, an age plugin that brokers decryption through `avd`.
- `av sops`, commands that manage SOPS identities.
- A `sops_unwrap` RPC in `avd`.

Out, deliberately:

- **Encryption** (`sops -e`, `sops edit` on save). Encryption needs only the public
  recipients from `.sops.yaml`. No private key participates, so there is nothing to broker.
- **In-cluster decryption.** Flux's `kustomize-controller` decrypts with its own key from
  a Kubernetes Secret. AgentVault covers the developer's machine only.
- **A new file format or new recipients.** Files stay encrypted to ordinary `age1…`
  recipients. `.sops.yaml` is untouched.
- **The `av://sops/…` reader backend.** Phase 2, specified below.

## Decisions (validated)

### 1. Broker the key through an age plugin, not an environment variable

Three mechanisms could deliver the key to SOPS:

| Mechanism | Key ends up in | Verdict |
|---|---|---|
| `SOPS_AGE_KEY` via `av run` | `environ` of the whole process tree | Works today with zero code; weakest |
| `SOPS_AGE_KEY_CMD` → `av sops-key` | memory of `sops` | Good; key still materializes |
| `age-plugin-av` | nowhere outside `avd` | **Chosen** |

With the plugin, `avd` performs the X25519 unwrap itself and returns only the file key —
a per-file value that decrypts one file and nothing else. The private key never leaves
the daemon.

### 2. Files keep their standard `age1…` recipients

This is the decision the whole design rests on, and it holds because age forwards **every**
header stanza to the plugin without filtering by type. From `filippo.io/age/plugin/client.go`:

```go
// Phase 1: client sends the plugin the identity string and the stanzas
writeStanza(conn, "add-identity", i.encoding)
for _, rs := range stanzas {              // no type filter
    s := &format.Stanza{
        Type: "recipient-stanza",
        Args: append([]string{"0", rs.Type}, rs.Args...),
        Body: rs.Body,
    }
    s.Marshal(conn)
}
```

So the plugin receives ordinary `X25519` stanzas and can unwrap them with an ordinary
X25519 key. Only the developer's *identity string* changes, from `AGE-SECRET-KEY-1…` to
`AGE-PLUGIN-AV-1…`. Flux, teammates, and CI read the same files with the same keys.

SOPS routes plugin identities correctly. `sops/age/keysource.go`:

```go
func parseIdentity(s string) (age.Identity, error) {
	switch {
	case strings.HasPrefix(s, "AGE-PLUGIN-"):
		return plugin.NewIdentity(s, pluginTerminalUI)
	...
```

Every identity source — `SOPS_AGE_KEY`, `SOPS_AGE_KEY_FILE`, and the default `keys.txt`
— funnels through this function, so a pointer written into `keys.txt` works everywhere.

Requires SOPS ≥ 3.10, which added age plugin support
([#1641](https://github.com/getsops/sops/pull/1641)).

### 3. The identity string is a pointer, not a secret

`AGE-PLUGIN-AV-1…` encodes the recipient public key. It names a key; it does not contain
one. Publish it, commit it to dotfiles, paste it in chat — without a running `avd` and a
presence check it decrypts nothing. Encoding the recipient also lets `avd` reject files
that were never encrypted to this key before prompting for presence.

### 4. SOPS identities are a first-class concept, stored in the existing vault

`av sops` treats an identity as its own object, with its own commands and its own access
rules. Storage reuses the existing vault (`vault.age`, see `internal/config/paths.go`)
under a reserved `sops/` namespace rather than a second encrypted file: a sibling file
would duplicate the atomic write, the flock, and the encryption from
`internal/backend/agefile/agefile.go` while differing only in access policy. Policy
belongs in the command layer, so that is where it goes — `av read` refuses names under
`sops/`.

### 4a. No new dependency

`filippo.io/age/plugin` ships a plugin-authoring framework — `plugin.New`,
`HandleIdentity`, `Main`, and the `EncodeIdentity`/`ParseIdentity` bech32 helpers — added
in age v1.3.0. `go.mod` already pins age v1.3.1. The protocol state machine, the stanza
wire format, and the identity encoding all come from the library, which reduces
`cmd/age-plugin-av` to an `Unwrap` method that calls the daemon.

### 5. One presence check per command, not per file

`helm secrets template` or `kustomize build` touches dozens of encrypted files, each a
separate decryption. Touch ID on every file would make the feature unusable.

- **Default tier `normal`:** the first decryption prompts for presence; the rest of the
  command runs inside the open session. One touch per `helm upgrade`.
- **Per-identity `--tier dangerous`:** presence on every file. Slow on purpose — a
  production deploy should be hard to perform absent-mindedly.
- **The first dangerous file on a *locked* vault costs TWO checks**, not one: the unwrap
  that opens the session, then the fresh per-file check. They buy different things — the
  first a session every later file rides for free, the second the per-file gate the tier
  exists for — and skipping the second because the session happens to be new would mean
  the first dangerous file of the day is the one that never prompts. It matches what
  `av run` on a dangerous entry from a locked vault already costs. Written down because
  "one check per file" reads like a promise of exactly one.
- Audit comes free from `internal/audit`. Each unwrap that reached an identity logs its
  name, tier, and outcome — never a value. An unknown recipient logs nothing: there is no
  identity to name, and one line per foreign file would drown the log exactly where it
  matters least.
- **Rate limiting deliberately does not apply here, correcting this document's first
  draft.** The limiter in `internal/daemon/ratelimit.go` belongs to the `Resolver` and its
  budget — 30 issuances per 60s — is sized for per-*command* issuance. An unwrap happens
  per *file*, so wiring the existing limiter in would force-relock the session partway
  through a `kustomize build` over any repo with 30+ encrypted files, turning a working
  setup into an intermittent one. Metering unwraps would need its own, far larger budget.
  Leaving them unmetered is consistent with the threat model in `docs/security-model.md`,
  which is cooperative-agent: the limiter exists to blunt mass enumeration by a confused
  agent, and an agent that can call `sops_unwrap` at will can equally call `sops -d` at
  will.

### 6. Agents fail fast, as they do everywhere else

SOPS collects identity-loading errors and reports them only if decryption fails outright,
so a locked vault would otherwise surface as an opaque "failed to decrypt". The plugin
protocol carries a `msg` command for exactly this. Under `AV_NO_PROMPT=1` the plugin skips
the presence request and returns `AgentVault: vault locked — ask a human to run
av unlock`, matching the exit-69 behavior of every other command.

**Amended by Task 6's review: the plugin RELAYS the daemon's message rather than hard-coding
that one.** `CodeLocked` turned out to cover two situations — a locked session, and a
dangerous-tier identity whose fresh per-file check was skipped under `no_prompt`, where the
session is open and `av unlock` changes nothing. A fixed "run `av unlock`" makes the second
a loop, and the plugin is the last layer that could have told them apart. The text above
remains what the daemon sends for a genuinely locked session.

### 7. "Try the next identity" is a wire code, not a phrase — `CodeNoMatch`

*Added by Task 8's review, which found that a two-key `keys.txt` could not decrypt at all.*

`age.Decrypt` tries identities in sequence and advances to the next one **only** on
`age.ErrIncorrectIdentity`; any other error aborts the whole decrypt. Decision 6 has the
plugin relay every daemon refusal as a hard error — so with two AgentVault pointers in
`keys.txt` and a file encrypted to the second key, the first identity's *"no stanza in this
file was encrypted to it"* ended the decrypt and the second was never tried. That is not an
edge case: it is a personal key plus a team key, and `av sops import` imports both.

The fix cannot be message matching. *"no stored SOPS identity for recipient…"* and *"no
stanza in this file was encrypted to it"* both arrived as `CodeBadRequest`, alongside
refusals that must NOT fall through, and sniffing prose to tell them apart would swallow the
very messages decision 6 exists to surface. So the distinction moves onto the wire:

**`ipc.CodeNoMatch` (7) means "this identity cannot decrypt this file; try another."** The
daemon returns it for the two refusals that mean exactly that, and nothing else:

| Situation | Code | Plugin behaviour |
| --- | --- | --- |
| Recipient names no stored identity (`backend.ErrNotFound`) | `CodeNoMatch` | fall through |
| Stored identity decrypts no stanza in this file (`age.ErrIncorrectIdentity`) | `CodeNoMatch` | fall through |
| Header stanzas malformed / recipient unparseable | `CodeBadRequest` | hard error, shown |
| Vault locked, or dangerous tier under `no_prompt` | `CodeLocked` | hard error, shown |
| Presence denied | `CodeDenied` | hard error, shown |
| Corrupt vault entry, unregistered backend | `CodeInternal` | hard error, shown |

`age-plugin-av` maps `CodeNoMatch` — and only `CodeNoMatch` — to `age.ErrIncorrectIdentity`.
Everything else is still relayed verbatim under the `AgentVault: ` prefix.

**What this costs, accepted deliberately.** A *stale* pointer — the key was deleted from the
vault but its line stayed in `keys.txt` — is `ErrNotFound`, so it now falls through
silently. When it sits beside a live pointer that is exactly right. When it is the *only*
pointer, the daemon's message naming the missing recipient no longer reaches the user: age's
identity loop discards the error it falls through on, so the user sees age's generic *"no
identity matched any of the recipients"* instead. `av sops ls` is the recovery.

The `msg` protocol command cannot buy the diagnostic back. It exists
(`plugin.Plugin.DisplayMessage`) and may be called from `Unwrap`, but the plugin has no way
to know which kind of no-match it is holding — that is precisely what one shared code
erases — and emitting on both would print a line per file per identity during every
`kustomize build` over a repo of other teams' secrets, which is the noise decision 5 exists
to prevent. It also fails closed in the wrong direction: a client that cannot display the
message sets the framework's `broken` flag, which aborts the run the fall-through was meant
to keep alive. Correctness first; the diagnostic is documented instead.

## Architecture

```
sops / helm-secrets / ksops / kustomize build
   │  identity: AGE-PLUGIN-AV-1…  (keys.txt, SOPS_AGE_KEY, or SOPS_AGE_KEY_FILE)
   ▼
filippo.io/age/plugin  ──exec──▶  age-plugin-av
   │   stdio: add-identity, recipient-stanza ×N                │
   │                                            existing socket / named pipe
   │◀──────────── file-key 0 <32 bytes> ────────────────────────┤
                                                               ▼
                                                    avd — RPC sops_unwrap
                                                               │
                                       Session (mlock, presence, TTL)
                                                               │
                                           vault.age → sops/<name>
```

`age-plugin-av` implements `identity-v1` only. It holds no state, performs no
cryptography, and caches nothing: it forwards stanzas to `avd` and returns the file key.
`avd` gains one dispatch case in `internal/daemon/server.go` alongside `resolve`, `add`,
and `unlock`.

## CLI

```
av sops import [--from PATH] [--name NAME]   move a key from keys.txt into the vault
av sops keygen NAME [--tier normal|dangerous]  generate a new identity
av sops ls                                   names and recipients (never private keys)
av sops recipient NAME                       print age1… for .sops.yaml
av sops identity NAME                        print AGE-PLUGIN-AV-1…
av sops rm NAME                              delete (guarded)
```

`av sops import` reports which file it found before touching it and asks whether to keep a
backup or overwrite. It never deletes a key silently.

`av sops rm` is the dangerous command here, not `keygen`. Deleting the only copy of a key
that files are encrypted to destroys those files permanently, so `rm` requires explicit
confirmation and says so plainly.

`keygen` earns its place through rotation. An imported key has already spent time as
plaintext on disk and that cannot be undone; a generated key never has. The path is
`import` today, then `keygen` + `sops updatekeys` + drop the old recipient from
`.sops.yaml` when convenient.

## On-disk layout

After `av sops import`, `keys.txt` holds a pointer:

```
# managed by AgentVault — this is a pointer, not a key.
# recipient: age1abc…
# useless without a running avd + your presence check.
AGE-PLUGIN-AV-1QQQ…
```

SOPS ignores `#` lines, so whoever opens this file a year from now understands it.

Where that file lives differs by platform, and macOS differs from the obvious guess:

| Platform | Path |
|---|---|
| Linux | `$XDG_CONFIG_HOME/sops/age/keys.txt`, else `~/.config/sops/age/keys.txt` |
| macOS | `$XDG_CONFIG_HOME/…` when set, else `~/Library/Application Support/sops/age/keys.txt` |
| Windows | `%AppData%\sops\age\keys.txt` |

Two colleagues on identical Macs can therefore keep this file in different places.
`av sops import` checks every location and reports what it found. The lookup belongs in
`internal/config/paths.go` with the other platform paths.

Packaging ships `age-plugin-av` beside `av` and `avd` in one directory, which Homebrew
already puts on `PATH`. age discovers plugins by filename, so the binary must be named
exactly `age-plugin-av` (`age-plugin-av.exe` on Windows).

## Testing

**Spike first.** The design rests on one claim read out of source but not yet observed:
the plugin unwraps a standard `X25519` stanza. Encrypt a file with stock `sops` to a
stock `age1…` recipient, decrypt it through the plugin, confirm. A failure here breaks
Flux compatibility and invalidates the design, so it must run before anything else is
written.

Automated coverage:

- Plugin round-trip against a real age client.
- `AGE-PLUGIN-AV-1…` encode/decode.
- `keys.txt` discovery on three platforms, driven by `HOME` and `XDG_CONFIG_HOME`.
- The `av sops rm` guard.
- A locked vault under `AV_NO_PROMPT=1` returns a readable error rather than hanging.

Out of reach of automation, as with Touch ID today: real `sops`, `helm secrets`, and
`kustomize` + ksops. Covered by `scripts/smoke-sops.sh`, alongside the existing
`scripts/smoke-backends.sh`.

## Phase 2 — the `av://sops/…` reader backend

A read-only backend resolving `av://sops/<file>#<dotted.key>` lets `av run` and `av env`
inject individual values out of an encrypted file, masked at the source. It improves on
`sops exec-env`, which dumps an entire file into `environ` unmasked.

Implementation shells out to `sops -d`, exactly as the `1p` and `bw` backends shell out to
`op read` and `bw get`. Same pattern, no new dependency. That `sops` decrypts through the
phase-1 plugin, so the key still never materializes.

**Hazard to design around:** this is re-entrant. `avd` spawns `sops`, which calls back
into `avd` for `sops_unwrap`. A handler holding a lock while waiting on the subprocess
deadlocks the daemon. Constraint: hold no lock across the `exec`.

## Work order

1. Spike — prove the standard-stanza unwrap.
2. Identity storage and the `av sops` commands.
3. The `sops_unwrap` RPC in `avd`.
4. The `age-plugin-av` binary.
5. Packaging, cross-build, and docs.
6. Phase 2 — the `av://sops/…` backend.

## Open risks

- **Windows plugin discovery.** The Task 1 spike now builds its test plugin with a `.exe`
  suffix, so it exercises age's plugin lookup when run on Windows. No CI job executes tests
  on Windows (`make cross-test` only compiles), so the risk stands until someone runs
  `go test ./internal/sopsplugin/` there.
- **SOPS version floor.** Plugin support landed in 3.10. `av sops import` should detect an
  older `sops` and say so rather than let decryption fail obscurely.
- **`sops updatekeys` through the plugin.** It decrypts and re-encrypts, so it should work
  unchanged, but confirm it in the smoke script.
