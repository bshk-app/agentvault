# AgentVault

An agent-agnostic secret broker for macOS. AI coding agents run real commands with
real credentials, but never see those credentials in plaintext: the value is injected
into a child process and masked at the source, so anything the agent reads back —
stdout, logs, errors — shows `{{AV:NAME}}` instead of the secret. macOS-only (v1).

## How it works

A resident daemon, `avd`, brokers secrets and redacts output; a thin `av` CLI talks to
it over a local socket. `av run` resolves a profile's secrets, launches your command
with them in its environment, and masks the values in the child's output at the source —
the agent driving `av run` only ever sees `{{AV:NAME}}`. Brokering is gated by a
Touch-ID-unlocked session; the vault's age key is protected at rest by the best tier the
binary can provide (see [Identity protection tiers](#identity-protection-tiers)) and
unwrapped only into that session, never held at rest.

## Documentation

This README is the one-page overview and reference. For step-by-step guides see
[`docs/`](docs/):

- [Getting started](docs/getting-started.md) — install → daemon → first secret → `av run`
- [Agent integration](docs/agent-integration.md) — wire AgentVault into Claude Code / any agent
- [Security model](docs/security-model.md) — threat model, guarantees, identity tiers
- [Troubleshooting](docs/troubleshooting.md) — Touch ID, locked vault, version skew, exit codes

## Install

```sh
brew install beshkenadze/tap/agentvault
# newer Homebrew gates third-party taps:
brew tap beshkenadze/tap && brew trust beshkenadze/tap
```

Requires macOS and the Xcode Command Line Tools (the Touch ID path is built with cgo).

`brew install` builds from source (an ad-hoc-signed binary), so the age key is protected
by the **login keychain** — see [Identity protection tiers](#identity-protection-tiers).
The strongest tier, the Secure Enclave, needs a signed binary and will arrive via a
future signed Cask (`brew install --cask …`, planned).

## Quick start

```sh
brew install beshkenadze/tap/agentvault
brew services start agentvault          # run avd as a per-user LaunchAgent
av setup                                # provision the local age vault (auto-picks the key tier)
av add GITHUB_TOKEN                     # hidden prompt; the value never touches argv
```

No explicit `av unlock` is needed: the first operation that needs the key (here `av
add`) prompts Touch ID on demand and opens the session for ~15 minutes. `av unlock`
stays available to warm the session up front, but it is optional.

`av add` reads the value from a hidden prompt (or piped stdin) — never from the command
line — so the secret stays out of your shell history and the process table.

Describe a profile in `agentvault.yaml` in your project:

```yaml
profiles:
  smoke:
    GITHUB_TOKEN:
      ref: av://file/GITHUB_TOKEN
      tier: normal
```

Then run a command that needs it:

```sh
av run --profile smoke -- sh -c 'echo $GITHUB_TOKEN'
# -> {{AV:GITHUB_TOKEN}}
```

The command really receives the token in its environment; the value is masked in the
output at the source, so the agent reading this line sees only `{{AV:GITHUB_TOKEN}}`.

## Identity protection tiers

The local age vault is encrypted to an age identity. How that identity is protected at
rest depends on what the running binary can do — `av setup` auto-picks the strongest
available, never silently downgrading to plaintext:

| Tier          | At rest                                  | Where                                  |
|---------------|------------------------------------------|----------------------------------------|
| **Secure Enclave** | age key wrapped by a non-exportable Enclave key (`identity.enc`); never leaves hardware | a future signed Cask (`brew install --cask …`, planned) |
| **keychain**  | age key in the login keychain (OS-encrypted at rest) | the build-from-source `brew install` (default there) |
| **plaintext** | age key unwrapped in `identity.txt` (0600) | only via `av setup --plaintext` (explicit) |

`av setup` selection:

- **auto** (default): try the Secure Enclave; on any failure (e.g. an unsigned binary)
  fall back to the **keychain** with a loud warning. Plaintext is **never** chosen
  automatically.
- `--keychain` / `--enclave`: force a tier.
- `--require-enclave`: force the Enclave and **error** instead of downgrading (for a
  signed deployment that must not fall back).
- `--plaintext`: force the plaintext tier (the explicit escape hatch).

The plain `brew install` builds from source as an ad-hoc-signed binary, which the
Secure Enclave refuses (it requires an Apple Team-ID entitlement that only a signed
build carries). That is by design — **keychain is the default and correct tier there**,
and it needs no entitlement. The Secure Enclave tier becomes available once a signed
Cask build runs the same code; the tier is chosen at runtime by what the binary can do.

Run `av version` to see which tier is active.

## Auto-unlock

The age key is only ever held in an unlocked, mlock'd session — zeroized on `lock`, TTL
expiry, or auto-lock (screen-lock / sleep). The first operation that needs the key
(`av add`, `av rm`, `av read`, `av run`) on a locked session prompts Touch ID on demand,
opens the session for ~15 minutes, and proceeds. `av unlock` is therefore optional — it
just warms the session ahead of time.

**Agents opt out.** The hook generated by `av init --agent …` exports `AV_NO_PROMPT=1`.
With that set, `av` does not trigger a biometric prompt for a locked vault: the operation
returns a clean **exit 69** ("vault locked — ask a human to unlock") instead of blocking
on Touch ID. So an agent pauses cleanly for a human rather than stalling on a prompt it
cannot satisfy.

## Backends

A reference is `av://<backend>/<locator>`.

| Backend    | Ref                              | Access     | Populate with                                  |
|------------|----------------------------------|------------|------------------------------------------------|
| age file   | `av://file/NAME`                 | read/write | `av setup` then `av add NAME` (`av rm` to drop) |
| Keychain   | `av://keychain/<service>/<account>` | read-only | `security add-generic-password -s <service> -a <account> -w` |
| 1Password  | `av://1p/<Vault>/<Item>/<field>` | read-only  | manage the item in 1Password (`op`); resolves via `op read` |

The age file backend is the only writable one — `av setup` provisions it and `av add` /
`av rm` manage it. Keychain and 1Password are read-only: AgentVault resolves them but
you populate and rotate them with their own tools.

## Manifest (`agentvault.yaml`)

A manifest maps logical environment names to a backend reference and an access tier,
grouped into profiles. It holds no secret values.

```yaml
profiles:
  smoke:
    GITHUB_TOKEN:
      ref: av://file/GITHUB_TOKEN
      tier: normal
    STRIPE_SECRET:
      ref: av://file/STRIPE_SECRET
      tier: dangerous
```

- **normal** — served from the unlocked session for its TTL (one Touch ID covers the
  window).
- **dangerous** — a fresh Touch ID per access; the value is never cached in the session.

## CLI

```
av ping                                 reach the daemon (prints pong)
av run [--profile P] -- cmd args...     run cmd with secrets injected, output masked
av env [--env-file PATH] [--profile P] [--no-mask] -- cmd args...   run cmd with .env av:// refs resolved + injected (output masked)
av read [--backend file|--profile P] NAME   print one secret to a TTY only (default: av://file/NAME, no manifest)
av add [--backend file] NAME            store a value (hidden prompt or stdin; never argv)
av rm  [--backend file] NAME            delete a value from the writable vault
av setup [--rotate] [--keychain|--enclave|--require-enclave|--plaintext]   provision the local age vault (auto-picks the tier)
av init --agent claude-code|generic [--dir D] [--force]   generate adapter files
av unlock                               Touch ID — open the session (optional; ops auto-unlock)
av lock                                 re-lock and clear issued values
av status                               print lock state and remaining time
av scrub                                filter stdin -> stdout through the redactor
av version                              print av/avd versions, active key tier, socket
```

`av read` refuses when stdout is not a terminal (exit **80**) so a piped secret cannot
leak — agents must use `av run`. By default `av read NAME` reads `av://file/NAME`
directly from the writable vault (symmetric with `av add`/`av rm`, no `agentvault.yaml`
needed); `--backend` picks another backend and `--profile P` resolves through the
manifest instead (the two modes are mutually exclusive). Daemon errors map to stable,
secret-free exit codes: **69** (vault locked), **77** (access denied, dangerous tier),
**2** (bad request, e.g. unknown profile). `av run`'s `--profile` defaults to `smoke`.

`av env` brings the same brokering to an existing `.env`-based app. A `.env` value that
is an `av://` reference is resolved at runtime and injected into the child; literals like
`MSSQL_PORT=1433` pass through unchanged. The `.env` refs merge with the `--profile`
`agentvault.yaml` profile — a name defined in both is a hard error, not a guess at
precedence. One Touch ID covers all normal-tier secrets (a single resolve), the output is
masked by default (`--no-mask` disables layer-1 source masking), and it is fail-closed: if
any reference can't resolve, or neither a `.env` nor an `agentvault.yaml` source exists, no
child is started. Secrets are never written to disk — the `.env` holds only references.

`av setup` provisions the local age vault and **auto-picks the strongest key tier the
binary can provide** (see [Identity protection tiers](#identity-protection-tiers)):
keychain on the build-from-source `brew install`, Secure Enclave on a future signed
build. `--plaintext` writes the identity unwrapped to `identity.txt` (an explicit escape
hatch — never chosen automatically); `--rotate` provisions a fresh identity and vault.

`av version` prints `av`'s version and, when the daemon is reachable, `avd`'s version,
the active key tier, and the socket path. It never hard-fails: with no daemon running it
prints the `av` version and notes `avd (not running)`.

**Self-healing after an upgrade.** After `brew upgrade`, the already-running `avd` keeps
serving the old code until it is restarted. `av` handles this automatically: on the next
command, if it sees a version skew (both release builds), it shuts the stale daemon down,
lets the new binary take over, and retries — no manual `brew services restart` needed.
Agents (`AV_NO_PROMPT=1`) never restart the daemon; they get a clear "avd outdated — ask
a human" error and pause instead.

## Security model

- **Broker, not store.** The agent never holds the secret: `av run` injects it into a
  child and `av read` prints only to a real terminal (refusing a pipe).
- **Source masking.** `av run` masks resolved values in the child's output at the
  source — the value is replaced before the agent can read it back.
- **Defense-in-depth redaction.** `av scrub` runs a second pass: exact-match of the
  session's issued values plus a gitleaks detector for *derived* secrets the daemon
  never issued.
- **Tiered key protection, session-scoped.** The vault's age identity is protected at
  rest by the strongest tier the binary can provide — Secure Enclave (signed build),
  else the login keychain (build-from-source default), with an explicit plaintext escape
  hatch (see [Identity protection tiers](#identity-protection-tiers)). Every tier gates
  the key behind Touch ID and holds it only in an `mlock`'d session, zeroized on `lock`,
  TTL expiry, or auto-lock (screen-lock / sleep). The daemon does not unwrap at startup,
  so there is no login-time prompt. The Enclave is the strongest tier — the key never
  leaves hardware and a daemon compromise after lock cannot decrypt — but it requires a
  signed build; the keychain tier still gates the key behind a presence check and the
  session window.
- **Local trust boundary.** `av` ↔ `avd` is a `0600` unix-domain socket with a
  peer-credential check (same-UID only).
- **Honest scope.** This is a *cooperative-agent* threat model: it stops an agent (and
  its logs) from capturing plaintext it has no business seeing. It is macOS-only (v1)
  and does **not** defend against an actively malicious same-user local attacker —
  malicious-agent defense is an explicit non-goal for v1.

## Agent integration

`av init --agent claude-code|generic` generates the adapter files (a hook that pipes
agent output through `av scrub`, plus a skill/doc) into your project so the agent's
output is redacted automatically. See the [agent integration guide](docs/agent-integration.md)
for the wiring, the two-layer model, and the scrub-coverage contract.

## Verification & development

The Touch ID, Secure Enclave, and real-backend paths cannot be exercised by automated
tests — verify them manually:

- `scripts/smoke-e2e.sh` — isolated end-to-end of the age-file backend (stub presence,
  ephemeral daemon and vault; no Touch ID).
- `scripts/smoke-backends.sh` — real Keychain (and optional 1Password) resolution.
- `scripts/manual-touchid-smoke.sh` — the human-in-the-loop Touch ID / auto-lock check.
- `docs/launchagent.md` — running `avd` as a per-user LaunchAgent (when not using
  `brew services`).

Build and test from source with `make build` and `make test`.

> The `AV_TEST_AUTH`, `AV_TEST_ENCLAVE`, and `AV_TEST_KEYSTORE` environment variables
> select stub presence / stub enclave / stub keystore for CI and the smoke scripts. They
> are **test-only** and bypass the hardware/keychain protections — never set them in real
> use.

## Status / non-goals

macOS-only in v1. Linux/Windows support and additional backends (HashiCorp Vault, AWS
Secrets Manager) are future work. Keychain and 1Password stay read-only — manage those
secrets with their own tools.
