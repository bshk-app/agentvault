# AgentVault

An agent-agnostic secret broker for macOS, Linux, and Windows. AI coding agents run real commands with
real credentials, but never see those credentials in plaintext: the value is injected
into a child process and masked at the source, so anything the agent reads back —
stdout, logs, errors — shows `{{AV:NAME}}` instead of the secret.

## How it works

A resident daemon, `avd`, brokers secrets and redacts output; a thin `av` CLI talks to
it over a private local OS endpoint (Unix socket on macOS/Linux, named pipe on Windows).
`av run` resolves a profile's secrets, launches your command with them in its environment,
and masks the values in the child's output at the source — the agent driving `av run`
only ever sees `{{AV:NAME}}`. Brokering is gated by a native-presence-unlocked session;
the vault's age key is protected at rest by the best tier the binary can provide (see
[Identity protection tiers](#identity-protection-tiers)) and unwrapped only into that
session, never held at rest.

## Documentation

This README is the one-page overview and reference. For step-by-step guides see
[`docs/`](docs/):

- [Getting started](docs/getting-started.md) — install → daemon → first secret → `av run`
- [Agent integration](docs/agent-integration.md) — wire AgentVault into Claude Code / any agent
- [SOPS](docs/sops.md) — broker your SOPS age key: import, `.sops.yaml`, rotation, troubleshooting
- [Security model](docs/security-model.md) — threat model, guarantees, identity tiers
- [Platform support](docs/platforms.md) — Linux/Windows prerequisites and current gaps
- [Troubleshooting](docs/troubleshooting.md) — native prompts, locked vault, version skew, exit codes

## Install

macOS:

```sh
brew install beshkenadze/tap/agentvault
# newer Homebrew gates third-party taps:
brew tap beshkenadze/tap && brew trust beshkenadze/tap
```

`brew install` builds from source (an ad-hoc-signed binary), so the age key is protected
by the **OS keychain/keyring tier** — see [Identity protection tiers](#identity-protection-tiers).
The strongest tier, the Secure Enclave, needs a signed binary and will arrive via a
future signed Cask (`brew install --cask …`, planned).

**Linux** builds from source today. **Windows does not yet run**: `avd` refuses to start
without a real presence check, and the Windows Hello bridge is unimplemented, so the
daemon only comes up under the test stub. Windows compiles and its test suite passes in
CI — the transport, the plugin, and the SOPS path all work — but it is not a usable
install. See [platform support](docs/platforms.md).

## Quick start

```sh
brew install beshkenadze/tap/agentvault
av setup                                # provision the vault + register avd to start at login
av add GITHUB_TOKEN                     # hidden prompt; the value never touches argv
```

`av setup` also registers `avd` to start at login via the native per-user service manager:
macOS Login Items/LaunchAgent, Linux `systemd --user`, or Windows Task Scheduler. Manage
it with `av service on|off|status`.

No explicit `av unlock` is needed: the first operation that needs the key (here `av
add`) prompts for native presence on demand and opens the session for ~15 minutes. `av unlock`
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
| **Secure Enclave** | age key wrapped by a non-exportable Enclave key (`identity.enc`); never leaves hardware | macOS signed Cask (planned) |
| **keychain**  | age key in OS secure storage: macOS login Keychain, Linux Secret Service, Windows Credential Manager | default when Enclave is unavailable |
| **plaintext** | age key unwrapped in `identity.txt` (0600) | only via `av setup --plaintext` (explicit) |

`av setup` selection:

- **auto** (default): try the Secure Enclave where available; otherwise fall back to the
  **keychain** OS secure-storage tier. Plaintext is **never** chosen automatically.
- `--keychain`: force the OS keychain/keyring tier.
- `--enclave`: force the macOS Secure Enclave tier; unsupported on Linux/Windows.
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
(`av add`, `av rm`, `av read`, `av run`) on a locked session prompts native presence on demand,
opens the session for ~15 minutes, and proceeds. `av unlock` is therefore optional — it
just warms the session ahead of time.

**Agents opt out.** The hook generated by `av init --agent …` exports `AV_NO_PROMPT=1`.
With that set, `av` does not trigger a native-presence prompt for a locked vault: the operation
returns a clean **exit 69** ("vault locked — ask a human to unlock") instead of blocking
on a prompt. So an agent pauses cleanly for a human rather than stalling on a prompt it
cannot satisfy.

## Backends

A reference is `av://<backend>/<locator>`.

| Backend    | Ref                              | Access     | Populate with                                  |
|------------|----------------------------------|------------|------------------------------------------------|
| age file   | `av://file/NAME`                 | read/write | `av setup` then `av add NAME` (`av rm` to drop) |
| Keychain   | `av://keychain/<service>/<account>` | read-only | `security add-generic-password -s <service> -a <account> -w` |
| 1Password  | `av://1p/<Vault>/<Item>/<field>` | read-only  | manage the item in 1Password (`op`); resolves via `op read` |
| Bitwarden  | `av://bw/<object>/<id-or-search>` | read-only | manage the item in Bitwarden (`bw`); resolves via `bw get` |

The age file backend is the only writable one — `av setup` provisions it and `av add` /
`av rm` manage it. Keychain, 1Password, and Bitwarden are read-only: AgentVault resolves
them but you populate and rotate them with their own tools.

Bitwarden uses the Password Manager CLI, not the Secrets Manager CLI. Supported
`<object>` values are `password`, `username`, `uri`, `totp`, and `notes`; full `item`
JSON is intentionally not exposed as a secret value. For a self-hosted Bitwarden server,
configure and unlock `bw` first, then run `avd` in an environment where that CLI state is
available:

```sh
bw config server https://your.bw.domain.com
bw login
export BW_SESSION="$(bw unlock --raw)"
```

If your self-hosted server uses a self-signed TLS certificate, set `NODE_EXTRA_CA_CERTS`
for the `bw` process. AgentVault does not store or refresh `BW_SESSION`; it only invokes
the already configured `bw` CLI.

## SOPS

`age-plugin-av` brokers your SOPS age key the way `av run` brokers an environment variable.
The key moves into the vault, `keys.txt` keeps an `AGE-PLUGIN-AV-1…` **pointer**, and `sops`
asks `avd` to unwrap each file — so the key is never plaintext on disk, never in `environ`,
and never in the memory of `sops`, `helm`, or `kustomize`.

Files keep their ordinary `age1…` recipients and `.sops.yaml` is untouched, so teammates,
CI, and Flux read the same files with the same keys.

```sh
av sops import                   # move keys.txt into the vault, leaving a pointer
av sops keygen work              # or start fresh: a key that never touches disk
av sops ls                       # what the vault holds: name, tier, recipient
sops -d secrets.enc.yaml         # unchanged — one presence check per command, not per file
```

`import` rewrites `keys.txt` for you; `keygen` prints the two lines to place — the `age1…`
recipient for `.sops.yaml` and the pointer for `keys.txt`.

Requires **sops 3.10+** (where age plugin support landed) and `age-plugin-av` on `PATH`
beside `av` — the Cask installs it. A `dangerous`-tier identity costs a fresh presence
check per file; `normal` (the default) costs one per command. `av sops ls` is also the
recovery when `sops` reports `no identity matched any of the recipients`.

CI proves the plugin itself: Go tests spawn a real `avd`, have age exec the real
`age-plugin-av`, and decrypt a standard `age1` file and a mixed multi-key `keys.txt` through
it. That is the production path **minus the `sops` binary**. Running `sops`, `helm secrets`
or `kustomize`+ksops against the plugin is *expected* to work — `sops` reaches it through the
same age plugin protocol, and the other two are ordinary `sops` callers — but no automated
run in this repository proves it. **`helm secrets` needs helm-secrets 4.7.7+ under helm 4** —
older releases load as a *getter* and expose no `secrets` subcommand. See the
[SOPS guide](docs/sops.md) for the walkthrough, the rotation flow, troubleshooting, what to
check by hand, and what brokering the key does *not* protect.

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

- **normal** — served from the unlocked session for its TTL (one native-presence check covers the
  window).
- **dangerous** — a fresh native-presence check per access; the value is never cached in the session.

## CLI

```
av ping                                 reach the daemon (prints pong)
av run [--profile P] -- cmd args...     run cmd with secrets injected, output masked
av env [--env-file PATH] [--profile P] [--no-mask] -- cmd args...   run cmd with .env av:// refs resolved + injected (output masked)
av read [--backend file|--profile P] NAME   print one secret to a TTY only (default: av://file/NAME, no manifest)
av add [--backend file] NAME            store a value (hidden prompt or stdin; never argv)
av rm  [--backend file] NAME            delete a value from the writable vault
av sops keygen NAME [--tier normal|dangerous]   generate a SOPS identity inside the vault
av sops import [--from PATH] [--name NAME]      move existing age keys out of keys.txt into the vault
av sops ls                              stored SOPS identities: name, tier, recipient
av sops recipient NAME | av sops identity NAME  the age1… for .sops.yaml / the pointer for keys.txt
av sops rm NAME [--force]               DESTRUCTIVE: files encrypted to it become unreadable
av setup [--rotate] [--keychain|--enclave|--require-enclave|--plaintext]   provision the vault + register avd at login
av service on|off|status                start avd at login via the native per-user service manager
av init --agent claude-code|generic [--dir D] [--force]   generate adapter files
av unlock                               native presence — open the session (optional; ops auto-unlock)
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
precedence. One native-presence check covers all normal-tier secrets (a single resolve), the output is
masked by default (`--no-mask` disables layer-1 source masking), and it is fail-closed: if
any reference can't resolve, or neither a `.env` nor an `agentvault.yaml` source exists, no
child is started. Secrets are never written to disk — the `.env` holds only references.

`av setup` provisions the local age vault and **auto-picks the strongest key tier the
binary can provide** (see [Identity protection tiers](#identity-protection-tiers)):
OS keychain/keyring by default, Secure Enclave on eligible macOS signed builds.
`--plaintext` writes the identity unwrapped to `identity.txt` (an explicit escape
hatch — never chosen automatically); `--rotate` provisions a fresh identity and vault.

`av version` prints `av`'s version and, when the daemon is reachable, `avd`'s version,
the active key tier, and the socket path. It never hard-fails: with no daemon running it
prints the `av` version and notes `avd (not running)`.

**Self-healing after an upgrade.** After `brew upgrade`, the already-running `avd` keeps
serving the old code until it is restarted. `av` handles this automatically: on the next
command, if it sees a version skew (both release builds), it shuts the stale daemon down,
lets the new binary take over, and retries — no manual restart needed.
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
  rest by the strongest tier the binary can provide — Secure Enclave on eligible macOS
  builds, else OS secure storage, with an explicit plaintext escape hatch (see
  [Identity protection tiers](#identity-protection-tiers)). Production tiers gate the key
  behind native presence where implemented and hold it only in an `mlock`'d session,
  zeroized on `lock`, TTL expiry, or auto-lock (screen-lock / sleep). The daemon does not
  unwrap at startup, so there is no login-time prompt.
- **Local trust boundary.** `av` ↔ `avd` is a private local endpoint: `0600`
  unix-domain socket with peer-credential checks on macOS/Linux, or a current-user named
  pipe ACL on Windows.
- **Honest scope.** This is a *cooperative-agent* threat model: it stops an agent (and
  its logs) from capturing plaintext it has no business seeing. It does **not** defend
  against an actively malicious same-user local attacker —
  malicious-agent defense is an explicit non-goal for v1.

## Agent integration

`av init --agent claude-code|generic` generates the adapter files (a hook that pipes
agent output through `av scrub`, plus a skill/doc) into your project so the agent's
output is redacted automatically. See the [agent integration guide](docs/agent-integration.md)
for the wiring, the two-layer model, and the scrub-coverage contract.

## Verification & development

Build and test from source with `make build`, `make test` (`go test ./...`), `make vet`, and
`make cross-test` (compiles the suite for linux/amd64 and windows/amd64 without running it).

CI runs `make test`, `make vet` and `make cross-test` on Linux and `go test ./...` on
Windows for every push and pull request; both are green. There is no macOS job — Touch ID
and the Secure Enclave are unreachable on a hosted runner, which is exactly where the
macOS-only risk lives.

Some paths cannot be exercised by automated tests, and the smoke harness that used to drive
them by hand is **no longer part of this repository**. Verify these on your own machine:

- **Touch ID, the Secure Enclave, and auto-lock** — the human-in-the-loop check: `av unlock`
  should prompt, cancelling should deny, locking the screen should return `av status` to
  locked.
- **Real Keychain and 1Password resolution** — no stub keystore.
- **The real `sops` / `helm secrets` / `kustomize`+ksops toolchain** against
  `age-plugin-av`. See
  [Verifying on your own machine](docs/sops.md#verifying-on-your-own-machine) for what to run
  and what CI does and does not prove.
- `docs/launchagent.md` — running `avd` at login and the `av service` login-item
  verification checklist.

> The `AV_TEST_AUTH`, `AV_TEST_ENCLAVE`, and `AV_TEST_KEYSTORE` environment variables
> select stub presence / stub enclave / stub keystore for CI and the test suite. They
> are **test-only** and bypass the hardware/keychain protections — never set them in real
> use.

## Status / non-goals

Linux support is source-build/desktop-prerequisite level.

**Windows is not usable yet**, and the gap is larger than "missing parity":

- **`avd` will not start.** `selectPresence` treats a missing presence provider as fatal —
  deliberately, so the daemon never brokers a secret without a real check — and the
  Windows Hello bridge is unimplemented. The daemon comes up only under `AV_TEST_AUTH`,
  which is test-only and bypasses the protection it stands for.
- **Owner-only files have no expression.** `0600` needs an explicit NTFS ACL, which Go's
  `os` package cannot set, so the vault and identity files are not restricted to their
  owner the way they are on Unix. That is a real gap for a secret store, not a formality.
- Auto-lock on screen-lock/sleep also needs a native bridge.

What Windows *does* have, proven by CI on every push: the named-pipe transport,
`age-plugin-av` discovery, `AV_SOCKET_PATH`, and the SOPS decrypt path.

Additional backends (HashiCorp Vault, AWS Secrets Manager) are future work. Keychain,
1Password, and Bitwarden stay read-only — manage those secrets with their own tools.
