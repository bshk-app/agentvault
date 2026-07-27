# Security model

This document states precisely what AgentVault protects against, what it does not, and
how the vault key is protected at rest. Read it before you trust it with a real secret.

## Threat model: cooperative agent

AgentVault defends a **cooperative-agent** boundary. The goal is to stop an AI coding
agent — and everything that captures its context (its logs, its transcript, an MCP
server it talks to) — from seeing plaintext credentials it has no business seeing, while
still letting it run the commands that need them.

It does **not** defend against an actively malicious, same-user local attacker. A process running as your user can, in principle, attach to the
daemon's memory while the session is unlocked or wait for you to type. Defending against a
malicious *agent* (as opposed to a cooperative one whose context you want to keep clean)
is an explicit non-goal for v1.

In scope:

- An agent reading back a secret from command output, logs, or errors.
- A secret leaking into the agent's context via file reads, web fetches, or tool output.
- A secret landing in shell history or the process table.
- The vault key sitting in plaintext on disk at rest.

Out of scope (v1):

- A malicious same-user process actively extracting an unlocked session.
- Headless/non-desktop Linux or Windows hosts without a native auth agent.
- Defending against the agent itself being adversarial.

## The guarantees

- **Broker, not store.** The agent never holds the secret. `av run` injects it into a
  child process; `av read` prints only to a real terminal and refuses a pipe.
- **Source masking (layer 1).** `av run` masks resolved values in the child's
  stdout/stderr *at the source* — the value is replaced before the agent can read it back.
- **Defense-in-depth redaction (layer 2).** `av scrub` runs a second, independent pass:
  exact-match of the session's issued values (plus common encodings) and a gitleaks
  detector for *derived* secrets the daemon never issued. See
  [agent integration](agent-integration.md#the-two-layers).
- **Values never reach argv.** `av add` reads the value from a hidden prompt or stdin,
  never from a command-line argument, so it cannot leak via shell history or `ps`.
- **`av read` refuses a pipe.** When stdout is not a terminal, `av read` writes nothing of
  the value and exits **80** — an agent piping it gets nothing.
- **Secret-free errors and exit codes.** Daemon errors map to stable, secret-free exit
  codes (see [the CLI reference](../README.md#cli)); no message ever wraps a value.
- **Local trust boundary.** `av` ↔ `avd` is a private local endpoint: `0600`
  unix-domain socket with peer-credential checks on macOS/Linux, or a current-user named
  pipe ACL on Windows.

## Identity protection tiers

The local age vault is encrypted to an age identity. How that identity is protected at
rest depends on what the running binary can do. `av setup` **auto-picks the strongest
available tier and never silently downgrades to plaintext.**

| Tier | Key at rest | Available on |
|------|-------------|--------------|
| **Secure Enclave** | age key wrapped by a non-exportable Enclave key (`identity.enc`); never leaves hardware | macOS signed Cask (planned) |
| **keychain** | age key in OS secure storage: macOS login Keychain, Linux Secret Service, Windows Credential Manager | default when Enclave is unavailable |
| **plaintext** | age key unwrapped in `identity.txt` (0600) | only via `av setup --plaintext` (explicit opt-out) |

### How `av setup` chooses

- **auto** (default, no flag): try the Secure Enclave where available; otherwise fall
  back to the **keychain** OS secure-storage tier. Plaintext is **never** chosen
  automatically.
- `--keychain`: force the OS secure-storage tier.
- `--enclave`: force the macOS Secure Enclave tier; unsupported on Linux/Windows.
- `--require-enclave`: force the Enclave and **error** instead of downgrading — for a
  signed deployment that must not fall back.
- `--plaintext`: force the plaintext tier (the explicit escape hatch).

Conflicting tier flags are rejected, so your intent is never guessed.

### Why keychain is the default (and correct) on `brew install`

The plain `brew install` builds from source as an **ad-hoc-signed** binary. The Secure
Enclave refuses such a binary: creating a Secure Enclave key requires an Apple Team-ID
entitlement (`com.apple.application-identifier`) that only a properly signed build
carries. That is by design — **keychain is the right tier there**, it needs no
entitlement, and it still gates the key behind Touch ID and the session window.

The Secure Enclave tier becomes available once a signed Cask build runs the same code;
the Enclave-tier logic is already implemented and activates at runtime based on what the
binary can do. Run `av version` to see the active tier.

## Session lifecycle: the key is never at rest unlocked

The daemon does **not** unwrap the key at startup — there is no login-time prompt. The key
is unwrapped only into an unlocked, `mlock`'d session, and that session is **zeroized** on:

- `av lock`,
- session TTL expiry (~15 minutes), and
- auto-lock — screen lock or sleep.

Production tiers gate the key behind native presence before the session opens where
implemented. With the Enclave tier the key never leaves hardware, so a daemon compromise
*after* lock cannot decrypt the vault. With the keychain tier the age identity is stored
by the OS secure store and gated by the session window, but is held in process memory
while unlocked — consistent with the cooperative-agent threat model above.

## What brokering the SOPS key protects

`age-plugin-av` brokers your SOPS age key the way `av run` brokers an environment variable:
the key stays inside `avd`, and `sops` gets back only the **file key** for the one file it
asked about — a per-file value that decrypts that file and nothing else. See
[the SOPS guide](sops.md) for the walkthrough.

Protected:

- **The key is never plaintext on disk.** `keys.txt` holds an `AGE-PLUGIN-AV-1…` pointer,
  which encodes a *recipient*, not a key. Without a running `avd` and a presence check it
  decrypts nothing. Publish it, commit it to dotfiles, paste it in chat.
- **The key is never in `environ`.** No `SOPS_AGE_KEY`, no `SOPS_AGE_KEY_CMD` — so it does
  not reach the whole process tree the way an exported variable does.
- **The key is never in the memory of `sops`, `helm`, or `kustomize`.** The X25519 unwrap
  happens inside `avd`. Those processes hold one file key at a time and never the identity
  that produced it.
- **Use is gated and audited.** Decryption needs an unlocked, presence-gated session on the
  **Secure Enclave** and **keychain** tiers; under `av setup --plaintext` the vault identity
  is unwrapped on disk, so anyone who can read that file recovers the SOPS key with no
  running `avd` and no presence check at all. Each unwrap that reached an identity is logged
  with its name, tier, and outcome — never a value. A `dangerous`-tier identity costs a
  fresh presence check per file.
- **No plaintext copy is deleted silently.** `av sops import` reports the `.bak` it kept and
  says the plaintext key is still in it.

**Not protected — the decrypted output.** Brokering the key says nothing about what happens
to the plaintext once `sops` hands it back:

- **`helm secrets` writes decrypted values into temporary files** on their way to `helm`.
  Those files are outside AgentVault's boundary.
- **`sops -d` prints plaintext to stdout**, which your shell, your pipeline, and your
  scrollback all see. `av run`'s source masking does not cover it — that masks values
  *AgentVault issued*, and a decrypted YAML document is not one.
- **In-cluster decryption is entirely outside AgentVault.** Flux's `kustomize-controller`
  decrypts with its own key from a Kubernetes Secret. AgentVault covers the developer's
  machine only.
- **Encryption never involves AgentVault.** `sops -e` uses only the public recipients from
  `.sops.yaml`; no private key participates, so there is nothing to broker.

The guarantee is about the *key*: it stops your long-lived SOPS identity from sitting in
plaintext where every process can read it, and it caps the blast radius of a compromised
`sops` invocation at the files that invocation decrypted. It is not a guarantee about where
the decrypted bytes go afterward.

The vault's `sops/` namespace is reserved and enforced in the daemon: `av read`, `av add`,
and `av rm` all refuse it, so a SOPS private key cannot be printed by the ordinary secret
commands or overwritten by junk. `av sops` is the only way in or out.

## Access tiers (per secret)

Independently of the key tier, each manifest entry has an **access tier** that controls
how often a presence check is required to *use* it:

- **normal** — served from the unlocked session for its TTL; one native-presence check
  covers the window.
- **dangerous** — a fresh native-presence check per access; the value is never cached in the session.

Use `dangerous` for the credentials whose every use you want to physically confirm.

## Reporting issues

Found a way a secret reaches the agent's context, the logs, an error, the audit trail, or
a non-TTY pipe? That is a security bug. Please report it via the project's issue tracker
with a minimal reproduction (and **never** paste a real secret into the report).
