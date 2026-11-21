---
name: agentvault
description: Use secrets safely via AgentVault. Run commands that need credentials with `av run` so the values never enter your context; treat {{AV:NAME}} as an opaque reference.
---

# AgentVault — using secrets you never see

AgentVault keeps real secret values out of your context. You work with **logical
names** only; the daemon (`avd`) holds the values and injects them into subprocesses
on your behalf. Follow these rules.

## Quick reference (exact syntax — don't guess)

- **Addressing:** every secret is an `av://<backend>/<locator>` reference. The backend
  ids are exactly `file`, `1p`, `bw`, `keychain` — see below. Never `op://`.
- **Find the PROFILE and logical NAMEs in `agentvault.yaml`** (read it). Never invent a
  profile/name; `av run` has no safe default profile — always pass `--profile`.
- **Run a command that needs secrets:**
  `av run --profile <PROFILE> -- <command> [args...]`
- **A tool that reads a CONFIG FILE** (`.npmrc`, `.env`, etc.): do NOT write the value to
  disk. Put an environment *reference* in the file and run the tool under `av run`, so the
  value is resolved at runtime and never persisted. Example:
  `printf '//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n' > .npmrc`
  then `av run --profile <PROFILE> -- npm whoami`.
- `av read [--profile <PROFILE>] <NAME>` — **human-only** (refuses a pipe/file). Don't use
  it to fetch a value; use `av run`. If a human needs the value, they run it themselves.
- `av status` (lock state) · `av version` (av/avd).
- **Request access yourself:** run `av unlock` to open the native approval prompt
  (biometrics when available); the user approves it.

## Addressing secrets: `av://<backend>/<locator>`

Every secret is addressed by an **`av://`** reference. There are exactly four backend
ids — any other name fails with `no backend registered for "<id>"`:

| backend id | reference shape | writable | populated with |
| --- | --- | --- | --- |
| `file` | `av://file/<NAME>` | yes — `av add` / `av rm` | AgentVault's own age vault (`av setup`) |
| `1p` | `av://1p/<Vault>/<Item>/<field>` | no | the 1Password app / `op` CLI |
| `bw` | `av://bw/<object>/<id-or-search>` | no | the Bitwarden `bw` CLI |
| `keychain` | `av://keychain/<service>/<account>` | no | macOS Keychain (`security`) |

1Password's id is **`1p`** — never `op`, `1password`, or `onepassword`. `op://…` is
1Password's OWN scheme; AgentVault builds it internally when it shells out to `op read`.
It MUST NOT appear in `agentvault.yaml`, in a `.env`, or in any `av` command — write
`av://1p/Vault/Item/field` instead.

Only the FIRST segment after `av://` is the backend id; the locator after it may contain
slashes and spaces, so `av://1p/Eng/GitHub CI/token` is one valid reference.

Backends are resolved by the DAEMON: `avd` links them and the thin `av` client
deliberately does not. Inspecting the `av` binary therefore proves nothing about which
backends exist — ask the daemon (`av read --backend 1p <Vault>/<Item>/<field>`) and read
the failure literally: `no backend registered for "op"` means the id was wrong, not that
1Password is unsupported.

Only `file` is writable. `av add` / `av rm` against `1p`, `bw`, or `keychain` fail by
design — populate and rotate those with their own tools.

## `agentvault.yaml` is written by a human, never generated

`av init` generates the hook script, the hooks snippet, and this skill. It does **not**
create `agentvault.yaml`. A missing manifest means nobody has written one yet — it is not
a sign that profiles are unsupported. It lives at the repo root:

```yaml
profiles:
  ci:                              # profile name -> av run --profile ci
    GITHUB_TOKEN:                  # logical env name the child process sees
      ref: av://file/GITHUB_TOKEN
      tier: normal
    DEPLOY_KEY:
      ref: av://1p/Eng/Deploy/private key
      tier: dangerous
```

`ref` and `tier` are both REQUIRED on every entry, and `tier` is exactly `normal` or
`dangerous` — a missing or misspelled tier is a load error, not a default.

## `av env` — the `.env` entry point

A project that already keeps a `.env` needs no profile: replace each secret VALUE with an
`av://` reference in place.

```
GITHUB_TOKEN=av://file/GITHUB_TOKEN
NPM_TOKEN=av://1p/Eng/npm/token
LOG_LEVEL=debug
```

`av env -- <command>` resolves every `av://` value (normal tier), passes non-reference
lines through literally, and masks the child's output exactly like `av run`. It also
merges the `agentvault.yaml` profile named by `--profile` (default `smoke`) when that file
exists; a name defined in BOTH sources is a hard error, not a silent precedence.

## 1. Run commands with `av run` — never read the secret yourself

To run a command that needs credentials, wrap it:

```
av run --profile <PROFILE> -- <command> [args...]
```

`av run` resolves the profile's secrets, injects them into the command's
environment, runs it, and **masks the command's own stdout/stderr at the source**
before any byte reaches you (layer 1). You get the command's output with secrets
already replaced by `{{AV:NAME}}`.

Do NOT try to print or capture a secret value (e.g. `env`, `cat .env`, `echo
$TOKEN`). Even if you do, `av run` masks it. Resolve credentials only through
`av run`.

## 2. Treat `{{AV:NAME}}` as opaque — never try to recover the value

When you see `{{AV:NAME}}` (or `{{AV:REDACTED:<rule>}}`) in any output, that is a
**redacted secret**. It is a reference, not a value:

- You MAY refer to the secret by its name (`{{AV:GITHUB_TOKEN}}`) in your reasoning.
- You MUST NOT attempt to un-redact, reconstruct, decode, brute-force, or otherwise
  recover the underlying value. The value is intentionally withheld from you.
- Do not ask the user to paste the value so you can see it.

## 3. Pipe tool output through `av scrub` (layer 2)

The generated hook (`.claude/hooks/av-scrub.sh`) pipes context-ingress text through
`av scrub`, which asks the daemon to redact session values and gitleaks-detected
secrets. This is the independent second layer that catches secrets `av run` did not
issue (e.g. a token a subprocess derived, or a value pasted into a file you read).
This PostToolUse hook is a **redaction hook, not a blocking/validation hook**. Switching
from `op://` to `av://` does not remove the need to wire it: `av run` protects child
output at layer 1, while this hook protects other context-ingress channels at layer 2.

## 4. `av read` is for a human at a TTY only

`av read NAME` prints a single value, but **refuses unless stdout is a real
terminal**. It will not print to a pipe or a file. Do not call `av read` to capture
a value — it is the deliberate guard against an agent reading a secret directly. If
you need a credential for a command, use `av run`.

## 5. Request access yourself when the vault is locked (`AV_NO_PROMPT`)

The generated hook exports `AV_NO_PROMPT=1`, so a locked vault makes secret
operations exit **69** (`EX_UNAVAILABLE`) without prompting automatically.

When `av status` reports `locked`, or an operation fails because the vault is locked,
tell the user you are requesting access, then **run `av unlock` yourself**. Do not ask
the user to type the command. It requests native user-presence approval, using
biometrics (such as Touch ID) when available or the platform's configured
authentication method. The user completes the system prompt; the agent only starts it.
Explicit `av unlock` still requests approval with `AV_NO_PROMPT=1`; keep that setting
for ordinary secret operations.

Wait for `av unlock` to succeed, then retry the original operation. If approval is
canceled, denied, or times out, or authentication is unavailable, stop the dependent
operation and report the result. Never bypass authentication or repeat prompts in a loop.

---

## Scrub-coverage contract (for whoever wires the hooks)

Layer 2's promise holds only if **every channel that carries external text into the
agent's context is intercepted** by the scrub hook. The contract is not "hook
stdout" — it is "enumerate every ingress channel and intercept each." A channel left
unhooked is a hole.

Channels that MUST be hooked:

- **Bash** / shell tool output (stdout and stderr)
- **file read** tool output (file contents shown to the model)
- **MCP** tool output (results from every MCP server's tools)
- web fetch / web search results
- any future tool whose result is shown to the model

See `.claude/agentvault.hooks.json` for the PostToolUse wiring template (merge it
into your Claude Code settings and adjust to your version). Layer 1 (`av run`
source-masking) and layer 2 (this scrub hook) are independent: failure of either one
alone does not leak a secret.
