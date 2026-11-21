# AgentVault — generic agent integration

AgentVault keeps real secret values out of your agent's context. The agent works
with **logical names** only; the daemon (`avd`) holds the values and injects them
into subprocesses. This is the agent-agnostic integration; wire the two generated
pieces into whatever hook system your agent provides.

## The two pieces

1. **`av-scrub.sh`** — a hook script that pipes stdin through `av scrub` (layer-2
   redaction). Run it on every context-ingress channel.
2. **This doc** — the contract the agent must follow.
The hook is a **redaction hook, not a blocking/validation hook**. `av run` protects
child output at layer 1; `av scrub` protects other context-ingress channels at layer 2.

## Quick reference (exact syntax — don't guess)

- **Find the PROFILE and logical NAMEs in `agentvault.yaml`** (read it). Never invent a
  profile/name; always pass `--profile` (there is no safe default).
- **Run a command that needs secrets:** `av run --profile <PROFILE> -- <command> [args...]`
- **A tool that reads a CONFIG FILE** (`.npmrc`, `.env`, …): do NOT write the value to disk.
  Put an environment *reference* in the file and run the tool under `av run` so the value is
  resolved at runtime, never persisted. E.g.
  `printf '//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n' > .npmrc` then
  `av run --profile <PROFILE> -- npm whoami`.
- `av read [--profile <PROFILE>] <NAME>` — human-only (refuses a pipe/file); don't use it to
  fetch a value, use `av run`. If a human needs the value, they run it themselves at a TTY.

## Addressing secrets: `av://<backend>/<locator>`

Use AgentVault references, not 1Password references:

| backend id | reference shape | writable |
| --- | --- | --- |
| `file` | `av://file/<NAME>` | yes — `av add` / `av rm` |
| `1p` | `av://1p/<Vault>/<Item>/<field>` | no — resolves with `op read` |
| `bw` | `av://bw/<object>/<id-or-search>` | no — resolves with `bw get` |
| `keychain` | `av://keychain/<service>/<account>` | no — resolves with macOS `security` |

The 1Password backend id is exactly **`1p`**, never `op`, `1password`, or
`onepassword`. `op://…` is the scheme AgentVault constructs internally for the
1Password CLI; write `av://1p/Vault/Item/field` in manifests and `.env` files.
The daemon (`avd`) registers these backends; the thin `av` client does not link them.

## `agentvault.yaml` is written by a human

`av init` generates adapter files only; it does not create the manifest. Write
`agentvault.yaml` at the repository root:

```yaml
profiles:
  ci:
    GITHUB_TOKEN:
      ref: av://file/GITHUB_TOKEN
      tier: normal
    DEPLOY_KEY:
      ref: av://1p/Eng/Deploy/private key
      tier: dangerous
```

Every entry requires `ref` and `tier`; `tier` is exactly `normal` or `dangerous`.
`av run --profile ci -- <command>` injects the logical names into the child.

If a project already has `.env`, `av env -- <command>` can resolve references in
place and pass literal values through:

```dotenv
GITHUB_TOKEN=av://file/GITHUB_TOKEN
NPM_TOKEN=av://1p/Eng/npm/token
LOG_LEVEL=debug
```

`av env` also merges the selected manifest profile (`--profile`, default `smoke`).
A name defined in both `.env` and the manifest is an error; there is no silent
precedence.

## Rules for the agent

- **Run commands with `av run`.** Use `av run --profile <PROFILE> -- <command>` to
  run anything that needs credentials. `av run` injects the secrets into the
  command's environment and masks the command's own output at the source (layer 1)
  before it reaches the agent. Never print/capture a secret value directly.
- **Treat `{{AV:NAME}}` as opaque.** When you see `{{AV:NAME}}` (or
  `{{AV:REDACTED:<rule>}}`) it is a redacted secret — a reference, not a value. You
  may refer to it by name; you MUST NOT try to recover, decode, or reconstruct the
  value, nor ask the user to paste it.
- **Pipe tool output through `av scrub`.** The scrub hook is the independent second
  layer that catches secrets `av run` did not issue (derived tokens, values in files
  the agent reads).
- **`av read` is for a human at a TTY only.** `av read NAME` refuses unless stdout is
  a real terminal, so an agent cannot capture a value through a pipe. Use `av run`
  for credentials.
- **Request access yourself when the vault is locked (`AV_NO_PROMPT`).** The generated
  hook exports `AV_NO_PROMPT=1`, so secret operations exit **69** (`EX_UNAVAILABLE`)
  without prompting automatically. When `av status` reports `locked`, or an operation
  fails because the vault is locked, tell the user you are requesting access and **run
  `av unlock` yourself**. Do not ask the user to type the command. It requests native
  user-presence approval, using biometrics (such as Touch ID) when available or the
  platform's configured authentication method. The user completes the system prompt;
  the agent only starts it. Explicit `av unlock` still requests approval with
  `AV_NO_PROMPT=1`; keep that setting for ordinary secret operations. Wait for unlock
  to succeed, then retry the original operation. If approval is canceled, denied, or
  times out, or authentication is unavailable, stop the dependent operation and report
  the result. Never bypass authentication or repeat prompts in a loop.

## Scrub-coverage contract

Layer 2's promise holds only if **every channel that carries external text into the
agent's context is intercepted** by the scrub hook. The contract is not "hook
stdout" — it is "enumerate every ingress channel and intercept each." A channel left
unhooked is a hole.

Channels that MUST be hooked (map these to your agent's tool/hook names):

- shell / command output (stdout and stderr)
- file read output (file contents shown to the model)
- tool / plugin output (anything that returns external text to the model)
- web fetch / web search results
- any future channel whose result is shown to the model

Layer 1 (`av run` source-masking) and layer 2 (this scrub hook) are independent:
failure of either one alone does not leak a secret.
