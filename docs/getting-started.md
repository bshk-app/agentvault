# Getting started

This walkthrough takes you from nothing to a command running with a brokered secret
that your agent never sees in plaintext. It assumes macOS with Touch ID.

> **New to the idea?** AgentVault runs a small resident daemon (`avd`) that holds your
> secrets and injects them into the commands you run, masking the values in the output
> at the source. A thin `av` CLI talks to it. You — and your agent — work with *logical
> names*; the real values stay in the daemon.

## 1. Install

```sh
brew install bshk-app/homebrew-tap/agentvault
# newer Homebrew gates third-party taps; if install is blocked:
brew tap bshk-app/homebrew-tap && brew trust bshk-app/homebrew-tap
```

Requires macOS and the Xcode Command Line Tools (the Touch ID path is built with cgo;
the CLT ship clang, which Homebrew already requires).

`brew install` builds from source as an ad-hoc-signed binary. That is fully supported —
it means your vault key is protected by the **login keychain** (the Secure Enclave tier
needs a signed build; see the [security model](security-model.md#identity-protection-tiers)).

## 2. Start the daemon

```sh
brew services start agentvault
```

This runs `avd` as a per-user LaunchAgent in your GUI session — the only context where
the Touch ID prompt can appear. It starts at login and is kept alive.

Verify:

```sh
av version
# av     v0.2.4
# avd    v0.2.4
# key    keychain  (Enclave unavailable — unsigned build)
# socket /Users/you/.../avd.sock
```

If `avd` shows `(not running)`, see [troubleshooting](troubleshooting.md#the-daemon-isnt-running).

## 3. Provision the vault

```sh
av setup
# created vault /Users/you/.../vault.age
#   identity /Users/you/.../identity
```

`av setup` creates the local age vault and **auto-picks the strongest key tier the
binary can provide** — never silently downgrading to plaintext. On the build-from-source
install that is the login keychain. Run it once.

You do **not** need to run `av unlock` first. The first operation that needs the key
prompts Touch ID on demand and opens the session for ~15 minutes (see
[auto-unlock](#auto-unlock-no-explicit-unlock-needed)).

## 4. Store a secret

```sh
av add GITHUB_TOKEN
# Value (input hidden): ••••••••••••••••
# added GITHUB_TOKEN
```

The value is read from a **hidden prompt** (or piped stdin) — never from the command
line — so it stays out of your shell history and the process table. The first `av add`
on a locked vault triggers Touch ID.

Piping works too (a single trailing newline is stripped; interior newlines are kept for
multi-line secrets):

```sh
printf '%s' "$MY_TOKEN" | av add GITHUB_TOKEN
```

Remove a value with `av rm GITHUB_TOKEN`. The age-file backend is the only writable one;
Keychain and 1Password are read-only (see [the manifest reference](#the-manifest-agentvaultyaml)).

## 5. Describe a profile

Create `agentvault.yaml` in your project. It maps logical names to backend references
and access tiers. **It holds no secret values** — commit it.

```yaml
profiles:
  smoke:
    GITHUB_TOKEN:
      ref: av://file/GITHUB_TOKEN
      tier: normal
```

`smoke` is the default profile name (`av run`/`av read` use it when you omit
`--profile`). See [the manifest reference](#the-manifest-agentvaultyaml) below for tiers
and references.

## 6. Run a command with the secret

```sh
av run --profile smoke -- sh -c 'echo $GITHUB_TOKEN'
# {{AV:GITHUB_TOKEN}}
```

The child process really receives the token in its environment — but the value is masked
in the output at the source, so anything reading this line (you, a log, an agent) sees
only `{{AV:GITHUB_TOKEN}}`. That is the whole point: the command works, the secret never
surfaces.

A more realistic example — a tool that reads a config file. **Don't write the value to
disk**; put an environment *reference* in the file and let `av run` resolve it at runtime:

```sh
printf '//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n' > .npmrc
av run --profile smoke -- npm whoami
# prints your npm login; the token is never written to .npmrc
```

### An existing `.env`-based app

If your app already loads its config from a `.env`, you don't need a profile. Make the
secret a *reference* instead of a value and run the app under `av env` — the reference is
resolved from the vault at launch and injected into the process, never written to `.env`:

```sh
# .env contains:  OPENAI_API_KEY=av://file/OPENAI_API_KEY
av env -- bun --bun next dev      # resolved from the vault at launch; never written to .env
```

Plain literals in the `.env` (e.g. `MSSQL_PORT=1433`) pass through unchanged, and the
child's output is masked by default, exactly as with `av run`.

## Auto-unlock (no explicit `unlock` needed)

The age key is only ever held in an unlocked, `mlock`'d session — zeroized on `av lock`,
on TTL expiry, and on auto-lock (screen-lock / sleep). The first operation that needs
the key (`av add`, `av rm`, `av read`, `av run`) on a locked session prompts Touch ID on
demand and proceeds.

`av unlock` stays available to warm the session up front, but it is optional:

```sh
av unlock     # Touch ID → "unlocked for 15m"
av status     # "unlocked, 873s remaining"
av lock       # re-lock and clear issued values
```

> **Agents pause instead of prompting.** The hook generated by `av init` exports
> `AV_NO_PROMPT=1`. With that set, a locked vault returns a clean **exit 69** ("ask a
> human to unlock") instead of blocking on a biometric prompt the agent can't satisfy.
> See [agent integration](agent-integration.md).

## The manifest (`agentvault.yaml`)

A profile groups logical names that are activated together. Each entry has a backend
`ref` and an access `tier`.

```yaml
profiles:
  smoke:
    GITHUB_TOKEN:
      ref: av://file/GITHUB_TOKEN
      tier: normal
  deploy:
    NPM_TOKEN:
      ref: av://file/NPM_TOKEN
      tier: normal
    STRIPE_SECRET:
      ref: av://keychain/stripe/live
      tier: dangerous
```

**Access tiers:**

| Tier | Behavior |
|------|----------|
| `normal` | served from the unlocked session for its TTL — one Touch ID covers the window |
| `dangerous` | a fresh Touch ID per access; the value is never cached in the session |

**Backends** — a reference is `av://<backend>/<locator>`:

| Backend | Reference | Access | Populate with |
|---------|-----------|--------|---------------|
| age file | `av://file/NAME` | read/write | `av add NAME` (`av rm NAME` to drop) |
| Keychain | `av://keychain/<service>/<account>` | read-only | `security add-generic-password -s <service> -a <account> -w` |
| 1Password | `av://1p/<Vault>/<Item>/<field>` | read-only | manage the item in 1Password (`op`); resolves via `op read` |

The age file is the only writable backend (`av setup` provisions it, `av add`/`av rm`
manage it). Keychain and 1Password are resolved read-only — populate and rotate them with
their own tools.

## Next steps

- **Wire it into your agent** so its output is redacted automatically →
  [agent integration](agent-integration.md)
- **Understand the guarantees** (what's protected, what isn't) →
  [security model](security-model.md)
- **Something not working?** → [troubleshooting](troubleshooting.md)
