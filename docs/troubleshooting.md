# Troubleshooting

Symptom-first fixes for the common AgentVault snags. Start with `av version` — it reports
both binary versions, the active key tier, and the socket path without needing an unlocked
vault.

## Exit codes

Every `av` command exits with a stable, secret-free code you (or your agent) can branch
on:

| Code | Meaning | What to do |
|------|---------|------------|
| `0` | success (`av run` also propagates the child's own exit code) | — |
| `1` | generic failure (setup / IO / unexpected daemon error) | check the stderr message and `av version` |
| `2` | bad request (usage error, unknown profile/name, bad ref) | fix the command or `agentvault.yaml` |
| `69` | vault locked | run `av unlock` (or, for an agent, ask a human to) |
| `77` | access denied (a `dangerous`-tier secret, Touch ID canceled/failed) | re-run and approve the prompt |
| `80` | `av read` refused — stdout is not a terminal | use `av run`; `av read` only prints to a real TTY |

## The daemon isn't running

`av version` shows `avd  (not running)`, or commands fail to reach the socket.

```sh
av service on      # register avd to start at login and bring it up now
av version         # avd should now show a version
```

`avd` also starts lazily the first time `av` dials the socket, so most commands bring it
up on their own — `av service on` is the explicit form and (re-)registers the login item.

If it still won't start, check the logs:

```sh
tail -f ~/Library/Logs/agentvault/avd.err.log
```

`avd` must run in your **GUI session** (that is what makes Touch ID presentable); the
login item registered by `av setup` / `av service on` runs it there. See
[running avd at login](launchagent.md).

## Touch ID prompt never appears

`av unlock` returns immediately with `locked` and no prompt shows.

This means `avd` is not in the GUI/Aqua session. A system `LaunchDaemon` (session 0) has
no GUI and `LocalAuthentication` fails silently there. The login item registered by
`av service on` runs `avd` as a per-user agent in your GUI session — re-run it and
confirm it is not a `LaunchDaemon`. See
[launchagent.md](launchagent.md#why-not-a-launchdaemon).

## After `brew upgrade`, commands behave oddly

The already-running `avd` keeps serving the **old** code until it is restarted. AgentVault
self-heals this: on the next command, if `av` sees a version skew (both release builds), it
shuts the stale daemon down, lets the new binary take over, and retries — no manual
restart needed.

If you ever need to force it:

```sh
av service off && av service on   # bounce the login item; the new binary takes over
av version                        # av and avd versions should now match
```

`av version` prints a loud warning when `av` and `avd` versions differ.

> **Agents never restart the daemon.** With `AV_NO_PROMPT=1`, an agent that hits a stale
> daemon gets a clear "avd outdated — ask a human" error and pauses, rather than
> restarting a shared service.

## "vault locked" / exit 69 in an agent

Expected behavior, not a bug. The agent adapter exports `AV_NO_PROMPT=1`, so a locked
vault returns exit 69 instead of blocking the agent on a Touch ID prompt. A human runs:

```sh
av unlock      # Touch ID → "unlocked for 15m"
```

…and the agent retries. See [agent integration](agent-integration.md#what-the-agent-must-know).

## `av add` shows a hex string / wrong value stored

Older builds could corrupt a value containing a trailing newline (the macOS `security`
tool returns such values as a hex dump). This is fixed in current releases. If you stored
a bad value with an old build, rotate and re-add:

```sh
av setup --rotate     # fresh identity + vault (Touch ID)
av add NAME           # re-enter the value
```

Make sure `av version` shows matching, current versions first.

## `av run` says no profile / "profile not found"

- You're not in a directory with an `agentvault.yaml`, or the profile name is wrong.
- `--profile` defaults to `smoke`; pass `--profile <name>` to select another.
- Check the file parses and the names match:

  ```sh
  av run --profile <name> -- env | grep -v '^_'   # values appear masked as {{AV:NAME}}
  ```

See [the manifest reference](getting-started.md#the-manifest-agentvaultyaml) for the exact
schema (every entry needs a `ref` and a `tier` of `normal` or `dangerous`).

## A secret reached the agent's context anyway

If text containing a real value reached the model, the most likely cause is an **unhooked
ingress channel** — layer 2 only redacts channels the scrub hook is wired onto. Audit your
hook matcher against the [scrub-coverage contract](agent-integration.md#the-scrub-coverage-contract):
shell output, file reads, tool/MCP output, and web results must all be intercepted. If a
channel is covered and a value still leaked, that is a security bug — see
[reporting issues](security-model.md#reporting-issues).

## The scrub hook isn't firing

- Confirm the hook is executable: `ls -l .claude/hooks/av-scrub.sh` (should be `0755`).
- Confirm the `PostToolUse` block was merged into your live settings (the generated
  `.claude/agentvault.hooks.json` is a **template to merge**, not applied automatically).
- Confirm the matcher names match your agent version's tool names (`claude --version`).

See [agent integration](agent-integration.md#wire-the-hook-posttooluse).

## `sops` can't decrypt through AgentVault

`sops` reports "Recovery failed because no master key could be found", or `no identity
matched any of the recipients`.

**Read the whole error box.** `sops` word-wraps it, so the line that names the real problem
arrives split across two rows with the box rule between them — a plain `grep` for it never
matches. Join the lines first:

```sh
sops -d secrets.enc.yaml 2>&1 | tr '\n' ' ' | tr -d '|' | tr -s ' '
```

`"av" plugin not found: exec: "age-plugin-av": executable file not found in $PATH` and `no
identity matched any of the recipients` sit under the same generic summary and are easy to
confuse. They are different failures: the first means age never started the plugin, the
second means the plugin ran and rejected every stanza. For the second, `av sops ls` tells a
stale pointer from a file that genuinely is not yours.

Full symptom table in [the SOPS guide](sops.md#troubleshooting).

## Test-only env vars leaked into real use

`AV_TEST_AUTH`, `AV_TEST_ENCLAVE`, and `AV_TEST_KEYSTORE` select stubbed presence /
enclave / keystore for CI and the smoke scripts. They **bypass the hardware and keychain
protections** and must never be set in real use. If `av version` or behavior looks wrong,
check your environment for a stray `AV_TEST_*`.
