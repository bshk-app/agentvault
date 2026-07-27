# Running `avd` at login (macOS)

`av unlock` triggers a Touch ID prompt via `LocalAuthentication`. That prompt can
only be presented from a process running in the user's **Aqua/GUI session**.
Therefore `avd` must run as a **per-user login item**, never as a system
`LaunchDaemon` (a LaunchDaemon has no GUI session and the prompt silently fails).

## What `av service` does

`av setup` registers `avd` to start at login, and `av service on|off|status` manages
that registration afterward. You do not edit a plist or run `launchctl` by hand —
`avd` owns the registration (`SMAppService` resolves the plist relative to *avd's* own
bundle, which `av` is not in), so the CLI is a thin RPC to the daemon.

Two backends, selected at runtime:

- **`SMAppService`** (the signed cask, macOS 13+) — the LaunchAgent plist is sealed
  inside `AgentVault.app/Contents/Library/LaunchAgents/` and registered via
  `SMAppService`. `av service status` reports `smappservice` and can show
  `requires-approval` (registered, but you must allow it in System Settings).
- **`launchagent`** (build-from-source) — `avd` writes
  `~/Library/LaunchAgents/app.bshk.agentvault.avd.plist` (an absolute `ProgramArguments`
  path, `Interactive` ProcessType so Touch ID is presentable) and bootstraps it into
  your GUI session. `av service status` reports `launchagent`, `enabled` or `disabled`.

```sh
av service on        # register avd to start at login (idempotent)
av service status    # login item (smappservice): enabled
av service off       # unregister; mirrors the System Settings → Login Items toggle
```

A plain `avd` start never (re-)registers — it honors whatever you set in **System
Settings → General → Login Items**.

## Manual verification — login item (cannot be unit-tested)

cgo + `SMAppService` need a signed bundle and a GUI session, so CI can't cover them.
Verify the real path by hand on a signed install:

```sh
av setup                 # registers the login item; expect the macOS background-item notice
av service status        # -> login item (smappservice): enabled   (or requires-approval)
# System Settings → General → Login Items → AgentVault is listed under "Allow in the Background"
# log out and back in    # avd is running without any manual launchctl step
av service off           # -> login item (smappservice): disabled; the entry disappears
```

On a build-from-source install the backend reads `launchagent` and the plist lands at
`~/Library/LaunchAgents/app.bshk.agentvault.avd.plist`.

## Manual verification (Touch ID — cannot be automated)

```sh
av status          # -> "locked"
av unlock          # -> a real Touch ID prompt appears reading "Unlock AgentVault"
                   #    touch the sensor -> "unlocked for 15m"; av status -> "unlocked, …"
av unlock          # then press Esc / cancel -> exit 69 (or 77), message "vault locked …"
```

If `av unlock` returns immediately with "locked" and **no prompt appears**, `avd`
is not in the GUI session — re-run `av service on` (which bootstraps it into
`gui/$(id -u)`), and confirm it is a per-user login item and not a `LaunchDaemon`.

## Manual fallback (launchctl by hand)

`av service on` does this for you; reach for the manual steps only when debugging.
Build with `make build`, then render and load the plist yourself:

```sh
mkdir -p ~/bin ~/Library/Logs/agentvault
# age-plugin-av too: age finds plugins by filename on PATH, so leaving it behind
# breaks SOPS decryption with a confusing error. See docs/sops.md.
cp bin/av bin/avd bin/age-plugin-av ~/bin/

# absolute avd path; Interactive ProcessType keeps Touch ID presentable
launchctl bootout gui/$(id -u)/app.bshk.agentvault.avd 2>/dev/null
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/app.bshk.agentvault.avd.plist
launchctl print gui/$(id -u)/app.bshk.agentvault.avd | head   # state = running
```

## Why not a LaunchDaemon

System `LaunchDaemon`s run in a non-GUI context (session 0). `LocalAuthentication`
returns an error there instead of presenting UI, so `av unlock` would always fail
with `CodeLocked`. The broker is per-user by design (it holds *your* session), so a
per-user LaunchAgent is the correct and only supported deployment.
