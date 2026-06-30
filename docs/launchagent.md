# Running `avd` as a per-user LaunchAgent (macOS)

`av unlock` triggers a Touch ID prompt via `LocalAuthentication`. That prompt can
only be presented from a process running in the user's **Aqua/GUI session**.
Therefore `avd` must run as a **per-user LaunchAgent**, never as a system
`LaunchDaemon` (a LaunchDaemon has no GUI session and the prompt silently fails).

> **Note:** With the Homebrew install, `brew services start agentvault` runs `avd`
> as the per-user LaunchAgent for you. The manual steps below are for building from
> source or verifying the Touch ID path by hand.

> **Status:** Phase 5 ships the plist template and these steps. `av init`
> (Phase 6) will generate and install this for you. The steps below are the
> **manual verification path** for the Touch ID work in Phase 5 — a green `go build`
> proves the cgo compiles, not that the prompt works; only this does.

> **Provisioning the vault:** you do not need to create an identity file by hand. Run
> `av setup` once (after `avd` is running) and it auto-picks the best key tier — the
> login keychain on a build-from-source install (no on-disk `identity.txt`). The
> `__AGE_IDENTITY_FILE__` placeholder below is only relevant to the explicit plaintext
> tier (`av setup --plaintext`). See the README's "Identity protection tiers".

## Install

1. Build the binaries:

   ```sh
   make build   # produces bin/av and bin/avd
   ```

2. Pick install paths and fill in the plist placeholders. Example using `~/bin`:

   ```sh
   mkdir -p ~/bin ~/Library/Logs/agentvault
   cp bin/av bin/avd ~/bin/

   sed \
     -e "s|__AVD_PATH__|$HOME/bin/avd|" \
     -e "s|__AGE_IDENTITY_FILE__|$HOME/.config/agentvault/identity.txt|" \
     -e "s|__AGE_VAULT_FILE__|$HOME/.config/agentvault/vault.age|" \
     -e "s|__LOG_DIR__|$HOME/Library/Logs/agentvault|" \
     packaging/app.bshk.agentvault.avd.plist \
     > ~/Library/LaunchAgents/app.bshk.agentvault.avd.plist
   ```

3. Load it into the **GUI session** (this is what makes Touch ID presentable):

   ```sh
   launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/app.bshk.agentvault.avd.plist
   launchctl print gui/$(id -u)/app.bshk.agentvault.avd | head   # should show state = running
   ```

   To reload after changes:

   ```sh
   launchctl bootout gui/$(id -u)/app.bshk.agentvault.avd 2>/dev/null
   launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/app.bshk.agentvault.avd.plist
   ```

## Manual verification (Touch ID — cannot be automated)

```sh
av status          # -> "locked"
av unlock          # -> a real Touch ID prompt appears reading "Unlock AgentVault"
                   #    touch the sensor -> "unlocked for 15m"; av status -> "unlocked, …"
av unlock          # then press Esc / cancel -> exit 69 (or 77), message "vault locked …"
```

If `av unlock` returns immediately with "locked" and **no prompt appears**, `avd`
is not in the GUI session — confirm it was loaded with `launchctl bootstrap
gui/$(id -u) …` and not as a `LaunchDaemon`.

## Why not a LaunchDaemon

System `LaunchDaemon`s run in a non-GUI context (session 0). `LocalAuthentication`
returns an error there instead of presenting UI, so `av unlock` would always fail
with `CodeLocked`. The broker is per-user by design (it holds *your* session), so a
per-user LaunchAgent is the correct and only supported deployment.
