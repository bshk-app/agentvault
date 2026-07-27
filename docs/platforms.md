# Platform support

AgentVault's vault format is portable: `vault.age` is encrypted with `filippo.io/age`
on every OS. Platform support is about protecting the age identity, presenting a native
human-presence prompt, and keeping the daemon reachable only by the current user.

## macOS

- IPC: `0600` Unix socket plus same-UID peer credential check.
- Identity tier: login Keychain by default; Secure Enclave on eligible signed builds.
- Presence: LocalAuthentication / Touch ID.
- Start at login: SMAppService for the signed app, LaunchAgent for source builds.
- Auto-lock: screen-lock and sleep observers.

## Linux

- IPC: `0600` Unix socket plus `SO_PEERCRED` same-UID check.
- Identity tier: Secret Service via `secret-tool`.
- Presence: polkit via `pkcheck --allow-user-interaction`.
- Start at login: generated `systemd --user` unit.
- Auto-lock: best-effort logind D-Bus monitor through `dbus-monitor`.

Install prerequisites before using the default keychain tier:

```sh
# Debian/Ubuntu package names
sudo apt install libsecret-tools policykit-1 dbus-user-session systemd
```

The polkit action id is `app.bshk.agentvault.unlock`; desktop distributions without a
matching local policy may deny the prompt. In that case `av unlock` fails closed instead
of falling back to plaintext. Use `av setup --plaintext` only as an explicit development
escape hatch.

## Windows

- IPC: named pipe derived from `%LocalAppData%\AgentVault\avd.pipe`, protected by a
  current-user security descriptor.
- Identity tier: Windows Credential Manager.
- Start at login: per-user Task Scheduler logon task.
- Runtime/audit state: `%LocalAppData%\AgentVault`.
- Vault/config state: `%AppData%\AgentVault`.

- Socket/pipe override: `AV_SOCKET_PATH` selects the endpoint on every platform. On
  Windows the pipe name is derived from that logical path by hash, so an override yields
  a genuinely independent instance — which is the only way to run a second one there.

### Current gaps — Windows is not usable yet

**`avd` does not start.** `selectPresence` (`cmd/avd/main.go`) treats a missing presence
provider as fatal, deliberately, so the daemon never brokers a secret without a real
check. `newTouchIDPresence` in `internal/daemon/presence_windows.go` always returns an
error because the Windows Hello WinRT bridge is unimplemented. So the daemon comes up
only under `AV_TEST_AUTH`, which is test-only and bypasses the very protection it stands
for. This is stronger than "missing parity": there is no working configuration.

**Owner-only file permissions have no expression.** `0600` and `0700` require an explicit
NTFS ACL, and Go's `os` package cannot set one — `os.Chmod` toggles only the read-only
attribute, and `Mode().Perm()` can never report anything but `0666`/`0444`/`0777`/`0555`.
The vault, the identity file, and the audit log are therefore not restricted to their
owner the way they are on Unix. For a secret store that is a real gap, not a formality;
closing it needs `golang.org/x/sys/windows` ACL work.

**Auto-lock on session lock / sleep** still needs a native bridge.

### What CI does prove on Windows

`go test ./...` runs on `windows-latest` on every push. The named-pipe transport,
`age-plugin-av` discovery through `PATHEXT`, `AV_SOCKET_PATH`, and the SOPS decrypt path
all pass. Three things are skipped, each naming its cause: the permission-bit assertions,
`TestAddFailureLeavesOriginalIntact` (a read-only directory attribute does not deny file
creation on Windows), and `TestE2ELockedRunFails` (it needs an `avd` with no auth, which
on Windows is an `avd` that does not start).
