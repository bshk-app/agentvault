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

Current gap: Windows Hello presence and session-lock auto-lock still need native bridges.
Production Windows builds therefore fail closed for `av unlock` unless the test stub
environment is explicitly enabled, and should not yet be treated as parity with macOS or
Linux desktop builds.
