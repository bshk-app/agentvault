# AgentVault documentation

AgentVault is an agent-agnostic secret broker for macOS: your AI coding agent runs
real commands with real credentials, but never sees those credentials in plaintext.

Start with the [project README](../README.md) for the one-page overview and install.
These guides go deeper, task by task.

## Guides

| Guide | Read it when you want to… |
|-------|---------------------------|
| [Getting started](getting-started.md) | install, start the daemon, store your first secret, and run a command with it — step by step |
| [Agent integration](agent-integration.md) | wire AgentVault into Claude Code (or any agent) so its output is redacted automatically |
| [Security model](security-model.md) | understand what AgentVault does and does not protect against, and how the key is protected at rest |
| [Troubleshooting](troubleshooting.md) | fix a stuck Touch ID prompt, a locked vault, a version skew, or a confusing exit code |
| [Signing & notarization](signing-and-notarization.md) | *(maintainers)* cut the signed, notarized release that unlocks the Secure Enclave tier |

## Reference

- [CLI reference](../README.md#cli) — every `av` subcommand and exit code (in the README)
- [`agentvault.yaml` manifest](getting-started.md#the-manifest-agentvaultyaml) — profiles, references, tiers
- [Running `avd` as a LaunchAgent](launchagent.md) — manual daemon install (when not using `brew services`)

## Design notes

`docs/plans/` holds the internal design and implementation plans. They record *why*
the system is shaped the way it is; they are not user documentation and may lag the
shipped behavior.
