# AgentVault documentation

AgentVault is an agent-agnostic secret broker for macOS, Linux, and Windows: your AI coding agent runs
real commands with real credentials, but never sees those credentials in plaintext.

Start with the [project README](../README.md) for the one-page overview and install.
These guides go deeper, task by task.

## Guides

| Guide | Read it when you want to… |
|-------|---------------------------|
| [Getting started](getting-started.md) | install, provision the vault (avd starts at login), store your first secret, and run a command with it — step by step |
| [Agent integration](agent-integration.md) | wire AgentVault into Claude Code (or any agent) so its output is redacted automatically |
| [SOPS](sops.md) | move your SOPS age key into the vault so `sops`, `helm secrets`, and `kustomize` decrypt without ever holding it |
| [Security model](security-model.md) | understand what AgentVault does and does not protect against, and how the key is protected at rest |
| [Platform support](platforms.md) | Linux/Windows prerequisites, service managers, and known gaps |
| [Troubleshooting](troubleshooting.md) | fix a stuck native prompt, a locked vault, a version skew, or a confusing exit code |
| [Signing & notarization](signing-and-notarization.md) | *(maintainers)* cut the signed, notarized release that unlocks the Secure Enclave tier |

## Reference

- [CLI reference](../README.md#cli) — every `av` subcommand and exit code (in the README)
- [`agentvault.yaml` manifest](getting-started.md#the-manifest-agentvaultyaml) — profiles, references, tiers
- [Running `avd` at login](launchagent.md) — what `av service` does + the login-item verification checklist

## Design notes

`docs/plans/` holds the internal design and implementation plans. They record *why*
the system is shaped the way it is; they are not user documentation and may lag the
shipped behavior.
