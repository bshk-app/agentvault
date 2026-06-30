# `av env` — resolve `.env` references at runtime

**Date:** 2026-06-21 · **Status:** design (validated via brainstorming)

## Problem

12-factor apps (e.g. a Node/Next dev server) read secrets from `process.env`, usually
loaded from a plaintext `.env`. That puts real `OPENAI_API_KEY` / `COHERE_API_KEY` values
on disk, readable by any process running as the user. AgentVault already brokers secrets
for `av run --profile`, but that requires an `agentvault.yaml` and rewriting how the app
is launched. We want the `.env`-native ergonomics: keep `.env`, but let its values be
**references into the vault** that are resolved at launch and injected into the child's
environment — never written to disk.

## Model: `.env` as a reference manifest

Each `KEY=VALUE` line in `.env`:

- if `VALUE` parses as a valid `av://backend/locator` reference (the **same**
  `backend.ParseRef` used by `agentvault.yaml`) → it is a **reference** to resolve;
- otherwise → a **literal**, injected verbatim (`MSSQL_PORT=1433`, `CHAT_MODEL=…`).

```dotenv
OPENAI_API_KEY=av://file/OPENAI_API_KEY      # resolved from the vault
COHERE_API_KEY=av://1p/Dev/Cohere/key        # resolved via 1Password
MSSQL_PORT=1433                              # literal, passed through
```

Detection is **structural** (`av://` = reference). A literal that coincidentally starts
with `av://` is treated as a reference; escaping is out of scope for v1 (documented).

## Key idea: reuse the `av run` engine (zero daemon change)

`av run` already works like this: the **client** reads `agentvault.yaml`, sends the daemon
`ipc.ResolveParams{Profile, Manifest: bytes, NoPrompt}`, the daemon resolves that profile's
entries against the backends (gated by the unlocked session) and returns `map[name]value`.

`av env` introduces **no new resolve path**. The client turns the discovered references
into a **synthetic in-memory manifest** — one profile `_env` with entries
`NAME: {ref: av://…, tier: normal}` — and calls the existing
`client.Resolve("_env", synthManifestBytes)`. The daemon cannot tell a synthetic profile
from a real one: same backends, same session + Touch ID, same source-masking.

New code lives entirely on the client: a `.env` parser, reference detection, the synthetic
manifest builder, source merge, and the `--no-mask` flag. Resolution, session, masking,
and exit-code mapping are reused one-for-one. SSOT preserved: one resolve engine.

## Command surface

```
av env [--env-file PATH] [--profile P] [--no-mask] -- <cmd> [args...]
```

- `--env-file` — default `.env` in cwd.
- `--profile` — which `agentvault.yaml` profile participates (default `smoke`); reused from `av run`.
- `--no-mask` — disable layer-1 source masking of the child's output (default: masking on).
- `--` separates `av env` flags from the child command.

## Data flow

1. Parse args → env-file path, flags, child argv (after `--`).
2. Read + parse `.env` (godotenv) → `map[KEY]VALUE`.
3. Split each entry: `ParseRef(VALUE)` ok → **refs**; else → **literals**.
4. Gather references from both sources (see precedence): `.env` refs + the `--profile`
   profile of `agentvault.yaml` (if present).
5. **Short path:** no references at all → inject literals + `exec` (no daemon contact;
   works offline). Otherwise continue.
6. Build the synthetic manifest (`profiles._env` = `NAME→{ref, tier}`; `.env` refs are
   `normal`, yaml refs keep their authored tier) → marshal to YAML bytes.
7. `client.Resolve("_env", synthBytes)` (NoPrompt from `AV_NO_PROMPT`, version) → one RPC,
   one session open, `map[name]value` for all entries.
8. Build child env = `os.Environ()` overlaid with `.env` literals + resolved values.
9. `exec` the child with that env. If masking on (default), wrap its stdout/stderr through
   the same source-masking redactor, seeded with the resolved values. Propagate the
   child's exit code.

## Sources & precedence

`av env` gathers names from **both** sources; it errors only if neither exists.

| Present | Behavior |
|---|---|
| only `.env` | literals + refs from `.env` |
| only `agentvault.yaml` | refs from the `--profile` profile (default `smoke`), with authored tiers (incl. `dangerous`) |
| both | **merge**: `.env` literals + `.env` refs + profile refs |
| neither | exit 2 |

**Name conflict** (same `NAME` in `.env` and the yaml profile) → **hard error,
fail-closed**: `NAME defined in both .env and agentvault.yaml — remove one`. Rationale: do
not guess precedence, and never silently downgrade a `dangerous`-tier yaml secret to the
`normal` tier a `.env` ref carries.

## Env precedence & fail-closed

Child environment invariant:

```
os.Environ()  <  every key defined in .env / the merged set (literals and resolved refs)
```

`.env` is authoritative for every key it defines; a resolved reference always beats an
inherited value (you wrote a reference, so you want the secret, not whatever is inherited).
A `--no-override` knob is deferred (YAGNI).

**Fail-closed:** if any reference fails to resolve, the child is **not started at all** —
the app never boots with a missing/empty secret.

| Situation | Exit | Message (secret-free) |
|---|---|---|
| no `.env` and no `agentvault.yaml` | 2 | `no .env or agentvault.yaml` |
| value looks like `av://` but `ParseRef` fails | 2 | names KEY + the bad ref |
| name in both `.env` and yaml profile | 2 | `NAME defined in both …` |
| vault locked (under `AV_NO_PROMPT`) | 69 | `vault locked — ask a human to unlock` |
| Touch ID denied/cancelled (dangerous) | 77 | `access denied` |
| a reference fails to resolve (missing secret / backend error) | 1/2 | names KEY+ref, **never a value** |
| no command after `--` | 2 | usage |
| success | child's code | — |

Reuses `av run`'s `exitForError` mapping; adds fail-closed on partial resolution.

## Unlock / batching

Batching is inherent — nothing special to build:

- `client.Resolve` is **one RPC** resolving the whole synthetic profile (all references) in
  one round-trip.
- Unlock unwraps the vault **identity** (the age key) — **one Touch ID**. After that the
  whole **file backend** decrypts in the `mlock`'d session with **no further prompts**.
  10 `av://file/…` secrets = **1 Touch ID**.
- Default tier `normal` → served from the session for its TTL; one presence check covers
  all of them.

Caveats:
- `dangerous`-tier entries (only from yaml) re-prompt per access, by their tier.
- `av://1p/…` resolves via `op`, which has its own biometric + cached session, separate
  from AgentVault's session (also not N×).

Timing:
- Interactive (`av env -- bun dev`): one on-demand Touch ID at startup; session ~15 min.
  Restarting the dev server within the TTL → no prompt.
- Agent (`AV_NO_PROMPT=1`): locked → exit 69; a human runs `av unlock` once, then `av env`
  proceeds. The env is injected once at `exec`, so a later TTL expiry doesn't disturb the
  running process.

## Parser

Use `github.com/joho/godotenv` (`Read`/`Parse` → `map[string]string`). It handles quotes,
comments, multiline, and the `export ` prefix. Reference detection runs on the resulting
values (`ParseRef(value)`); godotenv's `${VAR}` expansion does not touch `av://…` values.
Duplicate keys → last-wins (documented). Small, pure-Go dependency, acceptable for the thin
`av`.

## Masking

Default **on** (`--no-mask` to disable). Same layer-1 source masking as `av run`, seeded
with the resolved values — even if a secret leaks into the dev server's logs it shows
`{{AV:NAME}}`. `--no-mask` exists because `av env` typically wraps a long-running, noisy
dev server where streaming output untouched is sometimes preferable.

## Edge cases

- Empty `.env` / no references → inject literals, `exec`, no daemon (short path).
- Duplicate keys in `.env` → last-wins (godotenv).
- A literal coincidentally starting with `av://` → treated as a reference (structural
  detection is the contract).

## Testing

Unit (Go, no daemon) — the bulk:
- `.env` parser + reference detection: literal/reference split; malformed `av://` flagged;
  duplicate keys last-wins; coincidental `av://` treated as a reference.
- Synthetic manifest builder: references → bytes accepted by `manifest.Parse` (profile
  `_env`, `name→{ref, tier:normal}`).
- Source merge + precedence: `.env`-only / yaml-only / both / neither → correct name set;
  conflict → error.
- Child env assembly: `os.Environ()` < `.env` keys; resolved references overlaid.
- Arg parsing: `--env-file`, `--profile`, `--no-mask`, `--` split, missing command → exit 2.

Reused (not duplicated): resolve, session, source-masking, and `exitForError` tests already
cover the shared engine.

E2E / smoke (existing `AV_TEST_*` stub harness + file backend, like `smoke-e2e.sh`): a
`.env` with one `av://file/NAME` → `av env -- sh -c 'echo $NAME'` → output shows
`{{AV:NAME}}` (masked), the child really received the value, literals passed through, one
resolve, fail-closed on a missing secret.

Discipline: each task is test-first (TDD), per the repo.

## Out of scope (v1 / YAGNI)

- `${av://…}` interpolation inside a larger string (whole-value references only).
- Per-reference tier syntax in `.env` (`.env` refs are always `normal`; use
  `agentvault.yaml` for `dangerous`).
- Writing/rewriting `.env` (resolution is runtime-only, never persisted).
- Merging multiple env files / `.env.local` precedence chains.
- A `--no-override` precedence knob.

## Future

- Generated adapter docs (`av init`) could teach `av env` as the recommended way to run a
  `.env`-based app under AgentVault.
- A `dangerous` marker for `.env` refs if a real need appears.
