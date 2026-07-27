# SOPS

Your SOPS age key normally sits in `keys.txt`, plaintext, mode 0600. Every process you run
can read it, and `sops`, `helm secrets`, and `kustomize` load it on every invocation.
AgentVault moves that key into the vault and leaves a **pointer** where the key was. `sops`
then asks `avd` to unwrap each file, and `avd` returns only that one file's key.

Nothing else changes. Files keep their ordinary `age1…` recipients, `.sops.yaml` is
untouched, and teammates, CI, and Flux read the same files with the same keys.

## Requirements

- **sops 3.10 or newer.** Age plugin support landed in
  [3.10](https://github.com/getsops/sops/pull/1641). Older versions read the pointer, fail
  to make sense of it, and report a decryption failure that says nothing about the version.
  `av sops keygen` and `av sops import` warn when they see an old `sops`.
- **`age-plugin-av` on `PATH`.** age discovers plugins by filename, so the binary must be
  named exactly `age-plugin-av` (`age-plugin-av.exe` on Windows) and must sit in a directory
  on your `PATH`. `make build` puts it in `bin/` beside `av` and `avd`; install all three
  together.

> **`brew install` does not ship the plugin yet.** The Formula lives in an external tap and
> still installs only `av` and `avd` — see [the release blocker](#for-maintainers-the-formula-still-omits-the-plugin).

## Move your existing key into the vault

`av sops import` finds your `keys.txt`, moves every `AGE-SECRET-KEY-1…` in it into the
vault, and rewrites the file with pointers.

```sh
av sops import
# found 1 age key in /Users/you/Library/Application Support/sops/age/keys.txt
#   importing as: imported
# Keep a backup of the original at …/keys.txt.bak? [Y/n] (Ctrl-C to abort)
# imported 1 identity into the vault:
#   imported  (tier normal)  age1abc…
# …/keys.txt now holds pointers instead of keys.
# the plaintext key is STILL in …/keys.txt.bak — delete it once you have confirmed sops can decrypt.
```

`--name NAME` picks the stored name (default `imported`; several keys become `NAME-1`,
`NAME-2`, …). `--from PATH` names the exact file to read **and rewrite** — use it when your
key is somewhere the search does not look.

Three things worth knowing before you run it:

- **The backup keeps the plaintext key.** It defaults to on, and answering anything but `n`
  keeps it. With no terminal to ask at — CI, a script, `</dev/null` — the backup is kept
  *without asking*, so a `.bak` holding the plaintext key is left behind. Delete it once you
  have confirmed `sops -d` works.
- **The rewrite drops everything that is not a key or a pointer.** Comments and blank lines
  in your `keys.txt` do not survive; the `.bak` has them.
- **Nothing is rewritten unless every key stored.** A partial import leaves the file exactly
  as `sops` was using it, and says which names already reached the vault.

The file it rewrites is the file it read the key from — never a different one. That matters
because `SOPS_AGE_KEY_FILE` is *additive*: `sops` opens it **and** the config-dir
`keys.txt`, so a pointer written to the wrong one would leave the plaintext key exactly
where `sops` keeps reading it.

Where `keys.txt` lives differs by platform, and macOS differs from the obvious guess:

| Platform | Path |
|---|---|
| Linux | `$XDG_CONFIG_HOME/sops/age/keys.txt`, else `~/.config/sops/age/keys.txt` |
| macOS | `$XDG_CONFIG_HOME/…` when set, else `~/Library/Application Support/sops/age/keys.txt` |
| Windows | `%AppData%\sops\age\keys.txt` |

`av sops import` checks every location — plus `SOPS_AGE_KEY_FILE` — and names all of them
when it finds none.

### If your key lives in an environment variable

`SOPS_AGE_KEY` and `SOPS_AGE_KEY_CMD` are not files, so there is nothing on disk to import.
`av sops import` detects both and prints the exact commands to write the key to a file it
can import.

**Unset them afterwards, and remove them from your shell profile.** While either is set,
`sops` keeps using that key, the pointer is never exercised, and everything looks like it
works. `av sops keygen` and `av sops import` warn when they see either variable.

## Or start with a key that never touched disk

An imported key has already spent time as plaintext on your disk, and that cannot be
undone. `av sops keygen` generates the key inside `avd`, so the private half never exists
anywhere else:

```sh
av sops keygen work
# created SOPS identity "work" (tier normal)
#   recipient age1abc…
# encrypt to it — add to .sops.yaml:
#   creation_rules:
#     - age: age1abc…
# decrypt with it — point sops at the vault:
#   av sops identity work >> "/Users/you/Library/Application Support/sops/age/keys.txt"
```

Neither placement happens automatically: `.sops.yaml` is your repo, and `keys.txt` may hold
other identities that `av sops import` owns the rewriting of. Run the `av sops identity`
line it prints to append the pointer.

`--tier dangerous` makes every file cost a fresh presence check — see
[presence checks](#presence-checks-one-per-command-not-one-per-file).

## `.sops.yaml`

Unchanged. Encryption uses only public recipients, so no private key participates and
AgentVault has nothing to broker:

```yaml
creation_rules:
  - path_regex: .*\.enc\.yaml$
    age: age1abc…          # av sops recipient work
```

`av sops recipient NAME` prints the `age1…` to paste here. `av sops identity NAME` prints
the `AGE-PLUGIN-AV-1…` pointer for `keys.txt`. Both are public — the pointer encodes the
recipient, not the key, and without a running `avd` and a presence check it decrypts
nothing. Commit it to your dotfiles if you like.

## Everyday use

Nothing about how you invoke these tools changes.

```sh
sops -d secrets.enc.yaml
sops edit secrets.enc.yaml
helm secrets template myapp ./chart -f values.enc.yaml
kustomize build --enable-alpha-plugins --enable-exec ./overlay
```

**None of the four commands above is exercised by an automated test.** What the test suite
proves is the layer directly underneath them: it spawns a real `avd` and has age exec the
real `age-plugin-av`, which is the production path *minus the `sops` binary itself*.

So `sops -d`, `sops edit`, `sops updatekeys`, `helm secrets` and `kustomize`+ksops are all
**expected** to work — `sops` reaches the plugin through the same age plugin protocol those
tests drive, and the other two are ordinary `sops` callers — but expected is not proven, and
nothing in this repository proves them. See [Platform status](#platform-status) for exactly
where the line falls.

> **Under helm 4, `helm secrets` needs helm-secrets 4.7.7 or newer.** Older releases ship
> the legacy single-plugin layout, and helm 4 either refuses to load it (`both
> platformCommand and command are set`) or loads it as a *getter* and registers no
> subcommand — so `helm secrets` is `unknown command` while `helm plugin list` looks
> healthy. 4.7.7 publishes a separate `secrets-<version>.tgz` that is a real helm 4 plugin
> (`type: cli/v1`); unpack it into `$(helm env HELM_PLUGINS)`. Worth recognising by name:
> the symptom reads like a missing install, when in fact the plugin is installed and
> unusable.

### A mixed `keys.txt` works

Several AgentVault pointers, or AgentVault pointers sitting beside plain
`AGE-SECRET-KEY-1…` lines, all decrypt — the ordinary personal-key-plus-team-key setup that
`av sops import` produces. An identity that cannot open a given file steps aside and age
tries the next, exactly as an all-plaintext `keys.txt` already does.

```
# managed by AgentVault — this is a pointer, not a key.
# identity: work
# recipient: age1abc…
# useless without a running avd + your presence check.
AGE-PLUGIN-AV-1QQQ…

# a second AgentVault identity
AGE-PLUGIN-AV-1RRR…

# a plain age key AgentVault does not manage
AGE-SECRET-KEY-1XXX…
```

Put each comment on its own line. `sops` skips lines beginning with `#`, but a comment
trailing an identity on the same line becomes part of that identity and breaks it.

## Presence checks: one per command, not one per file

`helm secrets template` or `kustomize build` decrypts dozens of files. A presence check per
file would make the feature unusable.

- **`normal` (the default).** The first decryption prompts for presence if the vault is
  locked; the rest of the command runs inside the open session. One touch per
  `helm upgrade`.
- **`dangerous`** (`av sops keygen NAME --tier dangerous`). A fresh presence check on
  **every** file. Slow on purpose — a production deploy should be hard to perform
  absent-mindedly.

The first `dangerous` file on a *locked* vault costs **two** checks, not one: the unwrap
that opens the session, then the fresh per-file check. They buy different things, and
skipping the second would mean the first dangerous file of the day is the one that never
prompts.

Each unwrap that reached an identity is written to the audit log — name, tier, outcome,
never a value. A file encrypted to a recipient you do not hold logs nothing: there is no
identity to name, and one line per foreign file would drown the log.

## Rotation

`av sops keygen` earns its place here. Generate a fresh identity, add it to `.sops.yaml`,
re-wrap the files, then drop the old recipient:

```sh
av sops keygen work-2026     # new key, never on disk
```

Its summary prints the `age1…` recipient and the exact `av sops identity work-2026 >> …`
line for your platform's `keys.txt`. Run that line, then add the new recipient to
`.sops.yaml` **alongside the old one** and re-wrap every encrypted file:

```sh
sops updatekeys secrets.enc.yaml
```

`updatekeys` decrypts through the plugin and re-encrypts to the new recipient list. Once
every file is re-wrapped and you have confirmed they decrypt, remove the old recipient from
`.sops.yaml`, run `sops updatekeys` again, and delete the old identity:

```sh
av sops rm work
```

`av sops rm` destroys the only copy of the key. Every file still encrypted to it becomes
permanently unreadable. It prints what it is about to delete and requires you to type `yes`
at a terminal; `--force` skips the prompt but not the tier's presence check.

## Troubleshooting

### `sops` reports "no master key could be found"

Read the whole error box, not the summary line. **`sops` word-wraps its error box**, so the
line that names the real problem arrives split across two rows with the box rule between
them — a plain `grep` for it never matches. Join the lines first:

```sh
sops -d secrets.enc.yaml 2>&1 | tr '\n' ' ' | tr -d '|' | tr -s ' '
```

Then look for one of these:

| In the joined output | What it means |
|---|---|
| `"av" plugin not found: exec: "age-plugin-av": executable file not found in $PATH` | The plugin is not installed, is misnamed, or is not on the `PATH` `sops` sees. |
| `no identity matched any of the recipients` | Every identity in your `keys.txt` was tried and none could open the file. See below. |
| `AgentVault: sops unwrap: vault locked — ask a human to run "av unlock"` | The vault is locked and the caller set `AV_NO_PROMPT=1`, so nothing prompted. Run `av unlock`. |
| `AgentVault: sops unwrap "NAME": dangerous-tier identity needs a fresh presence check, and this caller set no_prompt` | Not the same thing. The session is **open**; a `dangerous`-tier identity wants a check per file and `AV_NO_PROMPT=1` skipped it. `av unlock` changes nothing — re-run without `AV_NO_PROMPT`, or move the identity to `normal`. |

The first two are easy to confuse because both sit under the same generic "Recovery failed
because no master key could be found" summary. They are different failures: a missing plugin
means age never started the binary, while `no identity matched` means the plugin *ran* and
rejected every stanza.

Any line prefixed `AgentVault:` came from `avd` through the plugin, which is itself proof
the plugin was found and ran.

### `no identity matched any of the recipients`

Your pointer may be **stale** — the identity was removed from the vault but its line stayed
in `keys.txt`. A stale pointer falls through silently rather than naming itself, which is
what lets a mixed `keys.txt` work at all (a live pointer beside a stale one still decrypts).
As the *only* pointer, it produces exactly this generic message.

`av sops ls` is the recovery. It prints the identities the vault actually holds:

```sh
av sops ls
# NAME  TIER       RECIPIENT
# work  normal     age1abc…
# team  dangerous  age1def…
```

Compare those recipients against the `# recipient:` comments `av sops import` wrote into
your `keys.txt`. A pointer whose recipient is not listed is stale — drop the line, or
restore the identity. If every pointer *is* listed, the file genuinely is not yours: its
`sops:` metadata block names the `age` recipients it was encrypted to, and none of them will
be one of yours.

`av sops ls` reads the vault, so it needs an unlocked session and prompts for presence if
the vault is locked.

### Everything decrypts, but the plugin never runs

`SOPS_AGE_KEY` or `SOPS_AGE_KEY_CMD` is still set. `sops` reads those too and keeps using
that key. Unset it and remove it from your shell profile.

### `sops` fails right after you added the pointer

Check the version — `av sops keygen` and `av sops import` warn about this, but a warning on
stderr is easy to scroll past:

```sh
sops --version
```

Below 3.10 there are no age plugins at all.

### `av read sops/work` refuses

By design. The `sops/` namespace in the vault is reserved: `av read`, `av add`, and `av rm`
all refuse it, so a SOPS private key cannot be printed or overwritten by the ordinary secret
commands. `av sops` is the only way in or out.

### Correlating an audit line to a command

The audit log records RPC method names, not subcommands:

| RPC method | Reached by | Audited |
|---|---|---|
| `sops_keygen` | `av sops keygen` | yes |
| `sops_put` | `av sops import` | yes |
| `sops_rm` | `av sops rm` | yes |
| `sops_unwrap` | the plugin — no subcommand | yes |
| `sops_list` | `av sops ls`, `av sops recipient`, `av sops identity` | no — a listing names no single identity, so there is nothing to file it under |

## What this protects

The key never enters the environment, the disk, or the memory of `sops`, `helm`, or
`kustomize`. It does **not** protect the decrypted *output*. See
[the security model](security-model.md#what-brokering-the-sops-key-protects) for the exact
boundary before you rely on it.

## Verifying on your own machine

`go test ./...` (or `make test`) covers everything up to the plugin boundary, and needs no
external toolchain. `cmd/age-plugin-av/main_test.go` builds `avd` and `age-plugin-av`, runs
an ephemeral daemon against an ephemeral vault, puts the plugin on `PATH` under the name age
discovers it by, and decrypts through it — a standard `age1` file, a two-pointer `keys.txt`
where the file is encrypted only to the second key, a stale pointer falling through, the
locked-vault message, and the dangerous-tier message. `internal/daemon/sops_rpc_test.go`
covers the `sops_unwrap` RPC beneath it, and `cmd/av/sops_import_test.go` covers
`av sops import` rewriting the `keys.txt` it read from. All of it runs in CI.

**The real `sops`, `helm secrets` and `kustomize`+ksops binaries are a manual step.** The
scripted harness that used to drive them is no longer in this repository, so there is no
command to run here — check them by hand, against a scratch directory rather than your real
`keys.txt`:

1. `av sops keygen scratch`, and place the recipient and pointer it prints into a scratch
   `.sops.yaml` and `keys.txt`.
2. Encrypt and decrypt a throwaway file with `sops` — the round trip is the check.
3. Re-wrap it with `sops updatekeys` as in [Rotation](#rotation) above.
4. Run `helm secrets template` and `kustomize build --enable-alpha-plugins --enable-exec`
   over the same file.
5. `av sops rm scratch` when you are done.

Point `AV_SOCKET_PATH` at a temp path first if you would rather do this against an isolated
daemon than your real one.

### Platform status

| Platform | Status |
|---|---|
| Linux | CI (`.github/workflows/ci.yml`) runs `make test`, `make vet` and `make cross-test` on every push and pull request, and it is **green**. That covers the plugin end-to-end path — a real `avd`, the real `age-plugin-av` found off `PATH`, a standard `age1` file, a two-pointer `keys.txt`, the locked-vault and dangerous-tier messages — plus `av sops import` and the `sops_unwrap` RPC underneath. The job installs **no external toolchain**, so it does not run `sops`, `helm secrets` or `kustomize`+ksops at all. |
| macOS | `go test ./...` by hand, plus the manual toolchain checks above. There is no macOS CI job: Secure Enclave and Touch ID are unreachable on a hosted runner, which is where the macOS-only risk actually lives, so a job could only re-run what Linux already covers. |
| Windows | CI runs `go test ./...` on `windows-latest` and it is **green**. Plugin discovery through age's `exec.LookPath` (the reason the Makefile emits `age-plugin-av.exe`), named-pipe transport, `AV_SOCKET_PATH`, and the daemon end-to-end path — `cmd/age-plugin-av`'s test drives a real `avd` over a real pipe and decrypts through the real plugin — all pass. But note the ceiling: **`avd` only runs on Windows with `AV_TEST_AUTH=allow`**, so what CI proves there is the transport and plugin machinery, not a usable product. See [Windows: what is skipped](#windows-what-is-skipped). |
| Any | `sops`, `helm secrets` and `kustomize`+ksops against the plugin are **proven nowhere**. They are expected to work and were checked by hand during development, but no automated run in this repository exercises them on any platform. |

### Pointing `av` and `avd` at one endpoint: `AV_SOCKET_PATH`

`AV_SOCKET_PATH` overrides the daemon endpoint. Every process in the chain — `av`, `avd`
and `age-plugin-av` — resolves its endpoint through the same function, so setting this one
variable puts them all on a private endpoint together. That is what an **isolated
instance** is: an ephemeral daemon running beside the user's real one — what the daemon
end-to-end tests need, and what to reach for when checking the toolchain by hand without
touching your real vault.

| Platform | Default endpoint | Value of the override |
|---|---|---|
| Linux / macOS | `$XDG_RUNTIME_DIR/agentvault/avd.sock`, else `<user-cache-dir>/agentvault/avd.sock` | The unix socket path. Still subject to the ~104-byte `sun_path` limit. |
| Windows | `%LOCALAPPDATA%\AgentVault\avd.pipe` | The *logical* path. The named pipe is derived from it by hash, and its parent dir holds the lockfile and audit log — so two override paths are two fully independent instances, same as on Unix. |

On Unix an isolated instance could always be had by pointing `$XDG_RUNTIME_DIR` at a temp
dir. Windows has no equivalent of that variable, so before `AV_SOCKET_PATH` existed there
was **no way to run a second instance there at all** — which is also why the daemon
end-to-end tests could not work on Windows: they set `$XDG_RUNTIME_DIR` and dialled a path
derived from it, while the `avd` they spawned resolved `%LOCALAPPDATA%` and listened on a
different pipe.

An empty `AV_SOCKET_PATH` is treated as unset, so an exported-but-empty variable in a shell
profile cannot send the daemon somewhere strange.

### Windows: what is skipped

`make cross-test` only ever cross-compiled, so nothing in this suite had run on Windows
until CI did it. That first run failed 21 tests. None was a regression, and all are now
fixed except two assertions that cannot be expressed on NTFS:

1. **Permission-bit assertions** are skipped. Go can only ever report `0666`/`0444` for a
   file and `0777` for a directory on Windows (`$GOROOT/src/os/types_windows.go`), so
   `0600`/`0700`/`0755` are not expressible. The `requirePerm` helper each package carries
   skips only the *mode* comparison — the file-exists half still runs, so a file that was
   never written still fails the test on Windows. The production `chmod` calls are
   unchanged and remain load-bearing on Unix.
2. **`TestAddFailureLeavesOriginalIntact`** (`internal/backend/agefile`) is skipped. The
   invariant it guards — a failed `Add` never touches the live vault — is
   platform-neutral, but the way the test *provokes* the failure is not: `os.Chmod` on
   Windows sets only the read-only attribute, and on a directory that attribute does not
   deny file creation, so the temp file is still creatable and there is no failed write to
   assert about. Denying it for real needs an NTFS DACL, which Go's `os` package cannot
   express.

3. **`TestE2ELockedRunFails`** (`internal/client`) is skipped, and this one is the
   important skip. It needs an `avd` started with **no** auth configured, and on Windows
   such an `avd` does not start at all: `selectPresence()` in `cmd/avd/main.go` treats a
   missing presence provider as fatal — "avd must never run without a real presence
   check" — and `newTouchIDPresence` in `internal/daemon/presence_windows.go` *always*
   errors, because the Windows Hello WinRT bridge is not implemented. The only
   configuration in which `avd` runs on Windows today is `AV_TEST_AUTH=allow`, which is
   exactly the state this test must avoid.

**The headline Windows limitation is (3), not the mode bits.** AgentVault's daemon has no
presence provider on Windows, so it cannot be run there outside tests: every green Windows
test that spawns a daemon does so with the test stub. Plugin discovery, the named-pipe
transport, `AV_SOCKET_PATH`, and the SOPS decrypt path are genuinely proven; a usable
Windows product needs Windows Hello implemented first.

The security property behind (1) — owner-only files — also still needs a real expression on
Windows via ACLs. Both remain open risks, and neither is something a test can assert today.

### For maintainers: the Formula still omits the plugin

`brew install` resolves to a Formula in the external tap **`bshk-app/homebrew-tap`**, which
this repository does not contain. Until that tap's `bin.install` names `age-plugin-av`, a
Formula install produces a working `av`, a working `avd`, and **no plugin** — and the
failure that follows reads like a key problem, not a missing file. This is a release blocker
for the SOPS feature.

Everything inside this repository is done: the `Makefile`, `scripts/release-signed.sh`, and
`packaging/agentvault-cask.json` all build and ship the binary, and both CI workflows
delegate to the release script and name no binary.

> **Tap naming, unresolved.** `README.md` tells users `brew install
> beshkenadze/tap/agentvault`, while `docs/getting-started.md`,
> `docs/signing-and-notarization.md`, `docs/gitea-cicd.md`, and both CI workflows all name
> `bshk-app/homebrew-tap` — the tap that actually holds the Formula. The README may be an
> intentional alias; it has been left alone deliberately. Someone should confirm which is
> correct and make the two agree.
