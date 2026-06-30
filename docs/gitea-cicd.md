# Gitea CI/CD for the signed release (self-hosted macOS runner)

Run the whole AgentVault release — build → Developer-ID sign → notarize → staple →
tarball → publish the Homebrew **cask** via `zamokctl` — inside your **local Gitea** on a
**self-hosted macOS runner** (alex-mac). This is the best place to exercise the flow
end-to-end *before* the public GitHub tap: signing must run on a Mac, and `zamokctl cask`
has no dry-run (render+push is one shot), so a private Gitea tap is your safe first run.

Workflow: [`.gitea/workflows/release.yml`](../.gitea/workflows/release.yml).

## Why self-hosted

A GitHub-hosted runner would need the Developer ID cert imported into a temp keychain
every run. alex-mac already has the cert in its login keychain, so signing "just works" —
the workflow only injects the account-specific *provisioning profile* + notary creds.

## One-time setup

### 1. Repos in your Gitea
- **`<owner>/agent-vault`** — push this repo here (e.g. add a `gitea` remote and push the
  branch/tag). Gitea Actions runs `.gitea/workflows/` automatically.
- **`<owner>/homebrew-tap`** — create it empty. `zamokctl` creates `Casks/` on first push.

### 2. The runner (alex-mac)
- Register a Gitea Act runner on alex-mac and note its **label**; set `runs-on:` in the
  workflow to match (the template uses `macos-latest`).
- Install zamokctl once (the workflow also self-installs if missing):
  ```sh
  brew tap zamok/zamok https://git.YOUR-HOST/zamok/homebrew-zamok.git
  brew install zamok/zamok/zamokctl
  ```
- Confirm the Developer ID cert is present and note the Team ID:
  ```sh
  security find-identity -p codesigning -v   # "Developer ID Application: NAME (TEAMID)"
  ```
- The runner must execute in a session where the login keychain is unlocked (so `codesign`
  and `notarytool` can read the identity). Running the runner as your GUI user is simplest.

### 3. Edit the workflow env
In `.gitea/workflows/release.yml` set:
- `GITEA_URL` — your Gitea base URL (e.g. `https://git.bshk.app` or your truenas host).
- `TAP_REPO` — `<owner>/homebrew-tap`.
- `runs-on` — your runner's label.

### 4. Repo secrets (Gitea → agent-vault → Settings → Actions → Secrets)

| Secret | What |
|--------|------|
| `AV_TEAM_ID` | 10-char Apple Team ID |
| `AV_DEV_ID` | `Developer ID Application: NAME (TEAMID)` |
| `AV_PROVISION_PROFILE` | base64 of your Developer ID provisioning profile (`base64 -i agentvault.provisionprofile`) |
| `AV_NOTARY_KEY_P8` | base64 of your App Store Connect API key `.p8` |
| `AV_NOTARY_KEY_ID` / `AV_NOTARY_ISSUER_ID` | the key id + issuer UUID |
| `AV_TAP_TOKEN` | a Gitea PAT with **write** to both `agent-vault` (release asset) and `homebrew-tap` (the `.rb`) |

> If alex-mac already has the notary profile stored (`xcrun notarytool store-credentials
> AgentVault …`), delete the "Store notarytool credentials" step and the `AV_NOTARY_*`
> secrets — the workflow will use the pre-stored profile.

## Run it

```sh
git tag v0.1.0 && git push gitea v0.1.0     # triggers the workflow on the tag
# or: Gitea → Actions → release → Run workflow → version v0.1.0
```

Then install from your Gitea tap:
```sh
brew tap <owner>/homebrew-tap https://git.YOUR-HOST/<owner>/homebrew-tap.git
brew install --cask <owner>/homebrew-tap/agentvault
av --version
```

## What each step does

1. **Fetch sources** — curl the repo tarball (no `actions/checkout`/node needed; the
   proven pattern on this runner infra).
2. **Ensure zamokctl** — install on demand if absent.
3. **Provisioning profile + notary creds** — decode account-specific material from secrets.
4. **`release-signed.sh`** — CGO build of `av` + `avd`, wrap `avd` in `AgentVault.app` with
   the embedded profile, Developer-ID sign (hardened runtime + timestamp), notarize, staple,
   tarball, and emit `dist/manifest.json`.
5. **`zamokctl cask`** — render `Casks/agentvault.rb` from `manifest.json` +
   `packaging/agentvault-cask.json`, upload the tarball to this repo's Gitea release
   (`--store git-release`), and push the `.rb` to the tap (`--tap-host gitea`).
6. **Cleanup** — wipe the provisioning profile + API key (the self-hosted workspace persists).

## Promoting to the public GitHub tap

Once the Gitea run is green, the same artifact publishes to GitHub by swapping the publish
step's flags (no rebuild): `--tap-host github --tap bshk-app/homebrew-tap` with a
`GITHUB_TOKEN`, and `--store url --url <github-release-url>` (or `--store git-release
--asset-repo beshkenadze/agent-vault`). See `docs/signing-and-notarization.md`.

## Troubleshooting

- **`no codesigning identity for team …`** — the cert isn't in the runner's keychain, or the
  keychain is locked for the runner's session. Check `security find-identity -p codesigning -v`
  as the runner user.
- **notarization hangs/fails** — `notarytool` needs network + valid creds; check the
  `AV_NOTARY_*` secrets or the pre-stored profile.
- **`zamokctl cask` push 401/403** — `AV_TAP_TOKEN` lacks write to the tap or the asset repo.
- **cask installs but won't open** — the `.app` wasn't notarized/stapled (a cask quarantines
  the app); confirm `release-signed.sh` completed notarization (`xcrun stapler validate`).
