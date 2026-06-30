# Signing & notarization (maintainer guide)

How to produce the **signed, notarized** AgentVault release that unlocks the Secure
Enclave key tier. This is a maintainer/release task, not something end users do.

## Two goals — don't conflate them

| Goal | Buys | Needs |
|------|------|-------|
| **Sign + notarize** | no Gatekeeper "unidentified developer" warning | Developer ID Application cert, hardened runtime, `notarytool` |
| **Unlock the Secure Enclave tier** | `av setup` picks the Enclave; key never leaves hardware | the above **+ an App ID + a Developer ID provisioning profile embedded in an app-like bundle** |

Notarization alone does **not** unlock the Enclave. Creating an Enclave key
(`SecKeyCreateRandomKey` + `kSecAttrTokenIDSecureEnclave`, see
`internal/enclave/enclave_darwin.m`) fails with `errSecMissingEntitlement` (-34018)
unless the binary carries `com.apple.application-identifier` **authorized by an embedded
provisioning profile** — and a bare Mach-O has nowhere to hold a profile.

**Only `avd` touches the Enclave.** So only `avd` is wrapped in an app-like bundle with a
profile; `av` ships as a bare, signed binary.

## One-time Apple setup

1. **Developer ID Application certificate.** Create a CSR (Keychain Access → Certificate
   Assistant), upload at developer.apple.com → Certificates, download, double-click to
   install in your login keychain. Confirm and note your Team ID:

   ```sh
   security find-identity -p codesigning -v
   # "Developer ID Application: Jane Doe (ABCDE12345)"  → DEV_ID, and TEAM_ID=ABCDE12345
   ```

2. **notarytool credentials** (so secrets never hit argv):

   ```sh
   xcrun notarytool store-credentials AgentVault \
     --apple-id you@example.com --team-id ABCDE12345 --password <app-specific-password>
   ```

   An app-specific password comes from appleid.apple.com → Sign-In & Security.

3. **App ID + Developer ID provisioning profile** (for the Enclave):
   - developer.apple.com → Identifiers → register App ID `app.bshk.agentvault`.
   - Profiles → **Developer ID** → create a profile for that App ID → download.
   - Save it to `packaging/agentvault.provisionprofile` (git-ignored — account-specific).

   > Developer ID provisioning profiles **expire**. When the profile expires you must
   > re-run the release (re-embed the fresh profile) and ship a new build.

## Release: one command

The whole pipeline is `scripts/release-signed.sh` — build (CGO) → assemble the `avd`
bundle (Info.plist + `embedded.provisionprofile` + entitlements) → codesign (hardened
runtime + timestamp) → notarize `av` and the bundle → staple the bundle → package a
tarball and print its sha256.

```sh
TEAM_ID=ABCDE12345 \
DEV_ID="Developer ID Application: Jane Doe (ABCDE12345)" \
NOTARY_PROFILE=AgentVault \
./scripts/release-signed.sh v0.3.0
```

Inputs it expects:

- `packaging/avd.entitlements.template` — `__TEAM_ID__` → `com.apple.application-identifier`
  + `keychain-access-groups`.
- `packaging/avd.app.Info.plist.template` — `__VERSION__`; `CFBundleIdentifier`
  `app.bshk.agentvault` (must match the entitlement suffix).
- `packaging/agentvault.provisionprofile` — your downloaded Developer ID profile.

Output (under `dist/`, git-ignored): a signed bare `av`, a signed+stapled
`AgentVault.app` (containing `avd`), and `agentvault-v0.3.0-macos.tar.gz` + its sha256.

## Distribution: a Cask, not the Formula

The `brew install` **Formula** builds from source → ad-hoc signed → entitlements
stripped → keychain tier (and re-triggers Gatekeeper). A signed release must therefore be
a Homebrew **Cask** that carries the notarized artifact.

Keep both: the Formula is the build-from-source / keychain-tier path; the
[Cask](https://github.com/bshk-app/homebrew-tap) ships the signed / Enclave-tier
artifact. The tier is chosen at runtime, so installing the Cask upgrades protection with
no config change.

After a release, `scripts/release-signed.sh` writes `dist/manifest.json` (the
`ArtifactManifest`) alongside the tarball. Publish the cask with the generic
[`zamokctl cask`](https://github.com/beshkenadze/zamok) tool — `--store url` is a
passthrough, so the tarball stays in AgentVault's own GitHub release (no re-upload):

```sh
# 1. publish the tarball to the GitHub release (if not already):
gh release create v0.3.0 dist/agentvault-v0.3.0-macos.tar.gz --repo bshk-app/agentvault
#    (or, on an existing release: gh release upload v0.3.0 dist/agentvault-v0.3.0-macos.tar.gz)

# 2. render + push Casks/agentvault.rb to the tap (needs GITHUB_TOKEN):
zamokctl cask \
  --manifest dist/manifest.json \
  --metadata packaging/agentvault-cask.json \
  --store url --url "https://github.com/bshk-app/agentvault/releases/download/v0.3.0/agentvault-v0.3.0-macos.tar.gz" \
  --tap-host github --tap bshk-app/homebrew-tap

# 3. brew install --cask bshk-app/homebrew-tap/agentvault  then  av version → key  enclave
```

The script prints this exact command (with the real version/url filled in) at the end of a
run. Manual fallback: hand-edit the tap's `Casks/agentvault.rb` — set `version` and
`sha256` from the script output.

## Verify

```sh
codesign -d --entitlements - dist/AgentVault.app    # lists application-identifier + team-identifier
codesign --verify --strict --deep --verbose=2 dist/AgentVault.app
spctl -a -vvv -t install dist/AgentVault.app        # → accepted, source=Notarized Developer ID
xcrun stapler validate dist/AgentVault.app          # → The validate action worked!
```

On Enclave hardware, `av setup` then `av version` should report `key  enclave`.

## Troubleshooting

- **`errSecMissingEntitlement` / -34018 at `av setup`** — the profile isn't embedded or
  isn't authorizing `com.apple.application-identifier`. Check
  `codesign -d --entitlements - dist/AgentVault.app` lists it, and that
  `dist/AgentVault.app/Contents/embedded.provisionprofile` is your **Developer ID** profile
  for `app.bshk.agentvault`.
- **"works in Xcode, not from the notarized build"** — the classic missing-profile symptom;
  Xcode embeds a profile for you but a standalone build does not. The bundle + profile here
  is what replaces that.
- **`av` won't run on another Mac** — a bare Mach-O can't be stapled, so Gatekeeper checks
  notarization **online** on first run. If that machine is offline, ship inside a stapled
  `.pkg`/`.dmg` instead (a `.pkg` needs a separate *Developer ID Installer* certificate).
- **Profile expired** — re-download and re-run `scripts/release-signed.sh`.

## See also

- [Security model → identity protection tiers](security-model.md#identity-protection-tiers)
- [Running avd as a LaunchAgent](launchagent.md)
- Apple: [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave),
  [Definitive rules for Secure Enclave on macOS](https://developer.apple.com/forums/thread/786171)
