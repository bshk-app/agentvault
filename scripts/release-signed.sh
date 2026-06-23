#!/usr/bin/env bash
# Build the UNSIGNED AgentVault artifacts, then hand the whole signing half to `zamokctl
# package` — it codesigns avd.app with the Secure-Enclave entitlements + provisioning profile,
# signs + notarizes the bare `av`, staples the app, tars both into one cask download, and writes
# manifest.json. One tool, one pass; this script no longer runs codesign/notarytool/stapler itself.
#
# WHY a bundle: creating a Secure Enclave key (SecKeyCreateRandomKey +
# kSecAttrTokenIDSecureEnclave, see internal/enclave/enclave_darwin.m) requires the
# com.apple.application-identifier entitlement AUTHORIZED BY A PROVISIONING PROFILE, and a bare
# Mach-O has nowhere to hold a profile. So `avd` is wrapped in an app-like bundle and zamokctl
# embeds the profile (--provisioning-profile) right before signing. `av` never calls SecKey, so
# it ships as a bare, signed+notarized binary (no entitlements, never stapled).
#
# Prereqs:
#   - zamokctl on PATH                          (brew install beshkenadze/tap/zamokctl)
#   - Developer ID Application cert in the login keychain   (security find-identity -p codesigning -v)
#   - notarytool keychain profile               (xcrun notarytool store-credentials <NOTARY_PROFILE>)
#   - a Developer ID provisioning profile authorizing the App ID's entitlements, at $PROFILE_PATH
#
# Usage:  SIGN_IDENTITY_SHA1=<40-hex> TEAM_ID=ABCDE12345 NOTARY_PROFILE=AgentVault \
#         ./scripts/release-signed.sh [VERSION]
set -euo pipefail

# ---- config (override via env) ---------------------------------------------------------
TEAM_ID="${TEAM_ID:-__TEAM_ID__}"                            # 10-char Apple Team ID (entitlements subst)
SIGN_IDENTITY_SHA1="${SIGN_IDENTITY_SHA1:-}"                 # 40-hex Developer ID Application SHA-1
NOTARY_PROFILE="${NOTARY_PROFILE:-AgentVault}"               # notarytool store-credentials name
PROFILE_PATH="${PROFILE_PATH:-packaging/agentvault.provisionprofile}"
VERSION="${1:-$(git describe --tags --always 2>/dev/null || echo dev)}"
VER="${VERSION#v}"                                           # CFBundle* / Cask want no leading 'v'

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
APP="$DIST/AgentVault.app"
TARBALL="$DIST/AgentVault-${VER}.tar.gz"                     # zamokctl names it <appBundle>-<shortVersion>.tar.gz

# ---- preflight -------------------------------------------------------------------------
[ "$TEAM_ID" = "__TEAM_ID__" ] && { echo "set TEAM_ID / SIGN_IDENTITY_SHA1 / NOTARY_PROFILE — see docs/signing-and-notarization.md" >&2; exit 2; }
[ -n "$SIGN_IDENTITY_SHA1" ]   || { echo "set SIGN_IDENTITY_SHA1 (security find-identity -p codesigning -v)" >&2; exit 2; }
[ -f "$PROFILE_PATH" ]         || { echo "missing provisioning profile at $PROFILE_PATH" >&2; exit 2; }
command -v zamokctl >/dev/null || { echo "zamokctl not on PATH — brew install beshkenadze/tap/zamokctl" >&2; exit 2; }

rm -rf "$DIST"; mkdir -p "$APP/Contents/MacOS"

# ---- build (CGO for the Touch ID / Enclave / Keychain cgo paths) — UNSIGNED ------------
echo "==> building $VERSION (unsigned; zamokctl signs)"
CGO_ENABLED=1 go build -ldflags "-X main.version=$VERSION" -o "$DIST/av"                "$ROOT/cmd/av"
CGO_ENABLED=1 go build -ldflags "-X main.version=$VERSION" -o "$APP/Contents/MacOS/avd" "$ROOT/cmd/avd"

# ---- assemble the avd bundle (Info.plist + entitlements file) ---------------------------
# NOTE: do NOT embed the provisioning profile here — zamokctl embeds it (--provisioning-profile)
# immediately before codesigning, so the signature seals it.
sed "s/__VERSION__/$VER/g"     "$ROOT/packaging/avd.app.Info.plist.template" > "$APP/Contents/Info.plist"
ENTITLEMENTS="$DIST/avd.entitlements"
sed "s/__TEAM_ID__/$TEAM_ID/g" "$ROOT/packaging/avd.entitlements.template"   > "$ENTITLEMENTS"

# ---- sign + notarize + staple + tarball + manifest — all in zamokctl --------------------
# minMacOS, bundleId, versions are read from AgentVault.app/Contents/Info.plist (single source of
# truth: LSMinimumSystemVersion / CFBundle* in avd.app.Info.plist.template), so manifest.json
# stays consistent with the bundle zamokctl just signed.
echo "==> zamokctl package (codesign avd.app w/ entitlements+profile; sign+notarize av; staple; tarball; manifest)"
zamokctl package \
  --input "$APP" \
  --extra-binary "$DIST/av" \
  --entitlements "$ENTITLEMENTS" \
  --provisioning-profile "$PROFILE_PATH" \
  --format tarball \
  --output-dir "$DIST" \
  --signing-identity-sha1 "$SIGN_IDENTITY_SHA1" \
  --notary-profile "$NOTARY_PROFILE"

SHA="$(shasum -a 256 "$TARBALL" | awk '{print $1}')"
URL="https://github.com/beshkenadze/agentvault/releases/download/${VERSION}/$(basename "$TARBALL")"

cat <<EOF

done.
  tarball  : $TARBALL
  sha256   : $SHA
  url      : $URL
  manifest : $DIST/manifest.json   (written by zamokctl package)

Next — host the tarball, then publish the Homebrew cask (artifact already hosted → --store url):
  gh release create ${VERSION} "$TARBALL" --repo beshkenadze/agentvault   # or: gh release upload ${VERSION} "$TARBALL"
  GITHUB_TOKEN=\$(gh auth token) zamokctl cask \\
    --manifest "$DIST/manifest.json" \\
    --metadata packaging/agentvault-cask.json \\
    --store url --url "$URL" \\
    --tap beshkenadze/homebrew-tap
  brew install --cask beshkenadze/tap/agentvault   # av version → key should show: enclave
EOF
