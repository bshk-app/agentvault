#!/usr/bin/env bash
# End-to-end smoke for the Homebrew-installed av/avd against the age-file backend.
#
# It is fully ISOLATED and EPHEMERAL: an isolated socket (temp $XDG_RUNTIME_DIR), the
# AV_TEST_AUTH=allow presence stub (no Touch ID prompt), an own avd it starts and
# kills, and a temp vault — it touches none of your real session and leaves nothing
# running. Re-runnable.
#
# Requires: brew-installed `av` + `avd` on PATH, a Go toolchain, and this repo (the
# one-time vault seeder, ./cmd/smoke-seed). Run:  bash scripts/smoke-e2e.sh
set -uo pipefail

REPO="${REPO:-/Volumes/DATA/agent-vault}"
AV="$(command -v av || true)"
AVD="$(command -v avd || true)"
[ -n "$AV" ] && [ -n "$AVD" ] || { echo "av/avd not on PATH (brew install bshk-app/homebrew-tap/agentvault)"; exit 1; }

PASS=0; FAIL=0
ok(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
no(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }

WORK="$(mktemp -d)"
export XDG_RUNTIME_DIR="$WORK/run"; mkdir -p "$XDG_RUNTIME_DIR"
export AV_TEST_AUTH=allow
export AV_AGE_IDENTITY="$WORK/id.txt"
export AV_AGE_VAULT="$WORK/vault.age"
SOCK="$XDG_RUNTIME_DIR/agentvault/avd.sock"

# Seed values the script knows so it can assert masking. Deliberately ARBITRARY (not a
# known token shape) so the run/scrub masking can only come from session exact-match —
# isolating that layer from gitleaks (tested separately with a real ghp_ shape below).
TOKVAL="SMOKEtokenARBITRARYvalue-not-a-pattern-0001"
STRVAL="STRIPEarbitrarySECRET-not-a-pattern-0002"

cleanup(){
  [ -n "${AVD_PID:-}" ] && kill "$AVD_PID" 2>/dev/null
  [ -n "${AVD_PID:-}" ] && wait "$AVD_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "av   = $AV"
echo "avd  = $AVD"
echo "work = $WORK"
echo

# 1) Seed an age identity + encrypted vault (reuses agefile.EncryptVault).
( cd "$REPO" && go run ./cmd/smoke-seed "$AV_AGE_IDENTITY" "$AV_AGE_VAULT" \
    "GITHUB_TOKEN=$TOKVAL" "STRIPE_SECRET=$STRVAL" ) \
  || { echo "seed failed"; exit 1; }

# 2) Project manifest (profile 'smoke': one normal + one dangerous entry).
cat > "$WORK/agentvault.yaml" <<'YAML'
profiles:
  smoke:
    GITHUB_TOKEN:
      ref: av://file/GITHUB_TOKEN
      tier: normal
    STRIPE_SECRET:
      ref: av://file/STRIPE_SECRET
      tier: dangerous
YAML

# 3) Start an ephemeral avd and wait for it to bind the isolated socket.
"$AVD" >"$WORK/avd.log" 2>&1 &
AVD_PID=$!
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "avd did not bind socket; log:"; cat "$WORK/avd.log"; exit 1; }

cd "$WORK"
echo "--- assertions ---"

# ping reaches the daemon
"$AV" ping >/dev/null 2>&1 && ok "av ping reaches daemon" || no "av ping"

# fresh session is locked
st="$("$AV" status 2>&1)"; case "$st" in locked*) ok "status: locked before unlock";; *) no "status before unlock (got: $st)";; esac

# unlock via the stub presence (no Touch ID)
"$AV" unlock >/dev/null 2>&1 && ok "av unlock (stub auth)" || no "av unlock"

# normal-tier: av run injects the value and masks it at the source
out="$("$AV" run --profile smoke -- sh -c 'printf "T=%s\n" "$GITHUB_TOKEN"' 2>>"$WORK/av.err")"
[ "$out" = "T={{AV:GITHUB_TOKEN}}" ] && ok "run masks normal-tier value -> {{AV:GITHUB_TOKEN}}" || no "run mask (got: '$out')"
case "$out" in *"$TOKVAL"*) no "LEAK: real token in run output";; *) ok "no plaintext token in run output";; esac

# dangerous-tier: still masked (stub grants the fresh-presence check)
out="$("$AV" run --profile smoke -- sh -c 'printf "S=%s\n" "$STRIPE_SECRET"' 2>>"$WORK/av.err")"
[ "$out" = "S={{AV:STRIPE_SECRET}}" ] && ok "run masks dangerous-tier value -> {{AV:STRIPE_SECRET}}" || no "dangerous mask (got: '$out')"

# av read into a pipe (non-TTY) must REFUSE (exit 80) and print no value
rout="$("$AV" read GITHUB_TOKEN 2>/dev/null)"; rc=$?
[ "$rc" -eq 80 ] && ok "read refuses non-TTY (exit 80)" || no "read refusal exit (got $rc)"
case "$rout" in *"$TOKVAL"*) no "LEAK: read leaked value to pipe";; *) ok "read printed no value to a pipe";; esac

# scrub layer-2 exact-match: the issued session value is masked in arbitrary text
sout="$(printf 'before %s after\n' "$TOKVAL" | "$AV" scrub 2>/dev/null)"
case "$sout" in *"{{AV:GITHUB_TOKEN}}"*) ok "scrub exact-match masks issued value";; *) no "scrub exact (got: '$sout')";; esac
case "$sout" in *"$TOKVAL"*) no "LEAK: scrub left plaintext";; *) ok "scrub left no plaintext";; esac

# scrub gitleaks: a DERIVED token (never issued) is caught by the detector
derived="ghp_DERIVEDtoken9876543210ZYXWVUTSRQPO12"   # GitHub-PAT shape, 36 chars
gout="$(printf 'jwt=%s\n' "$derived" | "$AV" scrub 2>/dev/null)"
case "$gout" in *"{{AV:REDACTED:"*) ok "scrub (gitleaks) masks a derived token";; *) no "gitleaks mask (got: '$gout')";; esac
case "$gout" in *"$derived"*) no "LEAK: gitleaks missed derived token";; *) ok "no plaintext derived token after scrub";; esac

# lock re-locks the session
"$AV" lock >/dev/null 2>&1 && ok "av lock" || no "av lock"
st="$("$AV" status 2>&1)"; case "$st" in locked*) ok "status: locked after lock";; *) no "status after lock (got: $st)";; esac

echo
echo "==== $PASS passed, $FAIL failed ===="
if [ "$FAIL" -ne 0 ]; then echo "--- avd.log ---"; cat "$WORK/avd.log"; fi
[ "$FAIL" -eq 0 ]
