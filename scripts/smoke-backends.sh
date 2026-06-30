#!/usr/bin/env bash
# Real-backend smoke for the Homebrew-installed av/avd:
#   * macOS Keychain  — fully self-contained (adds a throwaway item, then deletes it)
#   * 1Password       — tested only if you pass OP_REF='Vault/Item/field'
#
# Auth defaults to the AV_TEST_AUTH=allow stub (no Touch ID) so the BACKEND wiring can
# be validated on its own. Set REAL_AUTH=1 to use the REAL Touch ID path: `av unlock`
# then prompts the sensor (and dangerous-tier resolves prompt per access).
#
# It is isolated/ephemeral: its own avd on a temp socket, torn down on exit; touches
# none of your real session. Re-runnable.
#
# Usage:
#   bash scripts/smoke-backends.sh                                  # keychain, stub auth
#   OP_REF='AgentVault-Test/smoke/password' bash scripts/smoke-backends.sh   # + 1Password
#   REAL_AUTH=1 OP_REF='AgentVault-Test/smoke/password' bash scripts/smoke-backends.sh
#
# For 1Password you must be signed in first (`op signin`, or the desktop-app CLI
# integration). The avd this script starts inherits that session from your shell.
set -uo pipefail

AV="$(command -v av || true)"; AVD="$(command -v avd || true)"
[ -n "$AV" ] && [ -n "$AVD" ] || { echo "av/avd not on PATH (brew install bshk-app/homebrew-tap/agentvault)"; exit 1; }
[ "$(uname -s)" = "Darwin" ] || { echo "real backends (Keychain/Touch ID) are macOS-only"; exit 1; }

PASS=0; FAIL=0
ok(){   printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
no(){   printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
info(){ printf '  \033[33m..\033[0m %s\n' "$1"; }

WORK="$(mktemp -d)"
export XDG_RUNTIME_DIR="$WORK/run"; mkdir -p "$XDG_RUNTIME_DIR"
SOCK="$XDG_RUNTIME_DIR/agentvault/avd.sock"

REAL_AUTH="${REAL_AUTH:-0}"
if [ "$REAL_AUTH" = "1" ]; then
  unset AV_TEST_AUTH
  AUTHDESC="real Touch ID"
else
  export AV_TEST_AUTH=allow
  AUTHDESC="stub (AV_TEST_AUTH=allow)"
fi

# Throwaway keychain item. Value is ARBITRARY (not a token shape) so masking can only
# come from session exact-match — proving the value was resolved and replaced wholesale.
KC_SVC="av-smoke-$$"
KC_VAL="KEYCHAINsmokeVALUE-$$-not-a-pattern"

cleanup(){
  [ -n "${AVD_PID:-}" ] && kill "$AVD_PID" 2>/dev/null
  [ -n "${AVD_PID:-}" ] && wait "$AVD_PID" 2>/dev/null
  security delete-generic-password -s "$KC_SVC" -a token >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "av   = $AV"
echo "avd  = $AVD"
echo "auth = $AUTHDESC"
echo "work = $WORK"
echo

# Manifest: one profile per backend so a missing/failing backend can't fail the others.
{
  echo "profiles:"
  echo "  kc:"
  echo "    KC:"
  echo "      ref: av://keychain/$KC_SVC/token"
  echo "      tier: normal"
  if [ -n "${OP_REF:-}" ]; then
    echo "  op:"
    echo "    OP:"
    echo "      ref: av://1p/$OP_REF"
    echo "      tier: normal"
  fi
} > "$WORK/agentvault.yaml"

# Seed the keychain item. -A lets the (same) `security` binary read it via -w without a
# GUI access prompt; -U updates in place if a stale item exists.
security add-generic-password -U -A -s "$KC_SVC" -a token -w "$KC_VAL" \
  || { echo "could not add keychain test item"; exit 1; }

# Start the ephemeral avd (real or stub presence per env) and wait for the socket.
"$AVD" >"$WORK/avd.log" 2>&1 &
AVD_PID=$!
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "avd did not bind socket; log:"; cat "$WORK/avd.log"; exit 1; }

cd "$WORK"
echo "--- assertions ---"

# Unlock — REAL mode fires the Touch ID prompt here.
[ "$REAL_AUTH" = "1" ] && printf '\033[1;36m  >>> Touch the sensor to unlock AgentVault…\033[0m\n'
if "$AV" unlock >/dev/null 2>&1; then ok "av unlock ($AUTHDESC)"; else no "av unlock — see $WORK/avd.log"; fi

# --- Keychain backend (real `security`) ---
out="$("$AV" run --profile kc -- sh -c 'printf "K=%s\n" "$KC"' 2>>"$WORK/av.err")"
[ "$out" = "K={{AV:KC}}" ] && ok "keychain resolve + mask -> {{AV:KC}}" || no "keychain (got: '$out')"
case "$out" in *"$KC_VAL"*) no "LEAK: keychain value in output";; *) ok "no plaintext keychain value";; esac

# --- 1Password backend (real `op`), optional ---
if [ -n "${OP_REF:-}" ]; then
  if op whoami >/dev/null 2>&1; then
    out="$("$AV" run --profile op -- sh -c 'printf "O=%s\n" "$OP"' 2>>"$WORK/av.err")"
    if [ "$out" = "O={{AV:OP}}" ]; then
      ok "1password resolve + mask -> {{AV:OP}}  (op://$OP_REF)"
    else
      no "1password (got: '$out' | last err: $(tail -n1 "$WORK/av.err" 2>/dev/null))"
    fi
  else
    info "skipped 1Password: 'op whoami' failed — run 'op signin' first"
  fi
else
  info "skipped 1Password: pass OP_REF='Vault/Item/field' to test it"
fi

if "$AV" lock >/dev/null 2>&1; then ok "av lock"; else no "av lock"; fi

echo
echo "==== $PASS passed, $FAIL failed ===="
if [ "$FAIL" -ne 0 ]; then echo "--- avd.log ---"; cat "$WORK/avd.log"; [ -f "$WORK/av.err" ] && { echo "--- av.err ---"; cat "$WORK/av.err"; }; fi
[ "$FAIL" -eq 0 ]
