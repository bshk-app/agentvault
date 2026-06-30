#!/usr/bin/env bash
#
# manual-touchid-smoke.sh — the ONLY real verification of the cgo work in Phase 5.
#
# Tasks 5-7 (Touch ID via LocalAuthentication, the per-user LaunchAgent, and
# auto-lock observers) are compile-verified by the test suite but a biometric
# prompt and a screen-lock event CANNOT be exercised by automated tests. A green
# `go build` proves the cgo COMPILES — not that Touch ID works. This script drives
# the human-in-the-loop steps that actually prove it.
#
# It runs the non-interactive parts (build, install the LaunchAgent) for you and
# then PAUSES at each step that needs a human (touch the sensor, cancel a prompt,
# lock the screen). Run it on the Mac whose Touch ID you want to verify.
#
# Usage:  bash scripts/manual-touchid-smoke.sh
#
# Prereqs: a Mac with Touch ID, an age identity + vault for the file backend
# (or set AV_AGE_IDENTITY / AV_AGE_VAULT to existing ones before running).

set -euo pipefail

# --- locate the repo root (this script lives in scripts/) --------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

LABEL="app.bshk.agentvault.avd"
PLIST_SRC="$REPO_ROOT/packaging/${LABEL}.plist"
PLIST_DST="$HOME/Library/LaunchAgents/${LABEL}.plist"
INSTALL_DIR="$HOME/bin"
LOG_DIR="$HOME/Library/Logs/agentvault"

# Default backend paths (override by exporting AV_AGE_IDENTITY / AV_AGE_VAULT).
AGE_IDENTITY="${AV_AGE_IDENTITY:-$HOME/.config/agentvault/identity.txt}"
AGE_VAULT="${AV_AGE_VAULT:-$HOME/.config/agentvault/vault.age}"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m%s\033[0m\n' "$*"; }
pause() { printf '\n'; read -r -p "    [press Enter when done] " _; }

if [[ "$(uname -s)" != "Darwin" ]]; then
	warn "This script only verifies the macOS Touch ID path; you are not on Darwin."
	exit 1
fi

bold "AgentVault — Touch ID / LaunchAgent / auto-lock manual smoke test"
bold "This is the real (human) verification of Phase 5 Tasks 5-7."
echo  "Repo: $REPO_ROOT"

# --- 0. sanity: backend files exist (avd needs them to broker a secret) ------
step "0. Checking the file-backend inputs"
if [[ ! -f "$AGE_IDENTITY" || ! -f "$AGE_VAULT" ]]; then
	warn "Missing age identity ($AGE_IDENTITY) or vault ($AGE_VAULT)."
	warn "Set AV_AGE_IDENTITY / AV_AGE_VAULT to existing files, or create them, then re-run."
	warn "(The Touch ID prompt itself does NOT need them, but a full unlock+resolve does.)"
fi

# --- 1. build (cgo ON so the real Touch ID + auto-lock backends are linked) ---
step "1. Building av + avd with cgo enabled (real Touch ID backend)"
mkdir -p "$INSTALL_DIR" "$LOG_DIR"
CGO_ENABLED=1 go build -o "$INSTALL_DIR/avd" ./cmd/avd
CGO_ENABLED=1 go build -o "$INSTALL_DIR/av"  ./cmd/av
echo "    installed: $INSTALL_DIR/avd  $INSTALL_DIR/av"
warn "    Make sure $INSTALL_DIR is on your PATH for the 'av' commands below."

# --- 2. install + load the per-user LaunchAgent (GUI session) ----------------
step "2. Installing the per-user LaunchAgent (see docs/launchagent.md)"
mkdir -p "$(dirname "$PLIST_DST")"
sed \
	-e "s|__AVD_PATH__|$INSTALL_DIR/avd|" \
	-e "s|__AGE_IDENTITY_FILE__|$AGE_IDENTITY|" \
	-e "s|__AGE_VAULT_FILE__|$AGE_VAULT|" \
	-e "s|__LOG_DIR__|$LOG_DIR|" \
	"$PLIST_SRC" > "$PLIST_DST"
echo "    wrote $PLIST_DST"

# Reload cleanly: bootout an old instance (ignore errors) then bootstrap.
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST_DST"
echo "    bootstrapped into gui/$(id -u)"
launchctl print "gui/$(id -u)/$LABEL" 2>/dev/null | grep -E "state =" || true
warn "    NOTE: it MUST be a LaunchAgent in the GUI session — a LaunchDaemon cannot"
warn "    present the Touch ID prompt (av unlock would always return 'locked')."

# --- 3. baseline status (no secret values are ever printed) -------------------
step "3. Baseline: av status (expect 'locked')"
"$INSTALL_DIR/av" status || true

# --- 4. MANUAL: av unlock -> real Touch ID prompt, touch to unlock -----------
step "4. MANUAL — Touch ID success (Task 5)"
cat <<'EOF'
    In ANOTHER terminal (or after this prompt), run:

        av unlock

    EXPECT: a real Touch ID dialog reading "Unlock AgentVault".
    Touch the sensor.
    EXPECT: command prints "unlocked for 15m" and exits 0.
    Then run:  av status   -> EXPECT "unlocked, ~15m remaining".
EOF
pause
bold "    Recording: did Touch ID prompt appear AND unlock succeed? (note it)"
"$INSTALL_DIR/av" status || true

# --- 5. MANUAL: av unlock -> cancel -> exit 69/77 ----------------------------
step "5. MANUAL — Touch ID cancel (Task 5)"
cat <<'EOF'
    Run again:

        av unlock

    EXPECT: the Touch ID dialog appears; press Esc / click Cancel.
    EXPECT: command fails with exit code 69 (CodeLocked) or 77 (CodeDenied)
            and a "vault locked …" / "access denied" message — NO secret value.

    Check the exit code right after:   echo $?
EOF
pause
bold "    Recording: did cancel yield exit 69 or 77 with no secret? (note it)"

# --- 6. MANUAL: screen-lock auto-lock (Task 7) -------------------------------
step "6. MANUAL — auto-lock on screen-lock (Task 7)"
cat <<'EOF'
    First unlock again so there is something to auto-lock:

        av unlock        # touch the sensor
        av status        # EXPECT unlocked

    Now LOCK THE SCREEN:  press Ctrl-Cmd-Q  (or the Lock Screen menu).
    Then log back in and run:

        av status

    EXPECT: "locked" — the screen-lock observer fired and re-locked the session.
    (If it still shows unlocked, the auto-lock run loop did not deliver the
     notification — capture avd's logs below and report it.)
EOF
pause
bold "    Recording: did av status report 'locked' after the screen-lock? (note it)"
"$INSTALL_DIR/av" status || true

# --- 7. logs + teardown hint -------------------------------------------------
step "7. avd logs (for your report — never contain secret values)"
echo "    stdout: $LOG_DIR/avd.out.log"
echo "    stderr: $LOG_DIR/avd.err.log"
[[ -f "$LOG_DIR/avd.err.log" ]] && tail -n 20 "$LOG_DIR/avd.err.log" || true

cat <<EOF

$(bold "Done.") Summarize the three MANUAL results (steps 4, 5, 6) in your report:
  - Touch ID prompt appeared and unlocked        (Task 5)
  - Cancel produced exit 69/77 with no secret    (Task 5)
  - Screen-lock auto-locked the session          (Task 7)

To uninstall the LaunchAgent when finished:

    launchctl bootout gui/\$(id -u)/$LABEL
    rm -f "$PLIST_DST"
EOF
