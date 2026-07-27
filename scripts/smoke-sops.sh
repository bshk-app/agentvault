#!/usr/bin/env bash
# Real-toolchain smoke for the SOPS age plugin — the ONE place the actual `sops`,
# `helm secrets` and `kustomize`+ksops binaries are driven. Every other test in this
# feature runs against the age *library*; this script is what proves the programs a user
# installs work together.
#
# ISOLATION. This runs on a real developer's machine and touches nothing of theirs:
#   * its own $HOME, $XDG_CONFIG_HOME and $XDG_RUNTIME_DIR under one temp dir, removed on
#     exit even on failure — so AgentVault's config dir, sops's keys.txt and the daemon
#     socket all resolve inside it;
#   * its own vault (AV_AGE_IDENTITY/AV_AGE_VAULT) and its own avd, started here and
#     killed here — your running daemon is never contacted;
#   * SOPS_AGE_KEY / SOPS_AGE_KEY_CMD / SOPS_AGE_RECIPIENTS are unset, so no key of yours
#     can decrypt anything for us and no encrypt can silently address your recipients;
#   * av, avd and age-plugin-av are built FROM THIS TREE into the temp dir. The released
#     binaries predate the plugin, so nothing installed is used, and nothing is replaced;
#   * the last check re-hashes your real keys.txt files and FAILS if either moved.
#
# Auth defaults to the AV_TEST_AUTH=allow stub (no Touch ID) so the TOOLCHAIN is what is
# under test. REAL_AUTH=1 uses the real presence path: `av unlock` prompts the sensor once.
# Every identity here is normal-tier, so nothing prompts per file.
#
# ASSERTING THAT THE PLUGIN RAN, not merely that sops exited 0 or non-0, is the point of
# several of these checks. A missing or misnamed binary produces a DISTINGUISHABLE error —
# `"av" plugin not found: exec: "age-plugin-av": executable file not found in $PATH` — so
# the success paths assert the decrypted plaintext and the deliberately-failing paths
# assert AgentVault's own message *and* the absence of plugin-not-found. Check 5b is the
# control that proves the discriminator works.
#
# Every check reports PASS, SKIP(absent), SKIP(broken) or FAIL and the summary keeps them
# apart: a skipped check must never read as a pass. Exit is non-zero only on a real
# failure. Re-runnable; each run is a fresh temp dir.
#
# Requires: a Go toolchain and this repo. sops 3.10+ for the plugin checks (older, or
# absent, skips them by name rather than failing obscurely). helm-secrets and ksops are
# optional and skipped when absent or unusable.
#
# AV_SMOKE_REQUIRE=sops,helm,ksops,age turns those skips into FAILURES. Skipping is the
# right answer on a developer's laptop, where a tool is missing because nobody installed
# it. It is the wrong answer in CI, where the tools are installed on purpose: there a skip
# means the INSTALL broke, and a green run that silently skipped the checks would assert
# exactly nothing while looking like proof. The tags are the ones printed in the header —
# an unknown tag is refused rather than ignored, so a typo cannot quietly require nothing.
#
# Usage:  bash scripts/smoke-sops.sh
#         REAL_AUTH=1 bash scripts/smoke-sops.sh
#         AV_SMOKE_REQUIRE=sops,helm,ksops,age bash scripts/smoke-sops.sh   # CI
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
[ "$(uname -s)" = "Windows_NT" ] && { echo "unix only (the Windows plugin path is unverified — see the plan's open risks)"; exit 1; }
command -v go >/dev/null 2>&1 || { echo "go toolchain not on PATH (this script builds av/avd/age-plugin-av from $REPO)"; exit 1; }

# --- which skips are tolerable on this run -------------------------------------------
# Each skip carries a TAG naming the tool it needed. AV_SMOKE_REQUIRE lists the tags this
# run installed on purpose; a skip carrying one of them is a broken install, not a missing
# tool, so it is collected here and turned into a non-zero exit at the end.
KNOWN_TAGS="sops helm ksops age"
REQUIRE="$(printf '%s' "${AV_SMOKE_REQUIRE:-}" | tr ',' ' ')"
for t in $REQUIRE; do
  case " $KNOWN_TAGS " in
    *" $t "*) ;;
    *) echo "AV_SMOKE_REQUIRE: unknown tag '$t' (known: $KNOWN_TAGS)" >&2; exit 2 ;;
  esac
done
REQUIRED_SKIPS=""
# note_skip TAG CHECK — records CHECK if TAG was required. Returns 0 unconditionally so
# that neither absent() nor broken() ever reports a non-zero status to its caller.
note_skip(){
  case " $REQUIRE " in
    *" $1 "*) REQUIRED_SKIPS="$REQUIRED_SKIPS
  - $2 (needs: $1)" ;;
  esac
  return 0
}

PASS=0; FAIL=0; SKIPPED_ABSENT=0; SKIPPED_BROKEN=0
SKIPS=""
ok(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
no(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
absent(){ printf '  \033[33mSKIP\033[0m %s \033[33m[tool absent: %s]\033[0m\n' "$1" "$2"; SKIPPED_ABSENT=$((SKIPPED_ABSENT+1)); SKIPS="$SKIPS
  - $1 — NOT TESTED (tool absent: $2)"; note_skip "${3:-}" "$1"; }
broken(){ printf '  \033[35mSKIP\033[0m %s \033[35m[tool installed but unusable: %s]\033[0m\n' "$1" "$2"; SKIPPED_BROKEN=$((SKIPPED_BROKEN+1)); SKIPS="$SKIPS
  - $1 — NOT TESTED (installed but unusable: $2)"; note_skip "${3:-}" "$1"; }
info(){ printf '  \033[36m..\033[0m %s\n' "$1"; }

sha(){ # sha of a file, or the literal ABSENT — so "the file is gone" is a distinct value
  [ -f "$1" ] || { echo ABSENT; return; }
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else sha256sum "$1" | awk '{print $1}'; fi
}

# run_bounded SECS OUTFILE CMD... — CMD's combined output goes to OUTFILE; returns CMD's
# exit code, or 124 if it outlived SECS.
#
# The bound is the assertion, not defensive plumbing. A plugin that blocks waiting for a
# human stalls sops, and through sops it stalls helm, with nothing to interrupt it; an
# unbounded run would report that as a hung smoke script minutes later instead of as the
# bug. macOS has no timeout(1), hence the poll. stdin is /dev/null so nothing under test
# can block reading the terminal either.
run_bounded(){
  local secs="$1" out="$2"; shift 2
  "$@" >"$out" 2>&1 </dev/null &
  local pid=$! i=0 limit=$((secs*10))
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$i" -ge "$limit" ]; then
      kill -9 "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
      return 124
    fi
    sleep 0.1; i=$((i+1))
  done
  wait "$pid"
}

# saw FILE PATTERN — grep without echoing the file, which may hold decrypted plaintext.
# For sops STDOUT (the recovered plaintext), where an exact match is what is wanted.
saw(){ grep -qF -- "$2" "$1" 2>/dev/null; }

# unwrap FILE / saw_msg FILE PATTERN — the same, for sops's ERROR output.
#
# sops prints failures inside a box that WORD-WRAPS them, so the line the plan singles out
# as easy to misread arrives as `… "av" plugin not       | found: exec …` — split across
# two rows with the box rule between. A plain grep for "plugin not found" therefore never
# matches, which is worse than a wrong answer: the assertion that a release has not dropped
# age-plugin-av would silently pass on every run, including the runs where it had. Joining
# the lines and dropping the rule puts the message back together first.
unwrap(){ tr '\n' ' ' < "$1" | tr -d '|' | tr -s ' '; }
saw_msg(){ unwrap "$1" | grep -qF -- "$2"; }

# --- record the user's REAL keys.txt files, before $HOME moves ------------------------
# The isolation claim in the header is asserted at the end rather than assumed. Every path
# sops itself would open on this platform, plus an explicit SOPS_AGE_KEY_FILE.
REAL_KEYS=()
[ -n "${SOPS_AGE_KEY_FILE:-}" ] && REAL_KEYS+=("$SOPS_AGE_KEY_FILE")
[ -n "${XDG_CONFIG_HOME:-}" ] && REAL_KEYS+=("$XDG_CONFIG_HOME/sops/age/keys.txt")
[ "$(uname -s)" = "Darwin" ] && REAL_KEYS+=("$HOME/Library/Application Support/sops/age/keys.txt")
REAL_KEYS+=("$HOME/.config/sops/age/keys.txt")
REAL_HASHES=()
for i in "${!REAL_KEYS[@]}"; do REAL_HASHES+=("$(sha "${REAL_KEYS[$i]}")"); done

# --- probe the optional tools while the REAL environment is still in place -------------
# helm-secrets and ksops live under the user's HOME. Probing after the override would
# report every machine as "not installed", which is exactly the false skip this script is
# supposed to make impossible.
HELM_STATE=absent; HELM_WHY="helm not on PATH"; HELM_PLUGINS_REAL=""
if command -v helm >/dev/null 2>&1; then
  helm_probe="$(helm secrets --help 2>&1)"; helm_rc=$?
  HELM_PLUGINS_REAL="$(helm env HELM_PLUGINS 2>/dev/null | tr -d '"')"
  if [ "$helm_rc" -eq 0 ]; then
    HELM_STATE=ok; HELM_WHY=""
  else
    case "$helm_probe" in
      *"failed to load plugin"*secrets*)
        # "installed but unusable" is a THIRD outcome, distinct from absent, and the reason
        # is quoted rather than summarized: it is the user's own environment that has to be
        # fixed, and "helm-secrets is broken" alone tells them nothing about how.
        HELM_STATE=broken
        HELM_WHY="$(printf '%s\n' "$helm_probe" | grep -m1 'failed to load plugin' \
                    | sed -e 's/.*error="//' -e 's/"$//' -e 's/\\"/"/g')"
        [ -z "$HELM_WHY" ] && HELM_WHY="$(printf '%s\n' "$helm_probe" | head -1)"
        ;;
      *)
        # Loaded fine, yet `helm secrets` is not a command. helm 4 classifies a legacy
        # plugin that declares `downloaders:` as a getter and registers no subcommand for
        # it, so helm-secrets 4.x on helm 4.x is present, listed, and unusable. Reporting
        # that as "not installed" would send the user off to install what they already
        # have, so the listing decides between the two.
        if helm plugin list 2>/dev/null | awk '{print $1}' | grep -qx 'secrets'; then
          HELM_STATE=broken
          HELM_WHY="helm loaded the plugin but exposes no 'secrets' subcommand — a plugin-API mismatch with helm $(helm version --short 2>/dev/null)"
        else
          HELM_STATE=absent; HELM_WHY="helm has no 'secrets' subcommand (helm-secrets not installed)"
        fi
        ;;
    esac
  fi
fi

KSOPS_BIN=""
if command -v ksops >/dev/null 2>&1; then
  KSOPS_BIN="$(command -v ksops)"
else
  for d in "${XDG_CONFIG_HOME:-$HOME/.config}/kustomize/plugin/viaduct.ai/v1/ksops" \
           "$HOME/.config/kustomize/plugin/viaduct.ai/v1/ksops" \
           "$HOME/Library/Application Support/kustomize/plugin/viaduct.ai/v1/ksops"; do
    [ -x "$d/ksops" ] && { KSOPS_BIN="$d/ksops"; break; }
  done
fi

# sops version. Below 3.10 there are no age plugins at all and every check below would
# fail for one uninformative reason, so they are skipped by name instead.
SOPS_STATE=absent; SOPS_WHY="sops not on PATH"; SOPS_VER=""
if command -v sops >/dev/null 2>&1; then
  sops_ver_out="$(sops --version --disable-version-check 2>/dev/null || sops --version 2>/dev/null)"
  # First dotted-numeric field, matching cmd/av's parseSopsVersion: a build banner or a
  # renamed fork must not defeat it.
  SOPS_VER="$(printf '%s\n' "$sops_ver_out" | tr ' ' '\n' | sed -e 's/^v//' | grep -E '^[0-9]+\.[0-9]+' | head -1)"
  sops_major="${SOPS_VER%%.*}"; sops_rest="${SOPS_VER#*.}"; sops_minor="${sops_rest%%.*}"
  if [ -z "$SOPS_VER" ]; then
    SOPS_STATE=ok; SOPS_WHY=""   # unrecognizable version: a fork is not a reason to skip
  elif [ "$sops_major" -gt 3 ] || { [ "$sops_major" -eq 3 ] && [ "$sops_minor" -ge 10 ]; }; then
    SOPS_STATE=ok; SOPS_WHY=""
  else
    SOPS_STATE=broken; SOPS_WHY="sops $SOPS_VER predates age plugin support (need 3.10+)"
  fi
fi

# --- build this tree's binaries, still with the real HOME -----------------------------
# Before the override on purpose: a temp HOME means a temp GOMODCACHE, and this would
# re-download the entire dependency graph on every run.
WORK="$(mktemp -d /tmp/avsops.XXXXXXXX)"   # /tmp, not $TMPDIR: a unix socket path is capped
BIN="$WORK/bin"; mkdir -p "$BIN"           # near 104 bytes and macOS's /var/folders/… eats it
for pkg in avd av age-plugin-av; do
  ( cd "$REPO" && go build -o "$BIN/$pkg" "./cmd/$pkg" ) \
    || { echo "build ./cmd/$pkg failed"; rm -rf "$WORK"; exit 1; }
done
# An empty vault + its identity, seeded through agefile.EncryptVault so the on-disk format
# is the one avd reads. The SOPS identities go in later, through the real `av sops`.
( cd "$REPO" && go run ./cmd/smoke-seed "$WORK/id.txt" "$WORK/vault.age" >/dev/null ) \
  || { echo "seed failed"; rm -rf "$WORK"; exit 1; }

# --- the ephemeral environment --------------------------------------------------------
export HOME="$WORK/home"
export XDG_CONFIG_HOME="$WORK/config"
export XDG_DATA_HOME="$WORK/data"
export XDG_CACHE_HOME="$WORK/cache"
export XDG_RUNTIME_DIR="$WORK/run"
mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_CACHE_HOME" "$XDG_RUNTIME_DIR"
export PATH="$BIN:$PATH"
PATH_NO_PLUGIN="${PATH#"$BIN:"}"           # the same PATH with only the plugin dir removed
unset SOPS_AGE_KEY SOPS_AGE_KEY_CMD SOPS_AGE_RECIPIENTS SOPS_CONFIG
export SOPS_AGE_KEY_FILE="$WORK/keys.txt"
export AV_AGE_IDENTITY="$WORK/id.txt"
export AV_AGE_VAULT="$WORK/vault.age"
export AV_AVD_PATH="$BIN/avd"              # any autostart must reach OUR avd, never yours
SOCK="$XDG_RUNTIME_DIR/agentvault/avd.sock"
export AV_SOCKET_PATH="$SOCK"              # the documented override: one endpoint, both sides

REAL_AUTH="${REAL_AUTH:-0}"
if [ "$REAL_AUTH" = "1" ]; then
  unset AV_TEST_AUTH
  AUTHDESC="real Touch ID"
else
  export AV_TEST_AUTH=allow
  AUTHDESC="stub (AV_TEST_AUTH=allow)"
fi

cleanup(){
  [ -n "${AVD_PID:-}" ] && kill "$AVD_PID" 2>/dev/null
  [ -n "${AVD_PID:-}" ] && wait "$AVD_PID" 2>/dev/null
  # A timed-out sops leaves its plugin child behind. The pattern is this run's temp dir, so
  # it can only ever match a process this script started.
  pkill -f "$BIN/age-plugin-av" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "repo  = $REPO"
echo "work  = $WORK"
echo "auth  = $AUTHDESC"
echo "sops  = ${SOPS_VER:-none} ($SOPS_STATE${SOPS_WHY:+: $SOPS_WHY})"
echo "helm  = $HELM_STATE${HELM_WHY:+: $HELM_WHY}"
echo "ksops = ${KSOPS_BIN:-absent}"
[ -n "$REQUIRE" ] && echo "require = $REQUIRE (a skip of these is a FAILURE)"
echo

"$BIN/avd" >"$WORK/avd.log" 2>&1 &
AVD_PID=$!
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "avd did not bind $SOCK; log:"; cat "$WORK/avd.log"; exit 1; }

echo "--- assertions ---"

[ "$REAL_AUTH" = "1" ] && printf '\033[1;36m  >>> Touch the sensor to unlock AgentVault…\033[0m\n'
if av unlock >/dev/null 2>>"$WORK/av.err"; then ok "av unlock ($AUTHDESC)"; else no "av unlock — see $WORK/avd.log"; fi

# --- the two SOPS identities everything below is built on ------------------------------
# Generated inside the vault (`keygen`, not `import`), which is the path where the private
# key never exists outside avd at all.
REC1=""; PTR1=""; REC2=""; PTR2=""
if av sops keygen k1 >/dev/null 2>>"$WORK/av.err" && av sops keygen k2 >/dev/null 2>>"$WORK/av.err"; then
  REC1="$(av sops recipient k1 2>/dev/null)"; PTR1="$(av sops identity k1 2>/dev/null)"
  REC2="$(av sops recipient k2 2>/dev/null)"; PTR2="$(av sops identity k2 2>/dev/null)"
  case "$REC1$REC2" in
    age1*age1*) ok "av sops keygen stores an identity and prints a plain age1… recipient" ;;
    *) no "av sops recipient did not return age1… (got '$REC1' / '$REC2')" ;;
  esac
  case "$PTR1" in
    AGE-PLUGIN-AV-1*) ok "av sops identity prints an AGE-PLUGIN-AV-1… keys.txt pointer" ;;
    *) no "av sops identity did not return a pointer (got '${PTR1:0:24}…')" ;;
  esac
else
  no "av sops keygen failed — every check below it is unreachable (see $WORK/av.err)"
fi

# The plaintext each check hunts for. Deliberately NOT a token shape: the only thing that
# can put these strings in an output is a real decryption through the daemon.
SENT1="SOPSsmokePLAINTEXT-$$-not-a-pattern-0001"
SENT2="SOPSsmokeSECONDkey-$$-not-a-pattern-0002"
SENT3="SOPSsmokeHELMvalue-$$-not-a-pattern-0003"
SENT4="SOPSsmokeKSOPSval-$$-not-a-pattern-0004"

if [ "$SOPS_STATE" != "ok" ] || [ -z "$REC1" ]; then
  why="${SOPS_WHY:-no SOPS identity to test with}"
  for c in "sops -d through the plugin" "sops updatekeys" "locked vault under AV_NO_PROMPT" \
           "plugin-not-found control" "multi-pointer keys.txt"; do
    if [ "$SOPS_STATE" = "broken" ]; then broken "$c" "$why" sops; else absent "$c" "$why" sops; fi
  done
else
  # 1) THE HEADLINE CLAIM: a file encrypted to an ORDINARY age1… recipient, by ordinary
  #    sops, with no AgentVault anywhere on the write side, decrypts through the plugin.
  printf '%s\n' "$PTR1" > "$WORK/keys.txt"; chmod 600 "$WORK/keys.txt"
  printf 'password: %s\n' "$SENT1" > "$WORK/secret.dec.yaml"
  if sops --encrypt --age "$REC1" "$WORK/secret.dec.yaml" > "$WORK/secret.enc.yaml" 2>"$WORK/enc.err"; then
    if saw "$WORK/secret.enc.yaml" "$SENT1"; then
      no "sops encrypted nothing — the plaintext is still in the file"
    else
      ok "sops encrypts to a plain age1… recipient (no plugin on the write side)"
    fi
    run_bounded 30 "$WORK/dec1.out" sops -d "$WORK/secret.enc.yaml"; rc=$?
    if [ "$rc" -eq 124 ]; then
      no "sops -d HUNG (>30s): a blocked plugin stalls sops, and through sops, helm"
    elif [ "$rc" -ne 0 ]; then
      no "sops -d failed (rc=$rc): $(tr '\n' ' ' < "$WORK/dec1.out" | cut -c1-300)"
    elif saw "$WORK/dec1.out" "$SENT1"; then
      ok "sops -d decrypts through age-plugin-av (plaintext recovered, key never left avd)"
    else
      no "sops -d exited 0 but the plaintext is missing"
    fi
  else
    no "sops --encrypt failed: $(tr '\n' ' ' < "$WORK/enc.err" | cut -c1-300)"
  fi

  # 2) `sops updatekeys` — listed as an open risk and never exercised. It has to DECRYPT
  #    (through the plugin) and re-encrypt, so the check adds a second recipient: a
  #    "nothing to do" run would exit 0 without ever reaching the plugin.
  mkdir -p "$WORK/uk"
  cp "$WORK/secret.enc.yaml" "$WORK/uk/updatekeys.enc.yaml" 2>/dev/null
  cat > "$WORK/uk/.sops.yaml" <<YAML
creation_rules:
  - path_regex: .*\.enc\.yaml\$
    age: $REC1,$REC2
YAML
  if [ -f "$WORK/uk/updatekeys.enc.yaml" ]; then
    run_bounded 30 "$WORK/uk.out" sops --config "$WORK/uk/.sops.yaml" updatekeys -y "$WORK/uk/updatekeys.enc.yaml"; rc=$?
    if [ "$rc" -eq 124 ]; then
      no "sops updatekeys HUNG (>30s)"
    elif [ "$rc" -ne 0 ]; then
      no "sops updatekeys failed (rc=$rc): $(tr '\n' ' ' < "$WORK/uk.out" | cut -c1-300)"
    elif ! saw "$WORK/uk/updatekeys.enc.yaml" "$REC2"; then
      no "sops updatekeys exited 0 but did not add the second recipient"
    else
      ok "sops updatekeys re-wraps through the plugin (added a recipient)"
      run_bounded 30 "$WORK/uk2.out" sops -d "$WORK/uk/updatekeys.enc.yaml"; rc=$?
      if [ "$rc" -eq 0 ] && saw "$WORK/uk2.out" "$SENT1"; then
        ok "the updatekeys'd file still decrypts through the plugin"
      else
        no "the updatekeys'd file no longer decrypts (rc=$rc)"
      fi
    fi
  else
    no "sops updatekeys: no encrypted file to update (the encrypt above failed)"
  fi

  # 5) A LOCKED vault under AV_NO_PROMPT must answer, readably, and must not hang. This is
  #    the failure mode the plugin exists to avoid: nobody is in front of an agent's
  #    machine, so a biometric prompt here is an indefinite stall.
  av lock >/dev/null 2>&1
  run_bounded 30 "$WORK/locked.out" env AV_NO_PROMPT=1 sops -d "$WORK/secret.enc.yaml"; rc=$?
  if [ "$rc" -eq 124 ]; then
    no "a locked vault HUNG sops (>30s) instead of answering"
  else
    ok "a locked vault answers within the bound instead of hanging (rc=$rc)"
    if [ "$rc" -eq 0 ]; then
      no "LEAK: a locked vault decrypted the file"
    elif saw_msg "$WORK/locked.out" 'AgentVault: sops unwrap: vault locked'; then
      ok "the locked-vault message reaches the user through sops"
    else
      no "locked run did not carry the daemon's message: $(unwrap "$WORK/locked.out" | cut -c1-300)"
    fi
    # THE assertion that makes this script worth keeping: the failure above is
    # AgentVault's, so the plugin was found, started and answered. A release that dropped
    # the binary would fail here too — with a different, and much less useful, error.
    if saw_msg "$WORK/locked.out" 'plugin not found'; then
      no "the plugin was NOT found — this run proves nothing about the daemon path"
    else
      ok "the failure is AgentVault's own, not a missing plugin (the plugin ran)"
    fi
  fi
  [ "$REAL_AUTH" = "1" ] && printf '\033[1;36m  >>> Touch the sensor again to re-unlock…\033[0m\n'
  av unlock >/dev/null 2>&1

  # 5b) The control for the assertion above. With the plugin off PATH the error must be
  #     age's plugin-not-found — otherwise "no plugin-not-found in the output" is a
  #     statement about nothing, and a future release could drop the binary unnoticed.
  run_bounded 30 "$WORK/noplugin.out" env PATH="$PATH_NO_PLUGIN" sops -d "$WORK/secret.enc.yaml"; rc=$?
  if [ "$rc" -eq 0 ]; then
    no "control: sops decrypted with the plugin off PATH — something else holds the key"
  elif saw_msg "$WORK/noplugin.out" 'plugin not found'; then
    ok "control: a missing age-plugin-av says so, distinguishably (so the checks above discriminate)"
    # Printed because this is the error a Formula that forgot the binary produces, and the
    # plan calls it easy to read as a key problem. Seeing it once, next to the checks it
    # underwrites, is worth four lines of output.
    info "a missing plugin reads: $(unwrap "$WORK/noplugin.out" | sed -e 's/.*Group 0: FAILED//' | cut -c1-220)"
  else
    no "control: a missing plugin did not report 'plugin not found': $(unwrap "$WORK/noplugin.out" | cut -c1-300)"
  fi

  # 8) A MULTI-POINTER keys.txt: two AgentVault identities, a file encrypted to only the
  #    SECOND. k1 has to step aside rather than veto the decrypt — the whole point of
  #    ipc.CodeNoMatch, and until now proven only against the age library. Order is
  #    deliberate: with the working pointer first a regression is never reached.
  printf '%s\n%s\n' "$PTR1" "$PTR2" > "$WORK/keys-multi.txt"; chmod 600 "$WORK/keys-multi.txt"
  printf 'password: %s\n' "$SENT2" > "$WORK/multi.dec.yaml"
  if sops --encrypt --age "$REC2" "$WORK/multi.dec.yaml" > "$WORK/multi.enc.yaml" 2>"$WORK/enc2.err"; then
    run_bounded 30 "$WORK/multi.out" env SOPS_AGE_KEY_FILE="$WORK/keys-multi.txt" sops -d "$WORK/multi.enc.yaml"; rc=$?
    if [ "$rc" -eq 0 ] && saw "$WORK/multi.out" "$SENT2"; then
      ok "a two-pointer keys.txt decrypts a file encrypted to only the second key"
    elif [ "$rc" -eq 124 ]; then
      no "the two-pointer keys.txt HUNG (>30s)"
    else
      no "the two-pointer keys.txt failed (rc=$rc): $(tr '\n' ' ' < "$WORK/multi.out" | cut -c1-300)"
    fi
  else
    no "sops --encrypt to the second recipient failed"
  fi
fi

# --- 3) helm secrets ------------------------------------------------------------------
# HELM_PLUGINS is carried over from the real environment because the plugin lives under the
# user's HOME, which this script has moved. It is read, never written.
if [ "$HELM_STATE" = "absent" ]; then
  absent "helm secrets template" "$HELM_WHY" helm
elif [ "$HELM_STATE" = "broken" ]; then
  broken "helm secrets template" "$HELM_WHY" helm
elif [ "$SOPS_STATE" != "ok" ] || [ -z "$REC1" ]; then
  absent "helm secrets template" "${SOPS_WHY:-no SOPS identity to test with}" helm
else
  mkdir -p "$WORK/chart/templates"
  cat > "$WORK/chart/Chart.yaml" <<'YAML'
apiVersion: v2
name: avsmoke
version: 0.1.0
YAML
  printf 'password: ""\n' > "$WORK/chart/values.yaml"
  cat > "$WORK/chart/templates/cm.yaml" <<'YAML'
apiVersion: v1
kind: ConfigMap
metadata:
  name: avsmoke
data:
  password: {{ .Values.password | quote }}
YAML
  printf 'password: %s\n' "$SENT3" > "$WORK/helm-values.dec.yaml"
  if sops --encrypt --age "$REC1" "$WORK/helm-values.dec.yaml" > "$WORK/helm-values.enc.yaml" 2>/dev/null; then
    run_bounded 60 "$WORK/helm.out" env HELM_PLUGINS="$HELM_PLUGINS_REAL" \
      helm secrets template avsmoke "$WORK/chart" -f "$WORK/helm-values.enc.yaml"; rc=$?
    if [ "$rc" -eq 124 ]; then
      no "helm secrets template HUNG (>60s)"
    elif [ "$rc" -ne 0 ]; then
      no "helm secrets template failed (rc=$rc): $(tr '\n' ' ' < "$WORK/helm.out" | cut -c1-300)"
    elif saw "$WORK/helm.out" "$SENT3"; then
      ok "helm secrets template renders a value decrypted through the plugin"
    else
      no "helm secrets template exited 0 without the decrypted value"
    fi
  else
    no "helm secrets: could not encrypt the values file"
  fi
fi

# --- 4) kustomize + ksops --------------------------------------------------------------
if ! command -v kustomize >/dev/null 2>&1; then
  absent "kustomize build --enable-alpha-plugins (ksops)" "kustomize not on PATH" ksops
elif [ -z "$KSOPS_BIN" ]; then
  absent "kustomize build --enable-alpha-plugins (ksops)" "ksops not on PATH nor in a kustomize plugin dir" ksops
elif [ "$SOPS_STATE" != "ok" ] || [ -z "$REC1" ]; then
  absent "kustomize build --enable-alpha-plugins (ksops)" "${SOPS_WHY:-no SOPS identity to test with}" ksops
else
  # The plugin dir moved with XDG_CONFIG_HOME, so the real ksops is linked into the
  # ephemeral one at the location kustomize looks for it.
  KPDIR="$XDG_CONFIG_HOME/kustomize/plugin/viaduct.ai/v1/ksops"
  mkdir -p "$KPDIR" "$WORK/kust"
  ln -sf "$KSOPS_BIN" "$KPDIR/ksops"
  ln -sf "$KSOPS_BIN" "$BIN/ksops"
  cat > "$WORK/kust/secret.dec.yaml" <<YAML
apiVersion: v1
kind: Secret
metadata:
  name: avsmoke
stringData:
  password: $SENT4
YAML
  cat > "$WORK/kust/ksops-generator.yaml" <<'YAML'
apiVersion: viaduct.ai/v1
kind: ksops
metadata:
  name: avsmoke-secret
  annotations:
    config.kubernetes.io/function: |
      exec:
        path: ksops
files:
  - ./secret.enc.yaml
YAML
  cat > "$WORK/kust/kustomization.yaml" <<'YAML'
generators:
  - ./ksops-generator.yaml
YAML
  if sops --encrypt --age "$REC1" "$WORK/kust/secret.dec.yaml" > "$WORK/kust/secret.enc.yaml" 2>/dev/null; then
    rm -f "$WORK/kust/secret.dec.yaml"
    run_bounded 60 "$WORK/kust.out" kustomize build --enable-alpha-plugins --enable-exec "$WORK/kust"; rc=$?
    if [ "$rc" -eq 124 ]; then
      no "kustomize build HUNG (>60s)"
    elif [ "$rc" -ne 0 ]; then
      no "kustomize build failed (rc=$rc): $(tr '\n' ' ' < "$WORK/kust.out" | cut -c1-300)"
    elif saw "$WORK/kust.out" "$SENT4" || saw "$WORK/kust.out" "$(printf '%s' "$SENT4" | base64)"; then
      ok "kustomize build + ksops emits a Secret decrypted through the plugin"
    else
      no "kustomize build exited 0 without the decrypted value"
    fi
  else
    no "ksops: could not encrypt the secret"
  fi
fi

# --- 6) av sops import writes back to the file the key CAME from -----------------------
# SOPS_AGE_KEY_FILE is ADDITIVE — sops reads it *and* the config-dir keys.txt — so an
# import that wrote its pointer to the config dir would leave the plaintext key exactly
# where sops keeps reading it, the plugin never exercised, and the command reporting
# success. The check is therefore both halves: the pointer landed *here*, and the
# config-dir file did not move.
if [ -z "$REC1" ]; then
  absent "av sops import → SOPS_AGE_KEY_FILE" "no daemon session to import into" sops
elif ! command -v age-keygen >/dev/null 2>&1; then
  absent "av sops import → SOPS_AGE_KEY_FILE" "age-keygen not on PATH (needed to make a plaintext key to import)" age
else
  mkdir -p "$WORK/import" "$XDG_CONFIG_HOME/sops/age"
  CFG_KEYS="$XDG_CONFIG_HOME/sops/age/keys.txt"
  printf '# smoke sentinel — av sops import must not touch this file\n' > "$CFG_KEYS"
  CFG_BEFORE="$(sha "$CFG_KEYS")"
  IMP="$WORK/import/keys.txt"
  age-keygen -o "$IMP" >/dev/null 2>&1
  if ! grep -q 'AGE-SECRET-KEY-1' "$IMP" 2>/dev/null; then
    no "av sops import: age-keygen produced no key to import"
  else
    # stdin is /dev/null: non-TTY, so import keeps a backup without asking. That backup
    # holds the PLAINTEXT key and lives inside $WORK, which cleanup removes.
    if env SOPS_AGE_KEY_FILE="$IMP" av sops import --name imp >"$WORK/import.out" 2>&1 </dev/null; then
      if grep -q 'AGE-PLUGIN-AV-1' "$IMP" && ! grep -q 'AGE-SECRET-KEY-1' "$IMP"; then
        ok "av sops import rewrites the SOPS_AGE_KEY_FILE it read the key from (key out, pointer in)"
      else
        no "av sops import left $IMP wrong (pointer present: $(grep -c 'AGE-PLUGIN-AV-1' "$IMP"), key present: $(grep -c 'AGE-SECRET-KEY-1' "$IMP"))"
      fi
      if [ "$(sha "$CFG_KEYS")" = "$CFG_BEFORE" ]; then
        ok "av sops import left the config-dir keys.txt untouched"
      else
        no "av sops import MODIFIED the config-dir keys.txt ($CFG_KEYS)"
      fi
      if av sops ls 2>/dev/null | grep -qE '(^|[[:space:]])imp([[:space:]]|$)'; then
        ok "the imported identity is listed by av sops ls"
      else
        no "av sops ls does not list the imported identity"
      fi
    else
      no "av sops import failed: $(tr '\n' ' ' < "$WORK/import.out" | cut -c1-300)"
    fi
  fi

  # 7) av sops rm --force — destructive, non-interactive, and the way a script undoes the
  #    import above.
  if av sops rm imp --force >"$WORK/rm.out" 2>&1; then
    if av sops ls 2>/dev/null | grep -qE '(^|[[:space:]])imp([[:space:]]|$)'; then
      no "av sops rm --force exited 0 but the identity is still listed"
    else
      ok "av sops rm --force deletes without a prompt"
    fi
  else
    no "av sops rm --force failed: $(tr '\n' ' ' < "$WORK/rm.out" | cut -c1-300)"
  fi
fi

# --- the isolation claim, asserted --------------------------------------------------
moved=""
for i in "${!REAL_KEYS[@]}"; do
  [ "$(sha "${REAL_KEYS[$i]}")" = "${REAL_HASHES[$i]}" ] || moved="$moved ${REAL_KEYS[$i]}"
done
if [ -z "$moved" ]; then
  ok "your real keys.txt files are byte-for-byte unchanged (${#REAL_KEYS[@]} checked)"
else
  no "THIS SCRIPT CHANGED A REAL FILE:$moved"
fi

# The ephemeral daemon stops when the script does. Asserted here, while there is still
# something to print with, rather than left to the exit trap.
kill "$AVD_PID" 2>/dev/null; wait "$AVD_PID" 2>/dev/null; AVD_PID=""
if pgrep -f "$BIN/avd" >/dev/null 2>&1; then
  no "the avd this script started is still running"
else
  ok "the avd this script started is gone"
fi

echo
echo "==== $PASS passed, $FAIL failed, $SKIPPED_ABSENT skipped (tool absent), $SKIPPED_BROKEN skipped (tool unusable) ===="
if [ -n "$SKIPS" ]; then
  echo "skipped — these claims are UNPROVEN by this run:$SKIPS"
fi
if [ "$FAIL" -ne 0 ]; then
  echo "--- avd.log ---"; cat "$WORK/avd.log"
  [ -f "$WORK/av.err" ] && { echo "--- av.err ---"; cat "$WORK/av.err"; }
fi
if [ -n "$REQUIRED_SKIPS" ]; then
  # Deliberately louder than a FAIL line: every check the caller asked for reported
  # something other than a failure, so without this the run reads as a clean pass.
  printf '\n\033[31m==== REQUIRED CHECKS DID NOT RUN (AV_SMOKE_REQUIRE=%s) ====\033[0m\n' "${AV_SMOKE_REQUIRE:-}"
  echo "These tools were installed on purpose, so a skip means the install is broken:$REQUIRED_SKIPS"
  echo "(see the SKIP lines above for the reason each one gave)"
fi
[ "$FAIL" -eq 0 ] && [ -z "$REQUIRED_SKIPS" ]
