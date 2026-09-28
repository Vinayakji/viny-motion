#!/usr/bin/env bash
# lib/common.sh - shared helpers for Genymotion pipeline
set -uo pipefail

PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${TARGET_CONFIG:-$PIPELINE_ROOT/config/target.yaml}"
FINDINGS_DIR="$PIPELINE_ROOT/findings"
REPORTS_DIR="$PIPELINE_ROOT/reports"
mkdir -p "$FINDINGS_DIR" "$REPORTS_DIR"

NOW_TS="$(date +%Y%m%d_%H%M%S)"
if [ -n "${REUSE_RUN_DIR:-}" ] && [ -n "$REUSE_RUN_DIR" ]; then
  RUN_DIR="$REUSE_RUN_DIR"
else
  RUN_DIR="$REPORTS_DIR/run_$NOW_TS"
fi
mkdir -p "$RUN_DIR"

# ---- yaml getter ----
tget() {
  local k="${2:-}"
  awk -v s="$1" -v k="$k" '
    $0 == s ":" { in_s=1; next }
    !in_s && /^[a-zA-Z0-9_.]+: *$/ { in_s=($1 == s ":"); next }
    !in_s && $0 ~ "^" s ":" { v=$0; sub(/^[^:]*: */, "", v); gsub(/ *#.*$/, "", v); gsub(/^"|"$/, "", v); print v; exit }
    in_s && /^[a-zA-Z0-9_.]+:/ && !($0 ~ "^  ") { in_s=0 }
    in_s && $0 ~ "^  " k ":" {
      v=$0; sub(/^[^:]*: */, "", v); gsub(/ *#.*$/, "", v); gsub(/^"|"$/, "", v); print v; exit
    }' "$CONFIG"
}

# ---- logging ----
log()   { echo "[$(date +%H:%M:%S)] [${PROFILE_PHASE:-master}] $*"; }
info()  { log "INFO  $*"; }
warn()  { log "WARN  $*"; }
ok()    { log "OK    $*"; }
err()   { log "ERROR $*"; }

# ---- adb helpers ----
adb_shell() {
  adb shell "$@" 2>/dev/null
}

adb_install() {
  local apk="$1"
  info "Installing $apk..."
  adb install -r "$apk" 2>&1 | tail -1
}

adb_launch() {
  local pkg="$1"
  local activity
  activity="$(adb shell cmd package resolve-activity --brief "$pkg" 2>/dev/null | tail -1)"
  if [ -n "$activity" ]; then
    adb shell am start -n "$activity" 2>/dev/null
  else
    adb shell monkey -p "$pkg" -c android.intent.category.LAUNCHER 1 2>/dev/null
  fi
}

# ---- Genymotion helpers ----
genymotion_start() {
  local device="$1"
  info "Starting Genymotion device: $device"
  "$HOME/genymotion/genymotion" --vm-start "$device" 2>/dev/null || \
  "$HOME/genymotion/player" --vm-start "$device" 2>/dev/null || \
  warn "Could not start Genymotion device (is it installed?)"
  sleep 10
}

genymotion_stop() {
  local device="$1"
  info "Stopping Genymotion device: $device"
  "$HOME/genymotion/genymotion" --vm-stop "$device" 2>/dev/null || \
  "$HOME/genymotion/player" --vm-stop "$device" 2>/dev/null || \
  warn "Could not stop Genymotion device"
}

# ---- proxy setup ----
setup_proxy() {
  local host="$(tget proxy host)"
  local port="$(tget proxy port)"
  [ -z "$host" ] || [ -z "$port" ] && return
  info "Setting proxy: $host:$port"
  adb shell settings put global http_proxy "$host:$port" 2>/dev/null
}

clear_proxy() {
  info "Clearing proxy"
  adb shell settings put global http_proxy :0 2>/dev/null
}

# ---- frida helpers ----
frida_launch() {
  local pkg="$1"
  local script="${2:-}"
  if [ -n "$script" ]; then
    frida -U -f "$pkg" -l "$script" --no-pause 2>&1 &
  else
    frida -U -f "$pkg" --no-pause 2>&1 &
  fi
}

frida_attach() {
  local pkg="$1"
  local script="${2:-}"
  if [ -n "$script" ]; then
    frida -U "$pkg" -l "$script" 2>&1 &
  else
    frida -U "$pkg" 2>&1 &
  fi
}
