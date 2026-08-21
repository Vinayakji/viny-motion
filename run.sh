#!/usr/bin/env bash
# run.sh - Genymotion APK Pentesting Pipeline master runner
# usage:
#   ./run.sh                     # run ALL phases end-to-end
#   ./run.sh list                # list phases
#   ./run.sh <phase[:phase...]>  # run selected phases
#   ./run.sh check               # pre-flight: config, tools
#   ./run.sh --rag <phase...>    # same, plus RAG knowledge dispatch
set -uo pipefail
PIPELINE_ROOT="$(cd "$(dirname "$0")" && pwd)"
source "$PIPELINE_ROOT/lib/common.sh"

RAG=0
ARGS=()
for a in "$@"; do
  if [ "$a" = "--rag" ]; then RAG=1; else ARGS+=("$a"); fi
done
set -- "${ARGS[@]}"

export REUSE_RUN_DIR="$RUN_DIR"

PHASES=(
  00_acquire 01_static 02_setup_genymotion
  03_dynamic_drozer 04_dynamic_objection 05_frida_hooks
  06_traffic_capture 07_storage_dump 08_findings_report
)

run_one() {
  local ph="$1"
  [ -f "$PIPELINE_ROOT/phases/$ph.sh" ] || { err "unknown phase $ph"; exit 1; }
  info "=== PHASE $ph ==="
  [ "$RAG" = 1 ] && "$PIPELINE_ROOT/extras/skill_dispatch.sh" "$ph" 2>/dev/null || true
  bash "$PIPELINE_ROOT/phases/$ph.sh"
  echo
}

check() {
  echo "== PRE-FLIGHT =="
  echo "apk         : $(tget apk path || echo NOT SET)"
  echo "package     : $(tget apk package_name || echo NOT SET)"
  echo "device      : $(tget genymotion device_name || echo NOT SET)"
  echo "proxy       : $(tget proxy host):$(tget proxy port)"
  echo "run dir     : $RUN_DIR"
  echo "tools       :"
  for t in adb drozer objection frida jadx frida-ps frida-trace; do
    command -v "$t" >/dev/null 2>&1 && echo "  OK $t" || echo "  MISS $t"
  done
  echo "genymotion  : $([ -x "$HOME/genymotion/genymotion" ] || [ -x "$HOME/genymotion/player" ] && echo OK || echo MISS)"
}

case "${1:-all}" in
  list) printf '%s\n' "${PHASES[@]}" ;;
  check) check ;;
  all)
    check
    echo "== FULL RUN: $(date -Iseconds) =="
    for ph in "${PHASES[@]}"; do run_one "$ph"; done
    ;;
  *)
    for ph in "$@"; do run_one "$ph"; done
    ;;
esac
