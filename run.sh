#!/usr/bin/env bash
# run.sh - viny-motion APK Pentesting Pipeline master runner (IMPROVED)
# usage:
#   ./run.sh                     # run ALL phases end-to-end
#   ./run.sh list                # list phases
#   ./run.sh <phase[:phase...]>  # run selected phases
#   ./run.sh check               # pre-flight: config, tools
#   ./run.sh --rag <phase...>    # same, plus RAG knowledge dispatch
#   ./run.sh vapt_handoff        # extract findings for VAPT pipeline
#   ./run.sh retest [db]         # retest/closure report (retest-mark <id> FIXED)
set -uo pipefail
PIPELINE_ROOT="$(cd "$(dirname "$0")" && pwd)"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/objection_helpers.sh"
source "$PIPELINE_ROOT/lib/scope_gate.sh"
source "$PIPELINE_ROOT/lib/retest.sh"
source "$HOME/laya_orchestrator/laya_hook.sh" 2>/dev/null || true

RAG=0
VAPT_HANDOFF=0
ARGS=()
for a in "$@"; do
  case "$a" in
    --rag) RAG=1 ;;
    vapt_handoff) VAPT_HANDOFF=1 ;;
    *) ARGS+=("$a") ;;
  esac
done
set -- "${ARGS[@]}"

export REUSE_RUN_DIR="$RUN_DIR"

PHASES=(
  00_acquire 01_static 02_setup_viny_motion
  03_dynamic_drozer 03b_dynamic_drozer_mcp 04_dynamic_objection
  05_frida_hooks 06_traffic_capture 07_deep_links 07_storage_dump
  09_mobsf_dast 10_backup_extract 11_webview_exploit
  12_pending_intent 13_resilience 14_crypto_audit
  16_code_analysis 17_input_validation 18_dastforge
  15_cleanup 08_findings_report
)

# --- Debuggable-aware phase pruning ---
# If app is already debuggable, Frida/objection/RASP bypass add zero value.
# Only run those phases when protections need bypassing (non-debuggable).
_debuggable_flag="$RUN_DIR/.debuggable"
if [ -f "$_debuggable_flag" ] && [ "$(cat "$_debuggable_flag" 2>/dev/null)" = "1" ]; then
  warn "App is debuggable — skipping Frida/objection/bypass phases"
  _skip_phases=(04_dynamic_objection 05_frida_hooks)
  _new_phases=()
  for _ph in "${PHASES[@]}"; do
    _skip=0
    for _sp in "${_skip_phases[@]}"; do
      [ "$_ph" = "$_sp" ] && { _skip=1; break; }
    done
    [ "$_skip" -eq 0 ] && _new_phases+=("$_ph")
  done
  PHASES=("${_new_phases[@]}")
  info "Remaining phases: ${#PHASES[@]}"
fi

run_one() {
  local ph="$1"
  [ -f "$PIPELINE_ROOT/phases/$ph.sh" ] || { err "unknown phase $ph"; exit 1; }
  info "=== PHASE $ph ==="
  if ! laya_health_check; then
    return 1
  fi
  if ! laya_gate "$ph"; then
    err "LAYA gate blocked phase $ph"
    return 1
  fi
  [ "$RAG" = 1 ] && "$PIPELINE_ROOT/extras/skill_dispatch.sh" "$ph" 2>/dev/null || true
  bash "$PIPELINE_ROOT/phases/$ph.sh"
  echo
}

check() {
  local rc=0
  require_authorization || rc=1
  require_config || rc=1
  echo "== PRE-FLIGHT =="
  echo "apk         : $(tget apk path || echo NOT SET)"
  echo "package     : $(tget apk package_name || echo NOT SET)"
  echo "device      : $(tget viny-motion device_name || echo NOT SET)"
  echo "proxy       : $(tget proxy host):$(tget proxy port)"
  echo "run dir     : $RUN_DIR"
  echo "phases      : ${#PHASES[@]} total"
  echo "required tools:"
  for t in "${REQUIRED_TOOLS[@]}"; do
    if command -v "$t" >/dev/null 2>&1; then echo "  OK   $t"; else echo "  MISS $t"; rc=1; fi
  done
  echo "optional tools (warn only):"
  for t in "${OPTIONAL_TOOLS[@]}"; do
    command -v "$t" >/dev/null 2>&1 && echo "  OK   $t" || echo "  --   $t"
  done
  if [ -x "$HOME/genymotion/genymotion" ] || [ -x "$HOME/genymotion/player" ]; then
    echo "genymotion  : OK"
  else
    echo "genymotion  : MISS"
    rc=1
  fi
  if [ "$rc" -eq 0 ]; then
    ok "pre-flight passed — environment ready"
  else
    warn "pre-flight FAILED — fix the issues above before running"
  fi
  return $rc
}

# VAPT handoff - extract findings for web testing
vapt_handoff() {
  local handoff_dir="$RUN_DIR/vapt_handoff"
  mkdir -p "$handoff_dir"
  
  info "Extracting findings for VAPT pipeline..."
  
  # Extract API endpoints from traffic capture
  if [ -f "$RUN_DIR/traffic/api_endpoints.txt" ]; then
    cp "$RUN_DIR/traffic/api_endpoints.txt" "$handoff_dir/discovered_endpoints.txt"
  fi
  
  # Extract secrets from storage dump
  if [ -f "$RUN_DIR/storage/secrets.json" ]; then
    jq -r '.[] | .key + "=" + .value' "$RUN_DIR/storage/secrets.json" > "$handoff_dir/secrets.env" 2>/dev/null || true
  fi
  
  # Extract domains from static analysis
  if [ -f "$RUN_DIR/static/domains.txt" ]; then
    cat "$RUN_DIR/static/domains.txt" >> "$handoff_dir/extra_hosts.txt" 2>/dev/null || true
  fi
  
  # Extract Firebase config
  if [ -f "$RUN_DIR/static/firebase.json" ]; then
    cp "$RUN_DIR/static/firebase.json" "$handoff_dir/firebase_config.json"
  fi
  
  # Create VAPT config additions
  cat > "$handoff_dir/vapt_config_additions.yaml" << EOF
# Auto-generated from mobile testing
# Add these to your VAPT target.yaml

mobile_discovery:
  api_endpoints: discovered_endpoints.txt
  secrets: secrets.env
  hosts: extra_hosts.txt
  firebase: firebase_config.json

# Discovered endpoints to test
target_urls:
$(if [ -f "$handoff_dir/discovered_endpoints.txt" ]; then
  while IFS= read -r endpoint; do
    echo "  - $endpoint"
  done < "$handoff_dir/discovered_endpoints.txt"
fi)
EOF
  
  # Copy findings
  if [ -f "$RUN_DIR/findings/findings.json" ]; then
    cp "$RUN_DIR/findings/findings.json" "$handoff_dir/mobile_findings.json"
  fi
  
  ok "VAPT handoff complete: $handoff_dir"
  echo ""
  echo "To use with VAPT pipeline:"
  echo "  1. Copy contents of $handoff_dir to VAPT run dir"
  echo "  2. Add endpoints to VAPT target.yaml"
  echo "  3. Run VAPT pipeline with: ./run.sh --rag 00_discovery"
}

case "${1:-all}" in
  list) printf '%s\n' "${PHASES[@]}" ;;
  check) check ;;
  retest)
    require_authorization || exit 1
    retest_generate "${2:-$FINDINGS_DIR/findings.json}"
    echo
    retest_summary "${2:-$FINDINGS_DIR/findings.json}"
    echo
    echo "Mark closures with: ./run.sh retest-mark <finding-id> FIXED|OPEN|PARTIAL [note]"
    ;;
  retest-mark)
    require_authorization || exit 1
    retest_mark "$2" "$3" "$4"
    ;;
  vapt_handoff) vapt_handoff ;;
  all)
    check || exit 1
    # Fix viny-motion internet (clear dead global proxy)
    "$PIPELINE_ROOT/extras/fix-viny-motion-internet.sh" 2>/dev/null || true
    echo "== FULL RUN: $(date -Iseconds) =="
    for ph in "${PHASES[@]}"; do run_one "$ph"; done
    vapt_handoff
    ;;
  *)
    check || exit 1
    for ph in "$@"; do
      case "$ph" in
        vapt_handoff) vapt_handoff ;;
        *) run_one "$ph" ;;
      esac
    done
    ;;
esac
