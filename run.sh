#!/usr/bin/env bash
# run.sh - Genymotion APK Pentesting Pipeline master runner (IMPROVED)
# usage:
#   ./run.sh                     # run ALL phases end-to-end
#   ./run.sh list                # list phases
#   ./run.sh <phase[:phase...]>  # run selected phases
#   ./run.sh check               # pre-flight: config, tools
#   ./run.sh --rag <phase...>    # same, plus RAG knowledge dispatch
#   ./run.sh vapt_handoff        # extract findings for VAPT pipeline
set -uo pipefail
PIPELINE_ROOT="$(cd "$(dirname "$0")" && pwd)"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/objection_helpers.sh"

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
  00_acquire 01_static 02_setup_genymotion
  03_dynamic_drozer 03b_dynamic_drozer_mcp 04_dynamic_objection
  05_frida_hooks 06_traffic_capture 07_deep_links 07_storage_dump
  09_mobsf_dast 10_backup_extract 11_webview_exploit
  12_pending_intent 13_resilience 14_crypto_audit 15_cleanup
  08_findings_report
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
  echo "phases      : ${#PHASES[@]} total"
  echo "new modules : deep_links, objection_helpers"
  echo "tools       :"
  for t in adb drozer objection frida jadx frida-ps frida-trace jq; do
    command -v "$t" >/dev/null 2>&1 && echo "  OK $t" || echo "  MISS $t"
  done
  echo "genymotion  : $([ -x "$HOME/genymotion/genymotion" ] || [ -x "$HOME/genymotion/player" ] && echo OK || echo MISS)"
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
  vapt_handoff) vapt_handoff ;;
  all)
    check
    echo "== FULL RUN: $(date -Iseconds) =="
    for ph in "${PHASES[@]}"; do run_one "$ph"; done
    vapt_handoff
    ;;
  *)
    for ph in "$@"; do
      case "$ph" in
        vapt_handoff) vapt_handoff ;;
        *) run_one "$ph" ;;
      esac
    done
    ;;
esac
