#!/usr/bin/env bash
# extras/skill_dispatch.sh - RAG knowledge injection per phase (Android)
# usage: ./skill_dispatch.sh <phase> [run_dir]
# Queries the RAG index for Android-specific skills and writes knowledge files.

PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$PIPELINE_ROOT/lib/common.sh" >/dev/null 2>&1

PHASE="${1:-}"
[ -z "$PHASE" ] && { echo "usage: $0 <phase>"; exit 1; }
RUN_DIR="${2:-${REUSE_RUN_DIR:-}}"

command -v rag >/dev/null 2>&1 || { echo "[skip] rag CLI not installed"; exit 0; }

# Android-specific skill mapping per phase
declare -A PHASE_SKILLS=(
  [00_acquire]="apk download android recon"
  [01_static]="android static analysis manifest decompile secrets"
  [02_setup_genymotion]="genymotion android emulator setup frida drozer"
  [03_dynamic_drozer]="drozer android enumeration modules attack surface"
  [03b_dynamic_drozer_mcp]="drozer mcp android dynamic testing"
  [04_dynamic_objection]="objection android ssl pinning bypass root detection keystore"
  [05_frida_hooks]="frida android hooking ssl bypass method tracing memory"
  [06_traffic_capture]="android proxy traffic capture mitmproxy api endpoints"
  [07_deep_links]="android deep links intent injection exported components"
  [07_storage_dump]="android storage sharedpreferences sqlite database keystore"
  [08_findings_report]="android security findings report cvss owasp"
  [09_mobsf_dast]="mobsf android dynamic analysis security testing"
  [10_backup_extract]="android backup adb extract database analysis"
  [11_webview_exploit]="android webview javascript interface ssl error deep link"
  [12_pending_intent]="android pending intent flag mutable intent redirection"
  [13_resilience]="android anti debug root emulator bypass detection"
  [14_crypto_audit]="android cryptography weak algorithms hardcoded keys tls"
  [15_cleanup]="android cleanup frida removal certificate cleanup"
  [16_code_analysis]="android code analysis source code audit secrets dangerous functions logging crypto"
  [17_input_validation]="input validation testing sqli xss ssrf xxe api injection fuzzing"
)

QUERY="${PHASE_SKILLS[$PHASE]:-android security testing}"
PRIMARY="android-pentesting-tricks"
RELATED="mobile-ssl-pinning-bypass, mobile-dynamic-analysis"

mkdir -p "$RUN_DIR"
OUT="$RUN_DIR/${PHASE}.knowledge.md"

{
  echo "# $PHASE - RAG knowledge dispatch"
  echo "primary skill: \`$PRIMARY\` | related: $RELATED"
  echo ""
  echo "## Methodology (RAG retrieval)"
} > "$OUT"

# Query RAG with timeout
timeout 60 rag query "$QUERY" -k 4 2>/dev/null >> "$OUT" || {
  echo "RAG query failed/unavailable - run standalone: rag query \"$QUERY\"" >> "$OUT"
  echo "[warn] RAG query unavailable for $PHASE (see $OUT)"
  exit 0
}

echo ""
echo "== [RAG] $PHASE =="
echo "primary: skill $PRIMARY"
echo "related: $RELATED"
echo "knowledge: $OUT"
echo ""
echo "operator: load via: skill $PRIMARY"
echo "then for any hit: skill <matched-skill>"
