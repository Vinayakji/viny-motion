#!/usr/bin/env bash
# extras/skill_dispatch.sh - Inject REAL skill knowledge into the phase run.
# Reads ~/.config/opencode/skills/<skill>/SKILL.md for the phase, extracts methodology
# headings + payload code blocks (grep/python-verified from source, with provenance),
# and writes:
#   <run>/<phase>.knowledge.md   — methodology sections the phase relies on
#   <run>/<phase>.payloads.txt   — payload lines extracted from the skill (capped, deduped)
# Grounded: every line traces to an actual skill file. No hallucination, no overload.
# Usage: ./skill_dispatch.sh <phase> [run_dir]
set -uo pipefail

PHASE="${1:-}"
[ -z "$PHASE" ] && { echo "usage: $0 <phase>"; exit 1; }
SKILLS_DIR="${SKILLS_DIR:-$HOME/.config/opencode/skills}"
RUN_DIR="${2:-${REUSE_RUN_DIR:-.}}"
mkdir -p "$RUN_DIR"

declare -A PHASE_SKILLS=(
  [00_acquire]="apk-redteam-pipeline"
  [01_static]="android-attack-surface-classification android-app-bundle-analysis mobile-binary-protection"
  [02_setup_viny_motion]="android-emulator-detection-bypass android-kernel-rooting-strategies mobile-dynamic-analysis"
  [03_dynamic_drozer]="android-intent-ipc-security android-content-provider-deep"
  [03b_dynamic_drozer_mcp]="android-intent-ipc-security android-content-provider-deep"
  [04_dynamic_objection]="mobile-dynamic-analysis android-pentesting-tricks mobile-ssl-pinning-bypass"
  [05_frida_hooks]="android-pentesting-tricks mobile-ssl-pinning-bypass android-rasp-anti-tamper-bypass"
  [06_traffic_capture]="android-network-security-deep mobile-api-security"
  [07_deep_links]="android-deep-link-attacks android-intent-ipc-security"
  [07_storage_dump]="android-storage-crypto-security android-forensics-artifacts"
  [09_mobsf_dast]="android-automated-security-testing"
  [10_backup_extract]="android-forensics-artifacts android-storage-crypto-security"
  [11_webview_exploit]="android-webview-deep-security android-pentesting-tricks"
  [12_pending_intent]="android-intent-ipc-security"
  [13_resilience]="android-rasp-anti-tamper-bypass android-emulator-detection-bypass android-play-integrity-attestation"
  [14_crypto_audit]="android-storage-crypto-security"
  [16_code_analysis]="android-systems-deep mobile-binary-protection"
  [17_input_validation]="injection-checking api-sec"
  [18_dastforge]="sqli-sql-injection xss-cross-site-scripting ssrf-server-side-request-forgery cmdi-command-injection ssti-server-side-template-injection idor-broken-object-authorization api-auth-and-jwt-abuse nosql-injection path-traversal-lfi open-redirect"
  [19_rasp_bypass]="android-rasp-anti-tamper-bypass android-play-integrity-attestation"
)

KNOW="$RUN_DIR/${PHASE}.knowledge.md"
PAY="$RUN_DIR/${PHASE}.payloads.txt"
: > "$KNOW"; : > "$PAY"
echo "# $PHASE — skill knowledge (grounded in skill files)" > "$KNOW"

extract_payloads() { # $1=skillfile $2=outfile -> prints count
  python3 - "$1" "$2" <<'PY'
import sys, re
text = open(sys.argv[1], errors="ignore").read()
blocks = re.findall(r"```(?:\w+)?\n(.*?)```", text, re.S)
seen, out = set(), []
for b in blocks:
    for ln in b.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#") or ln.startswith("//"): continue
        if 4 <= len(ln) <= 200 and any(c in ln for c in "=';(){}<>\"\\$"):
            if ln not in seen:
                seen.add(ln); out.append(ln)
open(sys.argv[2], "a").write("\n".join(out[:40]) + "\n")
print(len(out[:40]))
PY
}

TOTAL=0
for skill in ${PHASE_SKILLS[$PHASE]:-android-pentesting-tricks}; do
  f="$SKILLS_DIR/$skill/SKILL.md"
  if [ ! -f "$f" ]; then
    echo "  - [MISSING] $skill (skill not installed)" >> "$KNOW"
    continue
  fi
  {
    echo ""
    echo "## source: \`$skill\` (SKILL.md)"
    echo "### methodology headings"
    grep -E '^#{1,3} ' "$f" | head -12
  } >> "$KNOW"
  n=$(extract_payloads "$f" "$PAY")
  TOTAL=$((TOTAL + n))
  echo "  - payload lines extracted: $n" >> "$KNOW"
done
{
  echo ""
  echo "Total grounded payload lines: $TOTAL (capped per skill, deduped)"
  echo "Findings still require the phase's 2-signal / differential confirmation."
} >> "$KNOW"
echo "[skill_dispatch] $PHASE -> ${TOTAL} grounded payload lines (see ${PHASE}.knowledge.md / ${PHASE}.payloads.txt)"