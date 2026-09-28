#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 08_findings_report.sh - Aggregate findings, generate ASSESS and summary reports
PROFILE_PHASE="08_findings_report"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"

cd "$RUN_DIR" || exit 1
info "Generating findings report for $PKG"

REPORT_FILE="$RUN_DIR/REPORT.md"
SUMMARY_FILE="$RUN_DIR/summary.json"
ASSESS_FILE="$RUN_DIR/ASSESS_REPORT.md"

# ---- 1. Read findings DB ----
info "[step-1/6] Reading findings database: $FINDINGS_DB"
TOTAL=$(jq '.findings | length' "$FINDINGS_DB" 2>/dev/null || echo 0)
CRITICAL=$(jq '[.findings[] | select(.severity == "CRITICAL")] | length' "$FINDINGS_DB" 2>/dev/null || echo 0)
HIGH=$(jq '[.findings[] | select(.severity == "HIGH")] | length' "$FINDINGS_DB" 2>/dev/null || echo 0)
MEDIUM=$(jq '[.findings[] | select(.severity == "MEDIUM")] | length' "$FINDINGS_DB" 2>/dev/null || echo 0)
LOW=$(jq '[.findings[] | select(.severity == "LOW")] | length' "$FINDINGS_DB" 2>/dev/null || echo 0)
INFO=$(jq '[.findings[] | select(.severity == "INFO")] | length' "$FINDINGS_DB" 2>/dev/null || echo 0)

info "  Total findings: $TOTAL"
info "  Breakdown: CRITICAL=$CRITICAL | HIGH=$HIGH | MEDIUM=$MEDIUM | LOW=$LOW | INFO=$INFO"

# ---- 2. Generate main report ----
info "[step-2/6] Writing main report: $REPORT_FILE"

cat > "$REPORT_FILE" <<EOF
# Genymotion Pipeline - Security Report

**Package:** $PKG
**Date:** $(date -Iseconds)
**Run Directory:** $RUN_DIR

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | $CRITICAL |
| HIGH | $HIGH |
| MEDIUM | $MEDIUM |
| LOW | $LOW |
| INFO | $INFO |
| **TOTAL** | **$TOTAL** |

---

## Findings

EOF

if [ "$TOTAL" -gt 0 ]; then
  jq -r '.findings[] | "### \(.severity): \(.title)\n\n- **CWE:** \(.cwe)\n- **OWASP:** \(.owasp)\n- **CVSS:** \(.cvss)\n- **Confidence:** \(.confidence)\n- **Phase:** \(.phase)\n- **Timestamp:** \(.timestamp)\n\n**Evidence:**\n\(.evidence | map("- \`\(.\)`") | join("\n"))\n\n---\n"' "$FINDINGS_DB" >> "$REPORT_FILE"
  info "  $TOTAL findings written to report"
else
  echo "*No findings recorded.*" >> "$REPORT_FILE"
  info "  No findings to report"
fi

# ---- 3. Generate JSON summary ----
info "[step-3/6] Writing JSON summary: $SUMMARY_FILE"

cat > "$SUMMARY_FILE" <<EOF
{
  "package": "$PKG",
  "date": "$(date -Iseconds)",
  "run_dir": "$RUN_DIR",
  "findings": {
    "total": $TOTAL,
    "critical": $CRITICAL,
    "high": $HIGH,
    "medium": $MEDIUM,
    "low": $LOW,
    "info": $INFO
  },
  "phases_run": [
    "00_acquire",
    "01_static",
    "02_setup_genymotion",
    "03_dynamic_drozer",
    "03b_dynamic_drozer_mcp",
    "04_dynamic_objection",
    "05_frida_hooks",
    "06_traffic_capture",
    "07_deep_links",
    "07_storage_dump",
    "09_mobsf_dast",
    "10_backup_extract",
    "11_webview_exploit",
    "12_pending_intent",
    "13_resilience",
    "14_crypto_audit",
    "16_code_analysis",
    "17_input_validation",
    "15_cleanup",
    "08_findings_report"
  ]
}
EOF
info "  JSON summary written"

# ---- 4. Print summary to stdout ----
info "[step-4/6] Printing summary to console"
echo ""
echo "=========================================="
echo "  FINDINGS SUMMARY"
echo "=========================================="
echo ""
echo "  Package:   $PKG"
echo "  Date:      $(date -Iseconds)"
echo "  Run Dir:   $RUN_DIR"
echo ""
echo "  CRITICAL:  $CRITICAL"
echo "  HIGH:      $HIGH"
echo "  MEDIUM:    $MEDIUM"
echo "  LOW:       $LOW"
echo "  INFO:      $INFO"
echo "  TOTAL:     $TOTAL"
echo ""
echo "  Report:    $REPORT_FILE"
echo "  Summary:   $SUMMARY_FILE"
echo "  Database:  $FINDINGS_DB"
echo ""
echo "=========================================="

# ---- 5. assessment-format report ----
info "[step-5/6] Generating assessment-format report: $ASSESS_FILE"

if [ "$TOTAL" -gt 0 ]; then
  info "  [assess-1/4] Writing header and summary table"
  cat > "$ASSESS_FILE" <<ASSESS_HEADER
# Security Assessment Report — $PKG

**Date:** $(date -Iseconds)
**Target:** $PKG
**Pipeline:** Genymotion APK Pentesting Pipeline
**Total Findings:** $TOTAL (CRITICAL: $CRITICAL, HIGH: $HIGH, MEDIUM: $MEDIUM, LOW: $LOW, INFO: $INFO)

---

## Finding Summary

| # | Severity | Title | CWE | OWASP | CVSS | Confidence |
|---|----------|-------|-----|-------|------|------------|
ASSESS_HEADER

  SEV_ORDER='CRITICAL HIGH MEDIUM LOW INFO'
  idx=0
  for sev in $SEV_ORDER; do
    while IFS= read -r line; do
      idx=$((idx + 1))
      title=$(echo "$line" | jq -r '.title')
      cwe=$(echo "$line" | jq -r '.cwe')
      owasp=$(echo "$line" | jq -r '.owasp')
      cvss=$(echo "$line" | jq -r '.cvss')
      conf=$(echo "$line" | jq -r '.confidence')
      echo "| $idx | **$sev** | $title | $cwe | $owasp | $cvss | $conf |" >> "$ASSESS_FILE"
    done < <(jq -c ".findings[] | select(.severity == \"$sev\")" "$FINDINGS_DB" 2>/dev/null)
  done
  info "  Summary table written: $idx rows"

  info "  [assess-2/4] Writing detailed findings sections"
  cat >> "$ASSESS_FILE" <<ASSESS_BODY

---

## Detailed Findings

ASSESS_BODY

  idx=0
  for sev in $SEV_ORDER; do
    while IFS= read -r line; do
      idx=$((idx + 1))
      title=$(echo "$line" | jq -r '.title')
      cwe=$(echo "$line" | jq -r '.cwe')
      owasp=$(echo "$line" | jq -r '.owasp')
      cvss=$(echo "$line" | jq -r '.cvss')
      conf=$(echo "$line" | jq -r '.confidence')
      phase=$(echo "$line" | jq -r '.phase')
      ts=$(echo "$line" | jq -r '.timestamp')
      evidence=$(echo "$line" | jq -r '.evidence | map("- `" + . + "`") | join("\n")')

      cat >> "$ASSESS_FILE" <<ASSESS_FINDING
### Finding $idx: $title

**Severity:** $sev | **CWE:** $cwe | **OWASP:** $owasp | **CVSS:** $cvss | **Confidence:** $conf

**Phase:** $phase | **Timestamp:** $ts

**Evidence:**
$evidence

---

ASSESS_FINDING
    done < <(jq -c ".findings[] | select(.severity == \"$sev\")" "$FINDINGS_DB" 2>/dev/null)
  done
  info "  $idx detailed finding sections written"

  # Code analysis section
  info "  [assess-3/4] Appending code analysis results (if present)"
  CODE_DIR="$RUN_DIR/code_analysis"
  if [ -d "$CODE_DIR" ]; then
    cat >> "$ASSESS_FILE" <<ASSESS_CODE

## Code Analysis Summary

ASSESS_CODE
    CODE_ITEMS=0
    for f in "$CODE_DIR"/*.txt; do
      [ -f "$f" ] || continue
      cnt=$(wc -l < "$f")
      [ "$cnt" -eq 0 ] && continue
      name=$(basename "$f" .txt)
      echo "### $name ($cnt items)" >> "$ASSESS_FILE"
      head -20 "$f" | sed 's/^/  /' >> "$ASSESS_FILE"
      [ "$cnt" -gt 20 ] && echo "  ... ($cnt total)" >> "$ASSESS_FILE"
      echo "" >> "$ASSESS_FILE"
      CODE_ITEMS=$((CODE_ITEMS + 1))
    done
    info "  Code analysis categories appended: $CODE_ITEMS"
  else
    info "  No code_analysis directory found; skipping"
  fi

  # Input validation section
  info "  [assess-4/4] Appending input validation results (if present)"
  IV_DIR="$RUN_DIR/input_validation/results"
  if [ -d "$IV_DIR" ]; then
    cat >> "$ASSESS_FILE" <<ASSESS_IV

## Input Validation Results

ASSESS_IV
    IV_ITEMS=0
    for f in "$IV_DIR"/*.txt; do
      [ -f "$f" ] || continue
      cnt=$(wc -l < "$f")
      name=$(basename "$f" .txt)
      if [ "$cnt" -gt 0 ]; then
        echo "### $name — $cnt hits" >> "$ASSESS_FILE"
        head -10 "$f" | sed 's/^/  /' >> "$ASSESS_FILE"
        [ "$cnt" -gt 10 ] && echo "  ... ($cnt total)" >> "$ASSESS_FILE"
      else
        echo "### $name — clean" >> "$ASSESS_FILE"
      fi
      echo "" >> "$ASSESS_FILE"
      IV_ITEMS=$((IV_ITEMS + 1))
    done
    info "  Input validation categories appended: $IV_ITEMS"
  else
    info "  No input_validation directory found; skipping"
  fi

  ok "  assessment report generated: $ASSESS_FILE"
else
  cat > "$ASSESS_FILE" <<EOF
# Security Assessment Report — $PKG

**Date:** $(date -Iseconds)
**Target:** $PKG

No findings recorded.
EOF
  info "  No findings; ASSESS report marked empty"
fi

# ---- 6. Copy reports to findings dir ----
info "[step-6/6] Copying reports to findings directory"

if [ "$TOTAL" -gt 0 ]; then
  TS=$(date +%Y%m%d_%H%M%S)
  cp "$REPORT_FILE" "$FINDINGS_DIR/report_${TS}.md"
  info "  Copied REPORT.md -> $FINDINGS_DIR/report_${TS}.md"
  cp "$ASSESS_FILE" "$FINDINGS_DIR/ASSESS_${TS}.md" 2>/dev/null || true
  info "  Copied ASSESS_REPORT.md -> $FINDINGS_DIR/ASSESS_${TS}.md"
fi

ok "Report generation complete"
ok "  Reports: $REPORT_FILE | $ASSESS_FILE | $SUMMARY_FILE"
ok "  Total findings: $TOTAL (C:$CRITICAL H:$HIGH M:$MEDIUM L:$LOW I:$INFO)"
