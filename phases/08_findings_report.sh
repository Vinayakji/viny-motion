#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 08_findings_report.sh - Aggregate findings, generate report
PROFILE_PHASE="08_findings_report"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"

cd "$RUN_DIR" || exit 1
info "Generating findings report"

REPORT_FILE="$RUN_DIR/REPORT.md"
SUMMARY_FILE="$RUN_DIR/summary.json"

# ---- 1. Read findings DB ----
TOTAL=$(jq '.findings | length' "$FINDINGS_DB" 2>/dev/null || echo 0)
CRITICAL=$(jq '[.findings[] | select(.severity == "CRITICAL")] | length' "$FINDINGS_DB" 2>/dev/null || echo 0)
HIGH=$(jq '[.findings[] | select(.severity == "HIGH")] | length' "$FINDINGS_DB" 2>/dev/null || echo 0)
MEDIUM=$(jq '[.findings[] | select(.severity == "MEDIUM")] | length' "$FINDINGS_DB" 2>/dev/null || echo 0)
LOW=$(jq '[.findings[] | select(.severity == "LOW")] | length' "$FINDINGS_DB" 2>/dev/null || echo 0)
INFO=$(jq '[.findings[] | select(.severity == "INFO")] | length' "$FINDINGS_DB" 2>/dev/null || echo 0)

# ---- 2. Generate report ----
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

# List each finding
if [ "$TOTAL" -gt 0 ]; then
  jq -r '.findings[] | "### \(.severity): \(.title)\n\n- **CWE:** \(.cwe)\n- **OWASP:** \(.owasp)\n- **CVSS:** \(.cvss)\n- **Confidence:** \(.confidence)\n- **Phase:** \(.phase)\n- **Timestamp:** \(.timestamp)\n\n**Evidence:**\n\(.evidence | map("- `\(.)`") | join("\n"))\n\n---\n"' "$FINDINGS_DB" >> "$REPORT_FILE"
else
  echo "*No findings recorded.*" >> "$REPORT_FILE"
fi

# ---- 3. Generate JSON summary ----
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
    "04_dynamic_objection",
    "05_frida_hooks",
    "06_traffic_capture",
    "07_storage_dump",
    "08_findings_report"
  ]
}
EOF

# ---- 4. Print summary ----
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

# ---- 5. Copy report to findings dir ----
if [ "$TOTAL" -gt 0 ]; then
  cp "$REPORT_FILE" "$FINDINGS_DIR/report_$(date +%Y%m%d_%H%M%S).md"
  ok "Report copied to findings directory"
fi

ok "Report generation complete"
