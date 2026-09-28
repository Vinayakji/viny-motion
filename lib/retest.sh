#!/usr/bin/env bash
# lib/retest.sh — retest / closure workflow for findings.
# Loads a previous findings DB, tracks per-finding verification status,
# and generates a retest report for the engagement's closure phase.
#
# API:
#   retest_generate [findings_db]            -> retest_report.md + retest_status.json
#   retest_mark <finding-id> <FIXED|OPEN|PARTIAL> [note]
#   retest_summary [findings_db]

RETEST_STATUS="${RETEST_STATUS_FILE:-$FINDINGS_DIR/retest_status.json}"
RETEST_REPORT="$RUN_DIR/retest_report.md"

retest_init() {
  [ -f "$RETEST_STATUS" ] || echo '{"retests":{}}' > "$RETEST_STATUS"
}

retest_mark() {
  local id="$1" st="$2" note="${3:-}"
  case "$st" in FIXED|OPEN|PARTIAL) ;; *) err "retest_mark: status must be FIXED|OPEN|PARTIAL"; return 1 ;; esac
  retest_init
  jq --arg id "$id" --arg st "$st" --arg note "$note" --arg ts "$(date -Iseconds)" \
    '.retests[$id] = {status: $st, note: $note, updated: $ts}' \
    "$RETEST_STATUS" > "$RETEST_STATUS.tmp" && mv "$RETEST_STATUS.tmp" "$RETEST_STATUS"
  ok "retest: $id -> $st"
}

retest_generate() {
  local db="${1:-$FINDINGS_DB}"
  [ -f "$db" ] || { err "retest: findings DB not found: $db"; return 1; }
  retest_init

  local total open fixed partial
  total=$(jq '.findings | length' "$db" 2>/dev/null || echo 0)
  open=$(jq '[.findings[] | select(.status == "open")] | length' "$db" 2>/dev/null || echo 0)
  fixed=$(jq --argjson rs "$(cat "$RETEST_STATUS")" '[.findings[] | select($rs.retests[.id].status == "FIXED")] | length' "$db" 2>/dev/null || echo 0)
  partial=$(jq --argjson rs "$(cat "$RETEST_STATUS")" '[.findings[] | select($rs.retests[.id].status == "PARTIAL")] | length' "$db" 2>/dev/null || echo 0)

  {
    echo "# RETEST REPORT"
    echo
    echo "- Generated: $(date -Iseconds)"
    echo "- Findings DB: $db"
    echo "- Total findings: $total | verified FIXED: $fixed | PARTIAL: $partial | pending: $open"
    echo
    echo "## Verification checklist"
    echo
    echo "| # | ID | Severity | Title | Retest status | Evidence files |"
    echo "|---|---|---|---|---|---|"
    jq -r --argjson rs "$(cat "$RETEST_STATUS")" '
      .findings | to_entries[] |
      (($rs.retests[.value.id].status // "OPEN")) as $st |
      "\(.key+1) | \(.value.id) | \(.value.severity) | \(.value.title) | \($st) | \(.value.evidence | join(", "))"
    ' "$db"
    echo
    echo "## Retest procedure"
    echo
    echo "For each finding:"
    echo "1. Re-run the original reproduction steps (evidence files + payloads in the finding)."
    echo "2. Compare response/behavior against the original evidence."
    echo "3. Mark with: retest_mark <finding-id> FIXED|OPEN|PARTIAL \"note\""
    echo "4. FIXED only when the original trigger no longer reproduces on the fixed target."
  } > "$RETEST_REPORT"
  ok "retest report: $RETEST_REPORT"
}

retest_summary() {
  local db="${1:-$FINDINGS_DB}"
  [ -f "$db" ] || { err "retest: findings DB not found: $db"; return 1; }
  [ -f "$RETEST_STATUS" ] || { warn "retest: no status file yet — run retest_generate first"; return 0; }
  jq -r '.retests | to_entries[] | "\(.key)\t\(.value.status)\t\(.value.note)\t\(.value.updated)"' "$RETEST_STATUS" 2>/dev/null
}