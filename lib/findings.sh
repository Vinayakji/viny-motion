#!/usr/bin/env bash
# lib/findings.sh - findings DB for Genymotion pipeline
FINDINGS_DB="$FINDINGS_DIR/findings.json"
[ -f "$FINDINGS_DB" ] || echo '{"findings":[]}' > "$FINDINGS_DB"

sev_score() {
  case "${1:-}" in
    CRITICAL) echo 9.8;; HIGH) echo 7.5;; MEDIUM) echo 5.3;;
    LOW) echo 3.1;; INFO) echo 0.0;; *) echo 0.0;;
  esac
}

fadd() {
  local title="$1" sev="$2" conf="$3" cwe="$4" owasp="$5"; shift 5
  local ev="[]" f
  for f in "$@"; do
    [ -f "$f" ] && ev="$(echo "$ev" | jq -c --arg p "$f" '. + [$p]')"
  done
  jq --arg t "$title" --arg s "$sev" --arg c "$conf" \
     --arg cwe "$cwe" --arg oa "$owasp" --argjson ev "$ev" --arg ts "$(date -Iseconds)" \
     '.findings += [{
        id: ("F-" + (now|tostring|split(".")[0])),
        title: $t, severity: $s, confidence: $c, cwe: $cwe, owasp: $oa,
        cvss: ('"$(sev_score "$sev")"'), evidence: $ev, status: "open",
        phase: "'"${PROFILE_PHASE:-manual}"'", timestamp: $ts
     }]' "$FINDINGS_DB" > "$FINDINGS_DB.tmp" && mv "$FINDINGS_DB.tmp" "$FINDINGS_DB"
}

fsnapshot() {
  echo "=== FINDINGS ($(jq '.findings|length' "$FINDINGS_DB")) ==="
  jq -r '.findings[] | "\(.severity)\t\(.confidence)\t\(.cwe)\t\(.title)\t[\(.phase)]"' "$FINDINGS_DB" 2>/dev/null | sort -r
}
