#!/usr/bin/env bash
# lib/findings.sh - findings DB for Genymotion pipeline
# v2: Schema-validated, CVSS 4.0 support, confidence levels, finding states

PIPELINE_DIR="${PIPELINE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
FINDINGS_DB="${FINDINGS_DB:-$FINDINGS_DIR/findings.json}"
FINDINGS_SCHEMA="${PIPELINE_DIR}/config/findings-schema.json"

[ -f "$FINDINGS_DB" ] || echo '{"findings":[],"_next_id":1,"metadata":{}}' > "$FINDINGS_DB"

# Ensure _next_id exists (backward compat with old DBs without it)
if ! jq -e '._next_id' "$FINDINGS_DB" >/dev/null 2>&1; then
  MAX_ID=$(jq '[.findings[].id | ltrimstr("F-") | tonumber] | max // 0' "$FINDINGS_DB")
  NEXT=$((MAX_ID + 1))
  jq --argjson n "$NEXT" '._next_id = $n' "$FINDINGS_DB" > "$FINDINGS_DB.tmp" && mv "$FINDINGS_DB.tmp" "$FINDINGS_DB"
fi

# Source CVSS engine
[[ -f "$PIPELINE_DIR/lib/cvss.sh" ]] && source "$PIPELINE_DIR/lib/cvss.sh"

# ──────────────────────────────────────────────────────────────────
# Confidence levels (DragonJAR-aligned)
# ──────────────────────────────────────────────────────────────────
# CONFIRMED    — PoC demonstrated, no ambiguity
# PROBABLE     — Source evidence + propagation + sink identified
# SUSPECTED    — Likely but needs dynamic confirmation
# INFORMATIONAL — Observation or hardening note

# ──────────────────────────────────────────────────────────────────
# Finding states
# ──────────────────────────────────────────────────────────────────
# open          — Newly discovered, not triaged
# confirmed     — Verified by operator
# false-positive — Incorrectly flagged
# fixed         — Remediation confirmed
# deferred      — Acknowledged, not fixing now
# accepted      — Risk accepted by stakeholder

# ──────────────────────────────────────────────────────────────────
# fadd() — add finding (backward-compatible + new fields)
# ──────────────────────────────────────────────────────────────────
# Usage: fadd "Title" "SEVERITY" "CONFIDENCE" "CWE-xxx" "A01:2021" [evidence_files...]
# Extended: fadd "Title" "SEV" "CONF" "CWE" "OWASP" --cvss 7.5 --vector "CVSS:..." --masvs "MASVS-..." --remediation "Fix..." --component "com.foo.Bar" --tags "tag1,tag2"

fadd() {
  local title="$1" sev="$2" conf="$3" cwe="$4" owasp="$5"
  shift 5

  # Parse optional extended flags
  local cvss_val="" cvss_vector="" cvss_ver="3.1" masvs="" remediation="" component="" tags_str="" refs_str=""
  local evidence_files=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --cvss)     cvss_val="$2"; shift 2 ;;
      --vector)   cvss_vector="$2"; shift 2 ;;
      --masvs)    masvs="$2"; shift 2 ;;
      --remediation) remediation="$2"; shift 2 ;;
      --component) component="$2"; shift 2 ;;
      --tags)     tags_str="$2"; shift 2 ;;
      --refs)     refs_str="$2"; shift 2 ;;
      --status)   ;; # handled below
      --phase)    ;; # handled below
      *)          evidence_files+=("$1") ;;
    esac
    shift
  done

  # Auto-compute CVSS if not provided
  if [[ -z "$cvss_val" ]]; then
    if [[ -n "$cvss_vector" ]]; then
      cvss_val=$(cvss31_calc "$cvss_vector" 2>/dev/null || sev_score "$sev")
    else
      cvss_val=$(sev_score "$sev")
    fi
  fi

  # Auto-derive severity from CVSS if score provided
  if [[ -n "$cvss_val" && -z "$sev" ]]; then
    sev=$(cvss_severity "$cvss_val")
  fi

  # Build evidence array
  local ev="[]" f
  for f in "${evidence_files[@]}"; do
    [ -f "$f" ] && ev="$(echo "$ev" | jq -c --arg p "$f" '. + [$p]')"
  done

  # Build tags array
  local tags_json="[]"
  if [[ -n "$tags_str" ]]; then
    IFS=',' read -ra tag_arr <<< "$tags_str"
    tags_json=$(printf '%s\n' "${tag_arr[@]}" | jq -R . | jq -s .)
  fi

  # Build references array
  local refs_json="[]"
  if [[ -n "$refs_str" ]]; then
    IFS=',' read -ra ref_arr <<< "$refs_str"
    refs_json=$(printf '%s\n' "${ref_arr[@]}" | jq -R . | jq -s .)
  fi

  # Insert finding
  jq \
    --arg t "$title" \
    --arg s "$sev" \
    --arg c "$conf" \
    --arg cwe "$cwe" \
    --arg oa "$owasp" \
    --argjson cvss "$cvss_val" \
    --arg vector "$cvss_vector" \
    --arg ver "$cvss_ver" \
    --arg masvs "$masvs" \
    --arg rem "$remediation" \
    --arg comp "$component" \
    --argjson ev "$ev" \
    --argjson tags "$tags_json" \
    --argjson refs "$refs_json" \
    --arg ts "$(date -Iseconds)" \
    --arg phase "${PROFILE_PHASE:-manual}" \
    '.findings += [{
       id: ("F-" + (._next_id | tostring)),
       title: $t,
       severity: $s,
       confidence: $c,
       cwe: $cwe,
       owasp: $oa,
       cvss: $cvss,
       cvss_vector: $vector,
       cvss_version: $ver,
       masvs: $masvs,
       evidence: $ev,
       status: "open",
       phase: $phase,
       timestamp: $ts,
       remediation: $rem,
       affected_component: $comp,
       references: $refs,
       tags: $tags
    }]
    | ._next_id += 1' "$FINDINGS_DB" > "$FINDINGS_DB.tmp" && mv "$FINDINGS_DB.tmp" "$FINDINGS_DB"

  echo "[findings] Added F-$(jq '._next_id - 1' "$FINDINGS_DB") [$sev] $title"
}

# ──────────────────────────────────────────────────────────────────
# fupdate() — update a finding field by ID
# ──────────────────────────────────────────────────────────────────
fupdate() {
  local fid="$1" field="$2" value="$3"
  jq --arg id "$fid" --arg f "$field" --arg v "$value" \
    '(.findings[] | select(.id == $id))[$f] = $v' \
    "$FINDINGS_DB" > "$FINDINGS_DB.tmp" && mv "$FINDINGS_DB.tmp" "$FINDINGS_DB"
}

# ──────────────────────────────────────────────────────────────────
# ftriage() — set finding status
# ──────────────────────────────────────────────────────────────────
ftriage() {
  local fid="$1" new_status="$2"
  local valid=("open" "confirmed" "false-positive" "fixed" "deferred" "accepted")
  local ok=false
  for v in "${valid[@]}"; do [[ "$v" == "$new_status" ]] && ok=true; done
  [[ "$ok" != "true" ]] && { echo "[findings] Invalid status: $new_status"; return 1; }
  fupdate "$fid" "status" "$new_status"
  echo "[findings] $fid → $new_status"
}

# ──────────────────────────────────────────────────────────────────
# fsnapshot() — human-readable summary
# ──────────────────────────────────────────────────────────────────
fsnapshot() {
  local total=$(jq '.findings | length' "$FINDINGS_DB")
  local open=$(jq '[.findings[] | select(.status == "open")] | length' "$FINDINGS_DB")
  local confirmed=$(jq '[.findings[] | select(.status == "confirmed")] | length' "$FINDINGS_DB")
  local fp=$(jq '[.findings[] | select(.status == "false-positive")] | length' "$FINDINGS_DB")

  echo "=== FINDINGS ($total total, $open open, $confirmed confirmed, $fp false-positive) ==="
  echo ""
  echo "--- HIGH / CRITICAL ---"
  jq -r '.findings[] | select(.severity == "HIGH" or .severity == "CRITICAL") | "  [\(.status)] \(.severity) \(.id) \(.confidence) | \(.cwe) \(.title)"' "$FINDINGS_DB" 2>/dev/null
  echo ""
  echo "--- MEDIUM ---"
  jq -r '.findings[] | select(.severity == "MEDIUM") | "  [\(.status)] \(.id) \(.confidence) | \(.cwe) \(.title)"' "$FINDINGS_DB" 2>/dev/null
  echo ""
  echo "--- LOW / INFO ---"
  jq -r '.findings[] | select(.severity == "LOW" or .severity == "INFO") | "  [\(.status)] \(.id) \(.confidence) | \(.cwe) \(.title)"' "$FINDINGS_DB" 2>/dev/null
}

# ──────────────────────────────────────────────────────────────────
# fexport() — export findings as CSV
# ──────────────────────────────────────────────────────────────────
fexport() {
  local out="${1:-$FINDINGS_DIR/findings.csv}"
  echo "id,title,severity,confidence,cvss,cwe,owasp,status,phase" > "$out"
  jq -r '.findings[] | [.id, .title, .severity, .confidence, (.cvss|tostring), .cwe, .owasp, .status, .phase] | @csv' "$FINDINGS_DB" >> "$out"
  echo "[findings] Exported $out"
}

# ──────────────────────────────────────────────────────────────────
# fvalidate() — validate DB against schema
# ──────────────────────────────────────────────────────────────────
fvalidate() {
  if [[ ! -f "$FINDINGS_SCHEMA" ]]; then
    echo "[findings] Schema not found: $FINDINGS_SCHEMA"; return 1
  fi
  if command -v jq &>/dev/null; then
    local count=$(jq '.findings | length' "$FINDINGS_DB")
    local invalid=$(jq '[.findings[] | select(.id == null or .title == null or .severity == null)] | length' "$FINDINGS_DB")
    echo "[findings] $count findings, $invalid invalid (missing required fields)"
    [[ "$invalid" -gt 0 ]] && return 1
  fi
}

# ──────────────────────────────────────────────────────────────────
# fstats() — summary statistics
# ──────────────────────────────────────────────────────────────────
fstats() {
  echo "=== FINDINGS STATISTICS ==="
  echo "Total:       $(jq '.findings | length' "$FINDINGS_DB")"
  echo "CRITICAL:    $(jq '[.findings[] | select(.severity == "CRITICAL")] | length' "$FINDINGS_DB")"
  echo "HIGH:        $(jq '[.findings[] | select(.severity == "HIGH")] | length' "$FINDINGS_DB")"
  echo "MEDIUM:      $(jq '[.findings[] | select(.severity == "MEDIUM")] | length' "$FINDINGS_DB")"
  echo "LOW:         $(jq '[.findings[] | select(.severity == "LOW")] | length' "$FINDINGS_DB")"
  echo "INFO:        $(jq '[.findings[] | select(.severity == "INFO")] | length' "$FINDINGS_DB")"
  echo ""
  echo "CONFIRMED:   $(jq '[.findings[] | select(.confidence == "CONFIRMED")] | length' "$FINDINGS_DB")"
  echo "PROBABLE:    $(jq '[.findings[] | select(.confidence == "PROBABLE")] | length' "$FINDINGS_DB")"
  echo "SUSPECTED:   $(jq '[.findings[] | select(.confidence == "SUSPECTED")] | length' "$FINDINGS_DB")"
  echo "INFO:        $(jq '[.findings[] | select(.confidence == "INFORMATIONAL")] | length' "$FINDINGS_DB")"
  echo ""
  echo "Open:        $(jq '[.findings[] | select(.status == "open")] | length' "$FINDINGS_DB")"
  echo "Confirmed:   $(jq '[.findings[] | select(.status == "confirmed")] | length' "$FINDINGS_DB")"
  echo "False-pos:   $(jq '[.findings[] | select(.status == "false-positive")] | length' "$FINDINGS_DB")"
  echo "Fixed:       $(jq '[.findings[] | select(.status == "fixed")] | length' "$FINDINGS_DB")"
  echo ""
  local avg_cvss=$(jq '[.findings[].cvss] | add / length' "$FINDINGS_DB" 2>/dev/null || echo "0")
  echo "Avg CVSS:    $avg_cvss"
}
