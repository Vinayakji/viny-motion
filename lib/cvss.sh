#!/usr/bin/env bash
# lib/cvss.sh - CVSS 4.0 and CVSS 3.1 scoring engine (Python-backed)
# Usage: source lib/cvss.sh; cvss31_calc "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
#        cvss40_calc "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

PIPELINE_DIR="${PIPELINE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
_CVSS_PY="${PIPELINE_DIR}/lib/cvss_calc.py"

# ──────────────────────────────────────────────────────────────────
# CVSS 3.1
# ──────────────────────────────────────────────────────────────────

cvss31_calc() {
  python3 "$_CVSS_PY" 3.1 "$1" 2>/dev/null || echo "0.0"
}

# ──────────────────────────────────────────────────────────────────
# CVSS 4.0
# ──────────────────────────────────────────────────────────────────

cvss40_calc() {
  python3 "$_CVSS_PY" 4.0 "$1" 2>/dev/null || echo "0.0"
}

# ──────────────────────────────────────────────────────────────────
# Helper: severity from score
# ──────────────────────────────────────────────────────────────────

cvss_severity() {
  python3 "$_CVSS_PY" severity "$1" 2>/dev/null || echo "INFO"
}

# ──────────────────────────────────────────────────────────────────
# Helper: build CVSS 3.1 vector from short params
# ──────────────────────────────────────────────────────────────────

cvss31_build() {
  local av="${1:-N}" ac="${2:-L}" pr="${3:-N}" ui="${4:-N}" s="${5:-U}" c="${6:-H}" i="${7:-H}" a="${8:-H}"
  echo "CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:${s}/C:${c}/I:${i}/A:${a}"
}

# ──────────────────────────────────────────────────────────────────
# Quick severity lookup (backward compat)
# ──────────────────────────────────────────────────────────────────

sev_score() {
  case "${1:-}" in
    CRITICAL) echo 9.8;; HIGH) echo 7.5;; MEDIUM) echo 5.3;;
    LOW) echo 3.1;; INFO) echo 0.0;; *) echo 0.0;;
  esac
}

# ──────────────────────────────────────────────────────────────────
# Batch score all findings in a JSON file
# ──────────────────────────────────────────────────────────────────

cvss_batch() {
  local findings_file="${1:-$FINDINGS_DIR/findings.json}"
  python3 "$_CVSS_PY" batch "$findings_file" 2>/dev/null
}

# ──────────────────────────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────────────────────────

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  case "${1:-}" in
    3.1|31)    shift; cvss31_calc "$@" ;;
    4.0|40)    shift; cvss40_calc "$@" ;;
    severity)  shift; cvss_severity "$@" ;;
    build)     shift; cvss31_build "$@" ;;
    batch)     shift; cvss_batch "$@" ;;
    *)
      echo "Usage: cvss.sh {3.1|4.0|severity|build|batch} <vector|findings.json>"
      echo ""
      echo "Examples:"
      echo "  cvss.sh 3.1 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'"
      echo "  cvss.sh 4.0 'AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'"
      echo "  cvss.sh severity 7.5"
      echo "  cvss.sh build N L N N U H H H"
      echo "  cvss.sh batch findings/findings.json"
      ;;
  esac
fi
