#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

fail() {
  echo "[FAIL] $*"
  exit 1
}

echo "[INFO] Verifying phase list -> phase scripts consistency"
mapfile -t phases < <(awk '
  /PHASES=\(/ {in_arr=1; next}
  in_arr && /\)/ {in_arr=0; next}
  in_arr {
    for (i=1; i<=NF; i++) print $i
  }
' run.sh)

[ "${#phases[@]}" -gt 0 ] || fail "No phases parsed from run.sh"
for ph in "${phases[@]}"; do
  [ -f "phases/${ph}.sh" ] || fail "Missing phase script phases/${ph}.sh"
done

echo "[INFO] Verifying setup template includes authorization gate key"
grep -q '^target:' setup.sh || fail "setup.sh template missing target block"
grep -q 'authorization_ref:' setup.sh || fail "setup.sh template missing authorization_ref"

echo "[INFO] Verifying no reference to missing skill_dispatcher.sh"
if grep -q 'lib/skill_dispatcher.sh' run_android_pipeline.sh; then
  fail "run_android_pipeline.sh still references missing lib/skill_dispatcher.sh"
fi

echo "[INFO] Verifying optional LAYA fallback hooks exist"
grep -q 'laya_health_check() { return 0; }' run.sh || fail "run.sh missing laya_health_check fallback"
grep -q 'laya_gate() { return 0; }' run.sh || fail "run.sh missing laya_gate fallback"

echo "[INFO] Verifying README uses prefixed phase script names"
grep -q '`00_acquire.sh`' README.md || fail "README missing 00_acquire.sh"
grep -q '`19_rasp_bypass.sh`' README.md || fail "README missing 19_rasp_bypass.sh"

echo "[OK] Smoke checks passed"
