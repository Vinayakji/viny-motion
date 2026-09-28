#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 19_rasp_bypass.sh - Comprehensive RASP bypass: fingerprint -> inventory -> deploy -> verify
#   Automates the methodology in docs/rasp-bypass.md. Validation on a real rooted device
#   is REQUIRED before a finding is reported as CONFIRMED (see doc caveats).
PROFILE_PHASE="19_rasp_bypass"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
[ -z "$PKG" ] && { err "No package_name"; exit 1; }
[ -x "$(command -v frida)" ] || { warn "frida not installed — skipping RASP bypass"; exit 0; }

cd "$RUN_DIR" || exit 1
RASP_DIR="$RUN_DIR/rasp_bypass"
mkdir -p "$RASP_DIR"
JADX_SRC="$RUN_DIR/jadx_output/sources"
SCRIPT_DIR="$PIPELINE_ROOT/extras/frida-scripts"

# ============================================================
# 1. Fingerprint the RASP solution
# ============================================================
info "=== 1. Fingerprinting RASP solution ==="
RASP_FP="$RASP_DIR/rasp_fingerprint.txt"
: > "$RASP_FP"
while read -r name marker; do
  [ -d "$JADX_SRC" ] || break
  if grep -rqiE "$marker" "$JADX_SRC" 2>/dev/null; then
    echo "DETECTED $name ($marker)" >> "$RASP_FP"
    info "  RASP: $name"
  fi
done <<'EOF'
PromonSHIELD com.promon
Guardsquare com.guardsquare
GuardsquareRASP dexguard
CrowdStrike crowdstrike
Zimperium zimperium
ThreatMetrix threatmetrix
PlayIntegrity play.integrity
SafetyNet safetynet
EOF
[ -s "$RASP_FP" ] && RASP_KNOWN=$(wc -l < "$RASP_FP") || RASP_KNOWN=0
info "  Known RASP SDKs detected: $RASP_KNOWN"
fadd "RASP / hardening present ($RASP_KNOWN known SDKs)" INFO INFO CWE-353 "A07:2021" --tags "rasp,resilience" "$RASP_FP"

# ============================================================
# 2. Inventory detection vectors
# ============================================================
info "=== 2. Inventorying detection vectors ==="
VEC="$RASP_DIR/detection_vectors.txt"
: > "$VEC"
[ -d "$JADX_SRC" ] && {
  grep -rnoE "RootBeer|isRooted|checkRoot|findBinary.*su|Magisk|SafetyNet|isDeviceRooted" "$JADX_SRC" 2>/dev/null | head -8 >> "$VEC"
  grep -rnoE "ro\.kernel\.qemu|goldfish|ranchu|generic\.x86|Build\.(FINGERPRINT|MODEL|DEVICE|HARDWARE)" "$JADX_SRC" 2>/dev/null | head -8 >> "$VEC"
  grep -rnoE "isDebuggerConnected|waitingForDebugger|TracerPid|ptrace" "$JADX_SRC" 2>/dev/null | head -8 >> "$VEC"
  grep -rnoE "getPackageInfo.*(SIGNATURES|SIGNING)|MessageDigest|\.apk.*sha|integrity|checksum" "$JADX_SRC" 2>/dev/null | head -8 >> "$VEC"
  grep -rnoE "27042|frida-agent|gum-js-loop|frida-server|D-Bus|linjector" "$JADX_SRC" 2>/dev/null | head -8 >> "$VEC"
}
VEC_COUNT=$(wc -l < "$VEC" 2>/dev/null || echo 0)
info "  Detection vectors found: $VEC_COUNT"

# ============================================================
# 3. Deploy bypass scripts
# ============================================================
info "=== 3. Deploying bypass scripts ==="
run_bypass() {
  local name="$1" script="$2"
  [ -f "$script" ] || { warn "  missing $name script"; return; }
  info "  [$name] spawning $PKG with frida..."
  timeout 25 frida -U -f "$PKG" -l "$script" --no-pause 2>/dev/null > "$RASP_DIR/${name}.log" &
  local pid=$!
  sleep 12
  kill $pid 2>/dev/null
  # did the process survive / reach a non-blocked state?
  if "$(command -v "$HOME/android-sdk/platform-tools/adb" || echo adb)" shell pidof "$PKG" >/dev/null 2>&1; then
    echo "$name: app alive under bypass" >> "$RASP_DIR/bypass_results.txt"
    ok "  [$name] app stayed alive"
  else
    echo "$name: app died/blocked" >> "$RASP_DIR/bypass_results.txt"
    warn "  [$name] app blocked/terminated"
  fi
}

ADB="${VINY_ADB:-$(command -v adb)}"
run_bypass rasp-bypass "$SCRIPT_DIR/rasp-bypass.js"
run_bypass root-bypass "$SCRIPT_DIR/root-bypass.js"
run_bypass emulator-bypass "$SCRIPT_DIR/emulator-detection-bypass.js"
run_bypass anti-debug "$SCRIPT_DIR/anti-debug.js"
run_bypass anti-frida "$SCRIPT_DIR/android-anti-frida-countermeasures.js"

BYPASS_OK=$(grep -c "app alive" "$RASP_DIR/bypass_results.txt" 2>/dev/null || echo 0)
info "  Bypass scripts with app alive: $BYPASS_OK/5"

# ============================================================
# 4. Magisk DenyList (hide root from the app) if Magisk present
# ============================================================
info "=== 4. Magisk DenyList ==="
if "$ADB" shell "ls /data/adb/magisk 2>/dev/null" | grep -q .; then
  "$ADB" shell "su -c 'magisk --denylist enable && magisk --denylist add com.google.android.gms $PKG'" 2>/dev/null \
    && ok "  DenyList enabled for $PKG" \
    || warn "  DenyList config failed"
else
  warn "  Magisk not present on this image — DenyList skipped"
fi

# ============================================================
# 5. Verify: app reaches normal UI (compare focused activity)
# ============================================================
info "=== 5. Verifying bypass (focused activity) ==="
BEFORE=$("$ADB" shell "dumpsys window | grep mCurrentFocus" 2>/dev/null | tr -d '\r' | head -1)
"$ADB" shell am start -n "$PKG"/"$(aapt dump badging "$RUN_DIR" 2>/dev/null | grep -m1 launchable-activity | grep -oE "name='[^']+'" | cut -d"'" -f2)" 2>/dev/null || \
  "$ADB" shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
sleep 6
AFTER=$("$ADB" shell "dumpsys window | grep mCurrentFocus" 2>/dev/null | tr -d '\r' | head -1)
echo "before: $BEFORE" > "$RASP_DIR/focus_before_after.txt"
echo "after:  $AFTER" >> "$RASP_DIR/focus_before_after.txt"
info "  before: $BEFORE"
info "  after:  $AFTER"
if [ "$BYPASS_OK" -gt 0 ] && [ -n "$AFTER" ] && echo "$AFTER" | grep -qiE "$PKG"; then
  ok "  App reached its own UI under bypass"
  fadd "RASP security checks bypassed at runtime ($BYPASS_OK/5 vectors, app reached UI)" HIGH SUSPECTED CWE-284 "A05:2021" --component "$PKG" --tags "rasp,bypass,frida" --remediation "Confirm on a real rooted device before reporting as CONFIRMED; harden RASP with hardware-backed attestation and anti-instrumentation" "$RASP_DIR/bypass_results.txt" "$RASP_DIR/focus_before_after.txt"
else
  warn "  No confirmed bypass — app blocked under all attempts"
  fadd "RASP detected but no bypass achieved on emulator ($BYPASS_OK/5)" LOW SUSPECTED CWE-284 "A05:2021" --tags "rasp" --remediation "Retest on a real rooted device with Magisk DenyList/Zygisk + Shamiko and on-device Frida gadget" "$RASP_DIR/bypass_results.txt"
fi

info "=== RASP bypass report: $RASP_DIR ==="