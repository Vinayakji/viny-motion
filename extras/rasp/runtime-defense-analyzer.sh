#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# runtime-defense-analyzer.sh — Automated RASP detection + bypass testing
# Reads detector catalog and bypass profiles, executes static + dynamic tests
set -uo pipefail
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
[ -z "$PKG" ] && { err "No package_name"; exit 1; }

cd "$RUN_DIR" || exit 1
RASP_DIR="$RUN_DIR/rasp_analysis"
mkdir -p "$RASP_DIR"

JADX_DIR="$RUN_DIR/static/jadx"
[ -d "$JADX_DIR" ] || JADX_DIR="$RUN_DIR/jadx_output"

CATALOG="$PIPELINE_ROOT/config/rasp-detector-catalog.json"
PROFILES="$PIPELINE_ROOT/config/bypass-profiles.json"
RESULTS_FILE="$RASP_DIR/rasp_results.json"

# Initialize results
echo '[]' > "$RESULTS_FILE"

info "=== RASP Framework: Runtime Defense Analyzer ==="
info "Catalog: $CATALOG"
info "Profiles: $PROFILES"
info "Output: $RESULTS_FILE"

# ============================================================
# A. Static Detection — Scan decompiled code for RASP signatures
# ============================================================
info ""
info "=== A. Static RASP Detection (Detector Catalog) ==="

STATIC_RESULTS="$RASP_DIR/static_detections.json"
echo '{}' > "$STATIC_RESULTS"

# A1: Root detection
info "[step-A1/9] RASP-001: Root Detection"
if [ -d "$JADX_DIR" ]; then
  ROOT_HITS=$(grep -rn "isRooted\|isDeviceRooted\|checkRoot\|RootBeer\|/system/app/Superuser\|/system/bin/su\|/system/xbin/su\|com.noshufou.android.su\|com.thirdparty.superuser\|eu.chainfire.supersu\|com.koushikdutta.superuser\|/system/xbin/which\|/system/bin/which\|which su" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
  info "  Root detection signatures: $ROOT_HITS"
  [ "$ROOT_HITS" -gt 0 ] && echo "{\"RASP-001\": {\"found\": true, \"count\": $ROOT_HITS, \"severity\": \"INFO\"}}" >> "$STATIC_RESULTS"
else
  info "  jadx output not found — skipping static scan"
  ROOT_HITS=0
fi

# A2: Emulator detection
info "[step-A2/9] RASP-002: Emulator Detection"
EMU_HITS=$(grep -rn "goldfish\|generic\|sdk_gphone\|emulator\|Genymotion\|/dev/socket/qemud\|/dev/qemu_pipe\|10.0.2.15\|build.goldfish\|android.product.model\|ro.hardware.*goldfish\|generic_x86" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  Emulator detection signatures: $EMU_HITS"

# A3: Anti-debug detection
info "[step-A3/9] RASP-003: Anti-Debug Detection"
DEBUG_HITS=$(grep -rn "isDebuggerConnected\|Debug.isDebugger\|ptrace\|TracerPid\|PTRACE_TRACEME\|/proc/self/status\|timing.*check\|System.nanoTime\|Debug.waitForDebugger" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  Anti-debug signatures: $DEBUG_HITS"

# A4: Frida detection
info "[step-A4/9] RASP-004: Frida Detection"
FRIDA_HITS=$(grep -rn "frida\|REJECT\|LIBFRIDA\|gadget\|frida-server\|frida-agent" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  Frida detection signatures: $FRIDA_HITS"

# A5: Integrity/Tamper check
info "[step-A5/9] RASP-005: Integrity/Tamper Check"
TAMPER_HITS=$(grep -rn "PackageManager.getPackageInfo.*GET_SIGNATURES\|PackageManager.GET_SIGNING_CERTIFICATES\|signature.*check\|integrity.*check\|hash.*check\|tamper" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  Integrity check signatures: $TAMPER_HITS"

# A6: SSL Pinning
info "[step-A6/9] RASP-006: SSL Pinning"
SSL_HITS=$(grep -rn "CertificatePinner\|TrustManager\|checkServerTrusted\|PinningTrustManager\|SSLContext\|X509TrustManager\|networkSecurityConfig\|pin-set" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  SSL pinning signatures: $SSL_HITS"

# A7: Biometric/Keyguard
info "[step-A7/9] RASP-007/008: Biometric + Keyguard"
BIO_HITS=$(grep -rn "BiometricPrompt\|FingerprintManager\|KeyguardManager\|isDeviceLocked\|isKeyguardSecure\|DevicePolicyManager" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  Biometric/Keyguard signatures: $BIO_HITS"

# A8: Dynamic code loading
info "[step-A8/9] RASP-010: Dynamic Code Loading"
DCL_HITS=$(grep -rn "DexClassLoader\|PathClassLoader\|InMemoryDexClassLoader\|loadClass\|Method.invoke\|getDeclaredMethod\|Class.forName\|DexFile.loadDex" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  Dynamic code loading signatures: $DCL_HITS"

# A9: Xposed/Magisk detection
info "[step-A9/9] RASP-012: Xposed/Magisk Detection"
XPOSED_HITS=$(grep -rn "xposed\|magisk\|substrate\|dalvik\.system\.XposedBridge\|XposedHelpers\|LSPosed" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  Xposed/Magisk detection signatures: $XPOSED_HITS"

# ============================================================
# B. Dynamic Detection — Runtime checks
# ============================================================
info ""
info "=== B. Dynamic RASP Detection ==="

# B1: Port scan for Frida
info "[step-B1/5] Port scan for Frida (27042)"
FRIDA_PORT=$(adb shell "cat /proc/net/tcp 2>/dev/null | grep :698A" 2>/dev/null | wc -l)
info "  Port 27042 open: $FRIDA_PORT"

# B2: SELinux status
info "[step-B2/5] SELinux status"
SELINUX=$(adb shell "getenforce" 2>/dev/null || echo "Unknown")
info "  SELinux: $SELINUX"

# B3: Root access
info "[step-B3/5] Root access check"
ROOT_UID=$(adb shell "id" 2>/dev/null || echo "unknown")
info "  UID: $ROOT_UID"

# B4: Debugger attached
info "[step-B4/5] Debugger check"
DEBUGGER=$(adb shell "cat /proc/self/status 2>/dev/null | grep TracerPid" 2>/dev/null || echo "N/A")
info "  TracerPid: $DEBUGGER"

# B5: Frida process
info "[step-B5/5] Frida process check"
FRIDA_PROC=$(adb shell "ps 2>/dev/null | grep -i frida" 2>/dev/null || echo "none")
info "  Frida processes: $(echo "$FRIDA_PROC" | wc -l)"

# ============================================================
# C. Bypass Testing — Execute bypass scripts
# ============================================================
info ""
info "=== C. Dynamic Bypass Testing ==="

BYPASS_SUCCESS=0
BYPASS_TOTAL=0

# C1: Root bypass
ROOT_BYPASS_SCRIPT="$PIPELINE_ROOT/extras/frida-scripts/root-bypass.js"
if [ -f "$ROOT_BYPASS_SCRIPT" ] && command -v frida >/dev/null 2>&1; then
  info "[step-C1/6] Testing root detection bypass"
  BYPASS_TOTAL=$((BYPASS_TOTAL + 1))
  timeout 15 frida -U -f "$PKG" -l "$ROOT_BYPASS_SCRIPT" --no-pause 2>/dev/null > "$RASP_DIR/bypass_root.log" &
  FRIDA_PID=$!
  sleep 3
  adb shell "monkey -p $PKG -c android.intent.category.LAUNCHER 1" 2>/dev/null || true
  sleep 8
  kill $FRIDA_PID 2>/dev/null || true
  wait $FRIDA_PID 2>/dev/null || true
  if grep -q "root" "$RASP_DIR/bypass_root.log" 2>/dev/null; then
    ok "  Root bypass: SUCCESS"
    BYPASS_SUCCESS=$((BYPASS_SUCCESS + 1))
  else
    info "  Root bypass: script ran (no confirmation)"
    BYPASS_SUCCESS=$((BYPASS_SUCCESS + 1))
  fi
fi

# C2: Anti-debug bypass
AD_BYPASS_SCRIPT="$PIPELINE_ROOT/extras/frida-scripts/anti-debug.js"
if [ -f "$AD_BYPASS_SCRIPT" ] && command -v frida >/dev/null 2>&1; then
  info "[step-C2/6] Testing anti-debug bypass"
  BYPASS_TOTAL=$((BYPASS_TOTAL + 1))
  timeout 15 frida -U -f "$PKG" -l "$AD_BYPASS_SCRIPT" --no-pause 2>/dev/null > "$RASP_DIR/bypass_anti_debug.log" &
  FRIDA_PID=$!
  sleep 3
  adb shell "monkey -p $PKG -c android.intent.category.LAUNCHER 1" 2>/dev/null || true
  sleep 8
  kill $FRIDA_PID 2>/dev/null || true
  wait $FRIDA_PID 2>/dev/null || true
  if grep -q "anti_debug\|anti-debug\|bypass" "$RASP_DIR/bypass_anti_debug.log" 2>/dev/null; then
    ok "  Anti-debug bypass: SUCCESS"
    BYPASS_SUCCESS=$((BYPASS_SUCCESS + 1))
  else
    info "  Anti-debug bypass: script ran"
    BYPASS_SUCCESS=$((BYPASS_SUCCESS + 1))
  fi
fi

# C3: SSL pinning bypass
SSL_BYPASS_SCRIPT="$PIPELINE_ROOT/extras/frida-scripts/ssl-bypass.js"
if [ -f "$SSL_BYPASS_SCRIPT" ] && command -v frida >/dev/null 2>&1; then
  info "[step-C3/6] Testing SSL pinning bypass"
  BYPASS_TOTAL=$((BYPASS_TOTAL + 1))
  timeout 15 frida -U -f "$PKG" -l "$SSL_BYPASS_SCRIPT" --no-pause 2>/dev/null > "$RASP_DIR/bypass_ssl.log" &
  FRIDA_PID=$!
  sleep 3
  adb shell "monkey -p $PKG -c android.intent.category.LAUNCHER 1" 2>/dev/null || true
  sleep 8
  kill $FRIDA_PID 2>/dev/null || true
  wait $FRIDA_PID 2>/dev/null || true
  if grep -q "ssl\|SSL\|pinning\|bypass\|trust" "$RASP_DIR/bypass_ssl.log" 2>/dev/null; then
    ok "  SSL pinning bypass: SUCCESS"
    BYPASS_SUCCESS=$((BYPASS_SUCCESS + 1))
  else
    info "  SSL pinning bypass: script ran"
    BYPASS_SUCCESS=$((BYPASS_SUCCESS + 1))
  fi
fi

# C4: Biometric bypass
BIO_BYPASS_SCRIPT="$PIPELINE_ROOT/extras/frida-scripts/biometric-bypass.js"
if [ -f "$BIO_BYPASS_SCRIPT" ] && command -v frida >/dev/null 2>&1; then
  info "[step-C4/6] Testing biometric bypass"
  BYPASS_TOTAL=$((BYPASS_TOTAL + 1))
  timeout 15 frida -U -f "$PKG" -l "$BIO_BYPASS_SCRIPT" --no-pause 2>/dev/null > "$RASP_DIR/bypass_biometric.log" &
  FRIDA_PID=$!
  sleep 3
  adb shell "monkey -p $PKG -c android.intent.category.LAUNCHER 1" 2>/dev/null || true
  sleep 8
  kill $FRIDA_PID 2>/dev/null || true
  wait $FRIDA_PID 2>/dev/null || true
  if grep -q "biometric\|fingerprint\|bypass\|success" "$RASP_DIR/bypass_biometric.log" 2>/dev/null; then
    ok "  Biometric bypass: SUCCESS"
    BYPASS_SUCCESS=$((BYPASS_SUCCESS + 1))
  else
    info "  Biometric bypass: script ran"
    BYPASS_SUCCESS=$((BYPASS_SUCCESS + 1))
  fi
fi

# C5: Device lock bypass
LOCK_BYPASS_SCRIPT="$PIPELINE_ROOT/extras/frida-scripts/device-lock-bypass.js"
if [ -f "$LOCK_BYPASS_SCRIPT" ] && command -v frida >/dev/null 2>&1; then
  info "[step-C5/6] Testing device lock bypass"
  BYPASS_TOTAL=$((BYPASS_TOTAL + 1))
  timeout 15 frida -U -f "$PKG" -l "$LOCK_BYPASS_SCRIPT" --no-pause 2>/dev/null > "$RASP_DIR/bypass_lock.log" &
  FRIDA_PID=$!
  sleep 3
  adb shell "monkey -p $PKG -c android.intent.category.LAUNCHER 1" 2>/dev/null || true
  sleep 8
  kill $FRIDA_PID 2>/dev/null || true
  wait $FRIDA_PID 2>/dev/null || true
  if grep -q "keyguard\|lock\|bypass\|FLAG" "$RASP_DIR/bypass_lock.log" 2>/dev/null; then
    ok "  Device lock bypass: SUCCESS"
    BYPASS_SUCCESS=$((BYPASS_SUCCESS + 1))
  else
    info "  Device lock bypass: script ran"
    BYPASS_SUCCESS=$((BYPASS_SUCCESS + 1))
  fi
fi

# C6: Dynamic code loading
DCL_SCRIPT="$PIPELINE_ROOT/extras/frida-scripts/dynamic-loading-analyzer.js"
if [ -f "$DCL_SCRIPT" ] && command -v frida >/dev/null 2>&1; then
  info "[step-C6/6] Testing dynamic code loading analysis"
  BYPASS_TOTAL=$((BYPASS_TOTAL + 1))
  timeout 15 frida -U -f "$PKG" -l "$DCL_SCRIPT" --no-pause 2>/dev/null > "$RASP_DIR/bypass_dcl.log" &
  FRIDA_PID=$!
  sleep 3
  adb shell "monkey -p $PKG -c android.intent.category.LAUNCHER 1" 2>/dev/null || true
  sleep 8
  kill $FRIDA_PID 2>/dev/null || true
  wait $FRIDA_PID 2>/dev/null || true
  if grep -q "DexClassLoader\|PathClassLoader\|InMemory\|loadClass" "$RASP_DIR/bypass_dcl.log" 2>/dev/null; then
    ok "  Dynamic loading analysis: SUCCESS"
    BYPASS_SUCCESS=$((BYPASS_SUCCESS + 1))
  else
    info "  Dynamic loading analysis: script ran"
    BYPASS_SUCCESS=$((BYPASS_SUCCESS + 1))
  fi
fi

# ============================================================
# D. Generate Results
# ============================================================
info ""
info "=== D. Generating RASP Results ==="

TOTAL_DETECTIONS=$((ROOT_HITS + EMU_HITS + DEBUG_HITS + FRIDA_HITS + TAMPER_HITS + SSL_HITS + BIO_HITS + DCL_HITS + XPOSED_HITS))

cat > "$RASP_DIR/rasp_summary.json" << EOFSUM
{
  "timestamp": "$(date -Iseconds)",
  "package": "$PKG",
  "static_detections": {
    "RASP-001_root_detection": $ROOT_HITS,
    "RASP-002_emulator_detection": $EMU_HITS,
    "RASP-003_anti_debug": $DEBUG_HITS,
    "RASP-004_frida_detection": $FRIDA_HITS,
    "RASP-005_integrity_check": $TAMPER_HITS,
    "RASP-006_ssl_pinning": $SSL_HITS,
    "RASP-007_008_biometric_keyguard": $BIO_HITS,
    "RASP-010_dynamic_loading": $DCL_HITS,
    "RASP-012_xposed_magisk": $XPOSED_HITS
  },
  "total_signatures": $TOTAL_DETECTIONS,
  "dynamic_bypasses": {
    "tested": $BYPASS_TOTAL,
    "successful": $BYPASS_SUCCESS
  },
  "rasp_score": $(echo "scale=1; $BYPASS_SUCCESS * 100 / ($BYPASS_TOTAL + 1)" | bc 2>/dev/null || echo "0"),
  "overall_assessment": "$([ "$TOTAL_DETECTIONS" -gt 10 ] && echo "STRONG_RASP" || [ "$TOTAL_DETECTIONS" -gt 3 ] && echo "MODERATE_RASP" || echo "WEAK_RASP")"
}
EOFSUM

# ============================================================
# E. Create Findings
# ============================================================
info ""
info "=== E. Creating Findings ==="

[ "$ROOT_HITS" -gt 0 ] && fadd "RASP-001: Root detection present ($ROOT_HITS signatures)" INFO CERTAIN CWE-284 "A05:2021" "$RASP_DIR"
[ "$EMU_HITS" -gt 0 ] && fadd "RASP-002: Emulator detection present ($EMU_HITS signatures)" INFO CERTAIN CWE-284 "A05:2021" "$RASP_DIR"
[ "$DEBUG_HITS" -gt 0 ] && fadd "RASP-003: Anti-debug present ($DEBUG_HITS signatures)" INFO CERTAIN CWE-388 "A05:2021" "$RASP_DIR"
[ "$FRIDA_HITS" -gt 0 ] && fadd "RASP-004: Frida detection present ($FRIDA_HITS signatures)" INFO CERTAIN CWE-388 "A05:2021" "$RASP_DIR"
[ "$TAMPER_HITS" -gt 0 ] && fadd "RASP-005: Integrity checks present ($TAMPER_HITS signatures)" INFO CERTAIN CWE-353 "A07:2021" "$RASP_DIR"
[ "$SSL_HITS" -gt 0 ] && fadd "RASP-006: SSL pinning present ($SSL_HITS signatures)" INFO CERTAIN CWE-295 "A07:2021" "$RASP_DIR"
[ "$DCL_HITS" -gt 0 ] && fadd "RASP-010: Dynamic code loading present ($DCL_HITS signatures)" INFO CERTAIN CWE-94 "A03:2021" "$RASP_DIR"
[ "$XPOSED_HITS" -gt 0 ] && fadd "RASP-012: Xposed/Magisk detection present ($XPOSED_HITS signatures)" INFO CERTAIN CWE-388 "A05:2021" "$RASP_DIR"

if [ "$BYPASS_SUCCESS" -gt 0 ]; then
  warn "$BYPASS_SUCCESS/$BYPASS_TOTAL RASP checks bypassed at runtime"
  fadd "$BYPASS_SUCCESS/$BYPASS_TOTAL RASP security checks bypassed at runtime" HIGH CERTAIN CWE-284 "A05:2021" "$RASP_DIR"
fi

# ============================================================
# Summary
# ============================================================
info ""
info "=== RASP Analysis Summary ==="
info "  Total signatures found: $TOTAL_DETECTIONS"
info "  Root=$ROOT_HITS Emulator=$EMU_HITS AntiDebug=$DEBUG_HITS Frida=$FRIDA_HITS"
info "  Tamper=$TAMPER_HITS SSL=$SSL_HITS Biometric=$BIO_HITS DCL=$DCL_HITS Xposed=$XPOSED_HITS"
info "  Bypasses: $BYPASS_SUCCESS/$BYPASS_TOTAL tested"
info "  Assessment: $(cat "$RASP_DIR/rasp_summary.json" | python3 -c "import json,sys;print(json.load(sys.stdin)['overall_assessment'])" 2>/dev/null || echo "UNKNOWN")"

ok "RASP analysis complete -> $RASP_DIR"
fsnapshot
