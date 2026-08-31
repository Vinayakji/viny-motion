#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 13_resilience.sh - Anti-debug, root detection bypass, emulator detection
PROFILE_PHASE="13_resilience"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
[ -z "$PKG" ] && { err "No package_name"; exit 1; }

cd "$RUN_DIR" || exit 1
RESILIENCE_DIR="$RUN_DIR/resilience"
mkdir -p "$RESILIENCE_DIR"

# ============================================================
# A. Static Analysis — Find Security Checks
# ============================================================
info "=== A. Static Security Analysis ==="

JADX_DIR="$RUN_DIR/static/jadx"
if [ -d "$JADX_DIR" ]; then
  # Root detection
  grep -rn "isRooted\|isDeviceRooted\|checkRoot\|RootBeer\|/system/app/Superuser\|/system/bin/su\|/system/xbin/su\|com.noshufou.android.su\|com.thirdparty.superuser\|eu.chainfire.supersu\|com.koushikdutta.superuser" "$JADX_DIR/sources/" 2>/dev/null > "$RESILIENCE_DIR/root_detection.txt" || true
  ROOT_COUNT=$(wc -l < "$RESILIENCE_DIR/root_detection.txt" 2>/dev/null || echo 0)
  info "Root detection methods: $ROOT_COUNT"

  # Emulator detection
  grep -rn "goldfish\|generic\|sdk_gphone\|emulator\|Android SDK\|Genymotion\|/dev/socket/qemud\|/dev/qemu_pipe\|10.0.2.15\|build.goldfish\|android.product.model\|X86\|generic_x86" "$JADX_DIR/sources/" 2>/dev/null > "$RESILIENCE_DIR/emulator_detection.txt" || true
  EMU_COUNT=$(wc -l < "$RESILIENCE_DIR/emulator_detection.txt" 2>/dev/null || echo 0)
  info "Emulator detection methods: $EMU_COUNT"

  # Anti-debug
  grep -rn "isDebuggerConnected\|Debug.isDebugger\|ptrace\|TracerPid\|PTRACE_TRACEME\|self/debug/tracer\|/proc/self/status\|timing.*check\|System.nanoTime\|Debug.waitForDebugger" "$JADX_DIR/sources/" 2>/dev/null > "$RESILIENCE_DIR/anti_debug.txt" || true
  DEBUG_COUNT=$(wc -l < "$RESILIENCE_DIR/anti_debug.txt" 2>/dev/null || echo 0)
  info "Anti-debug methods: $DEBUG_COUNT"

  # Integrity check
  grep -rn "PackageManager.getPackageInfo.*GET_SIGNATURES\|PackageManager.GET_SIGNING_CERTIFICATES\|signature.*check\|integrity.*check\|hash.*check\|tamper" "$JADX_DIR/sources/" 2>/dev/null > "$RESILIENCE_DIR/integrity_check.txt" || true
  INTEGRITY_COUNT=$(wc -l < "$RESILIENCE_DIR/integrity_check.txt" 2>/dev/null || echo 0)
  info "Integrity checks: $INTEGRITY_COUNT"

  # Jailbreak detection (for cross-platform apps)
  grep -rn "jailbreak\|Cydia\|AppSync\|substrate\|SSLKillSwitch\|FridaGadget\|frida-server\|frida-agent" "$JADX_DIR/sources/" 2>/dev/null > "$RESILIENCE_DIR/jailbreak_detection.txt" || true

  # Code obfuscation indicators
  grep -rnPro '[a-z]{1,2}\.[a-z]{1,2}\.[a-z]{1,2}\.' "$JADX_DIR/sources/" 2>/dev/null | head -20 > "$RESILIENCE_DIR/obfuscation.txt" || true
fi

# ============================================================
# B. Dynamic Analysis — Test Bypasses
# ============================================================
info "=== B. Dynamic Bypass Testing ==="

# B1. Root detection bypass
ROOT_SCRIPT="$PIPELINE_ROOT/extras/frida-scripts/root-bypass.js"
if [ -f "$ROOT_SCRIPT" ] && command -v frida >/dev/null 2>&1; then
  info "Testing root detection bypass..."
  timeout 15 frida -U -f "$PKG" -l "$ROOT_SCRIPT" --no-pause 2>/dev/null > "$RESILIENCE_DIR/root_bypass.log" &
  FRIDA_PID=$!
  sleep 3

  # Launch app
  adb shell "monkey -p $PKG -c android.intent.category.LAUNCHER 1" 2>/dev/null || true
  sleep 8

  kill $FRIDA_PID 2>/dev/null || true
  wait $FRIDA_PID 2>/dev/null || true

  if grep -q "root" "$RESILIENCE_DIR/root_bypass.log" 2>/dev/null; then
    ok "Root bypass hook active"
  fi
fi

# B2. Anti-debug bypass
ANTI_DEBUG_SCRIPT="$PIPELINE_ROOT/extras/frida-scripts/anti-debug.js"
if [ -f "$ANTI_DEBUG_SCRIPT" ] && command -v frida >/dev/null 2>&1; then
  info "Testing anti-debug bypass..."
  timeout 15 frida -U -f "$PKG" -l "$ANTI_DEBUG_SCRIPT" --no-pause 2>/dev/null > "$RESILIENCE_DIR/anti_debug_bypass.log" &
  FRIDA_PID=$!
  sleep 3

  adb shell "monkey -p $PKG -c android.intent.category.LAUNCHER 1" 2>/dev/null || true
  sleep 8

  kill $FRIDA_PID 2>/dev/null || true
  wait $FRIDA_PID 2>/dev/null || true

  if grep -q "anti_debug" "$RESILIENCE_DIR/anti_debug_bypass.log" 2>/dev/null; then
    ok "Anti-debug bypass hook active"
  fi
fi

# B3. SELinux status
SELINUX=$(adb shell "getenforce" 2>/dev/null || echo "Unknown")
info "SELinux status: $SELINUX"

# B4. Verify root access
ROOT_CHECK=$(adb shell "id" 2>/dev/null || echo "unknown")
info "Device root status: $ROOT_CHECK"

if echo "$ROOT_CHECK" | grep -q "uid=0"; then
  ok "Device is rooted"

  # Access app data with root
  adb shell "ls -la /data/data/$PKG/" > "$RESILIENCE_DIR/app_data_root.txt" 2>/dev/null || true
  if [ -s "$RESILIENCE_DIR/app_data_root.txt" ]; then
    info "App data accessible via root"
    fadd "App data accessible with root access" INFO CERTAIN CWE-250 "A01:2021" "$RESILIENCE_DIR/app_data_root.txt"
  fi
else
  warn "Device not rooted - some tests limited"
fi

# ============================================================
# C. Create Findings
# ============================================================
info "=== C. Creating Findings ==="

[ "$ROOT_COUNT" -gt 0 ] && fadd "Root detection present ($ROOT_COUNT checks)" INFO INFO CWE-284 "A05:2021" "$RESILIENCE_DIR/root_detection.txt"
[ "$EMU_COUNT" -gt 0 ] && fadd "Emulator detection present ($EMU_COUNT checks)" INFO INFO CWE-284 "A05:2021" "$RESILIENCE_DIR/emulator_detection.txt"
[ "$DEBUG_COUNT" -gt 0 ] && fadd "Anti-debug present ($DEBUG_COUNT checks)" INFO INFO CWE-284 "A05:2021" "$RESILIENCE_DIR/anti_debug.txt"
[ "$INTEGRITY_COUNT" -gt 0 ] && fadd "Integrity checks present ($INTEGRITY_COUNT checks)" INFO INFO CWE-353 "A07:2021" "$RESILIENCE_DIR/integrity_check.txt"

# Check if bypasses worked
BYPASS_COUNT=0
[ -s "$RESILIENCE_DIR/root_bypass.log" ] && BYPASS_COUNT=$((BYPASS_COUNT + 1))
[ -s "$RESILIENCE_DIR/anti_debug_bypass.log" ] && BYPASS_COUNT=$((BYPASS_COUNT + 1))

if [ "$BYPASS_COUNT" -gt 0 ]; then
  warn "$BYPASS_COUNT security checks bypassed"
  fadd "$BYPASS_COUNT security checks bypassed at runtime" HIGH CERTAIN CWE-284 "A05:2021" "$RESILIENCE_DIR"
fi

ok "Resilience testing complete -> $RESILIENCE_DIR"
fsnapshot
