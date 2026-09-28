#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 13_resilience.sh - Anti-debug, root detection, emulator detection, integrity checks
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
  info "[step-A1/6] Scanning for root detection methods"
  grep -rn "isRooted\|isDeviceRooted\|checkRoot\|RootBeer\|/system/app/Superuser\|/system/bin/su\|/system/xbin/su\|com.noshufou.android.su\|com.thirdparty.superuser\|eu.chainfire.supersu\|com.koushikdutta.superuser" "$JADX_DIR/sources/" 2>/dev/null > "$RESILIENCE_DIR/root_detection.txt" || true
  ROOT_COUNT=$(wc -l < "$RESILIENCE_DIR/root_detection.txt" 2>/dev/null || echo 0)
  info "  Root detection methods: $ROOT_COUNT"
  if [ "$ROOT_COUNT" -gt 0 ]; then
    head -5 "$RESILIENCE_DIR/root_detection.txt" | while IFS= read -r line; do info "    $line"; done
  fi

  info "[step-A2/6] Scanning for emulator detection methods"
  grep -rn "goldfish\|generic\|sdk_gphone\|emulator\|Android SDK\|viny-motion\|/dev/socket/qemud\|/dev/qemu_pipe\|10.0.2.15\|build.goldfish\|android.product.model\|X86\|generic_x86" "$JADX_DIR/sources/" 2>/dev/null > "$RESILIENCE_DIR/emulator_detection.txt" || true
  EMU_COUNT=$(wc -l < "$RESILIENCE_DIR/emulator_detection.txt" 2>/dev/null || echo 0)
  info "  Emulator detection methods: $EMU_COUNT"
  if [ "$EMU_COUNT" -gt 0 ]; then
    head -5 "$RESILIENCE_DIR/emulator_detection.txt" | while IFS= read -r line; do info "    $line"; done
  fi

  info "[step-A3/6] Scanning for anti-debug methods"
  grep -rn "isDebuggerConnected\|Debug.isDebugger\|ptrace\|TracerPid\|PTRACE_TRACEME\|self/debug/tracer\|/proc/self/status\|timing.*check\|System.nanoTime\|Debug.waitForDebugger" "$JADX_DIR/sources/" 2>/dev/null > "$RESILIENCE_DIR/anti_debug.txt" || true
  DEBUG_COUNT=$(wc -l < "$RESILIENCE_DIR/anti_debug.txt" 2>/dev/null || echo 0)
  info "  Anti-debug methods: $DEBUG_COUNT"
  if [ "$DEBUG_COUNT" -gt 0 ]; then
    head -5 "$RESILIENCE_DIR/anti_debug.txt" | while IFS= read -r line; do info "    $line"; done
  fi

  info "[step-A4/6] Scanning for integrity/tamper checks"
  grep -rn "PackageManager.getPackageInfo.*GET_SIGNATURES\|PackageManager.GET_SIGNING_CERTIFICATES\|signature.*check\|integrity.*check\|hash.*check\|tamper" "$JADX_DIR/sources/" 2>/dev/null > "$RESILIENCE_DIR/integrity_check.txt" || true
  INTEGRITY_COUNT=$(wc -l < "$RESILIENCE_DIR/integrity_check.txt" 2>/dev/null || echo 0)
  info "  Integrity checks: $INTEGRITY_COUNT"
  if [ "$INTEGRITY_COUNT" -gt 0 ]; then
    head -3 "$RESILIENCE_DIR/integrity_check.txt" | while IFS= read -r line; do info "    $line"; done
  fi

  info "[step-A5/6] Scanning for jailbreak detection (cross-platform apps)"
  grep -rn "jailbreak\|Cydia\|AppSync\|substrate\|SSLKillSwitch\|FridaGadget\|frida-server\|frida-agent" "$JADX_DIR/sources/" 2>/dev/null > "$RESILIENCE_DIR/jailbreak_detection.txt" || true
  JAILBREAK_COUNT=$(wc -l < "$RESILIENCE_DIR/jailbreak_detection.txt" 2>/dev/null || echo 0)
  info "  Jailbreak detection methods: $JAILBREAK_COUNT"

  info "[step-A6/6] Checking for code obfuscation indicators (ProGuard/R8 short names)"
  grep -rnPro '[a-z]{1,2}\.[a-z]{1,2}\.[a-z]{1,2}\.' "$JADX_DIR/sources/" 2>/dev/null | head -20 > "$RESILIENCE_DIR/obfuscation.txt" || true
  OBFUSC_COUNT=$(wc -l < "$RESILIENCE_DIR/obfuscation.txt" 2>/dev/null || echo 0)
  info "  Obfuscation indicators: $OBFUSC_COUNT"

  ok "  Static: Root=$ROOT_COUNT, Emulator=$EMU_COUNT, Debug=$DEBUG_COUNT, Integrity=$INTEGRITY_COUNT"
else
  warn "  jadx directory not found; skipping static analysis"
fi

# ============================================================
# B. Dynamic Analysis — Test Bypasses
# ============================================================
info "=== B. Dynamic Bypass Testing ==="

# B1. Root detection bypass
ROOT_SCRIPT="$PIPELINE_ROOT/extras/frida-scripts/root-bypass.js"
if [ -f "$ROOT_SCRIPT" ] && command -v frida >/dev/null 2>&1; then
  info "[step-B1/4] Testing root detection bypass"
  info "  Script: $ROOT_SCRIPT"
  info "  Timeout: 15s"
  timeout 15 frida -U -f "$PKG" -l "$ROOT_SCRIPT" --no-pause 2>/dev/null > "$RESILIENCE_DIR/root_bypass.log" &
  FRIDA_PID=$!
  info "  Frida PID: $FRIDA_PID"
  sleep 3

  adb shell "monkey -p $PKG -c android.intent.category.LAUNCHER 1" 2>/dev/null || true
  info "  Waiting 8s for root bypass hook to activate..."
  sleep 8

  kill $FRIDA_PID 2>/dev/null || true
  wait $FRIDA_PID 2>/dev/null || true

  if grep -q "root" "$RESILIENCE_DIR/root_bypass.log" 2>/dev/null; then
    ok "  Root bypass hook active"
  else
    info "  Root bypass script ran but no hook confirmation in output"
  fi
else
  info "  root-bypass.js not found or frida not installed; skipping root bypass"
fi

# B2. Anti-debug bypass
ANTI_DEBUG_SCRIPT="$PIPELINE_ROOT/extras/frida-scripts/anti-debug.js"
if [ -f "$ANTI_DEBUG_SCRIPT" ] && command -v frida >/dev/null 2>&1; then
  info "[step-B2/4] Testing anti-debug bypass"
  info "  Script: $ANTI_DEBUG_SCRIPT"
  info "  Timeout: 15s"
  timeout 15 frida -U -f "$PKG" -l "$ANTI_DEBUG_SCRIPT" --no-pause 2>/dev/null > "$RESILIENCE_DIR/anti_debug_bypass.log" &
  FRIDA_PID=$!
  info "  Frida PID: $FRIDA_PID"
  sleep 3

  adb shell "monkey -p $PKG -c android.intent.category.LAUNCHER 1" 2>/dev/null || true
  info "  Waiting 8s for anti-debug bypass hook to activate..."
  sleep 8

  kill $FRIDA_PID 2>/dev/null || true
  wait $FRIDA_PID 2>/dev/null || true

  if grep -q "anti_debug" "$RESILIENCE_DIR/anti_debug_bypass.log" 2>/dev/null; then
    ok "  Anti-debug bypass hook active"
  else
    info "  Anti-debug bypass script ran but no hook confirmation in output"
  fi
else
  info "  anti-debug.js not found or frida not installed; skipping anti-debug bypass"
fi

# B3. SELinux status
info "[step-B3/4] Checking device SELinux status"
SELINUX=$(adb shell "getenforce" 2>/dev/null || echo "Unknown")
info "  SELinux: $SELINUX"

# B4. Verify root access
info "[step-B4/4] Verifying device root access"
ROOT_CHECK=$(adb shell "id" 2>/dev/null || echo "unknown")
info "  Device UID: $ROOT_CHECK"

if echo "$ROOT_CHECK" | grep -q "uid=0"; then
  ok "  Device is rooted"
  adb shell "ls -la /data/data/$PKG/" > "$RESILIENCE_DIR/app_data_root.txt" 2>/dev/null || true
  if [ -s "$RESILIENCE_DIR/app_data_root.txt" ]; then
    info "  App data accessible with root:"
    head -5 "$RESILIENCE_DIR/app_data_root.txt" | while IFS= read -r line; do info "    $line"; done
    fadd "App data accessible with root access" INFO CERTAIN CWE-250 "A01:2021" "$RESILIENCE_DIR/app_data_root.txt"
  fi
else
  warn "  Device not rooted — some tests limited"
fi

# ============================================================
# C. Create Findings
# ============================================================
info "=== C. Creating Findings ==="

[ "${ROOT_COUNT:-0}" -gt 0 ] && fadd "Root detection present ($ROOT_COUNT checks)" INFO INFO CWE-284 "A05:2021" "$RESILIENCE_DIR/root_detection.txt"
[ "${EMU_COUNT:-0}" -gt 0 ] && fadd "Emulator detection present ($EMU_COUNT checks)" INFO INFO CWE-284 "A05:2021" "$RESILIENCE_DIR/emulator_detection.txt"
[ "${DEBUG_COUNT:-0}" -gt 0 ] && fadd "Anti-debug present ($DEBUG_COUNT checks)" INFO INFO CWE-284 "A05:2021" "$RESILIENCE_DIR/anti_debug.txt"
[ "${INTEGRITY_COUNT:-0}" -gt 0 ] && fadd "Integrity checks present ($INTEGRITY_COUNT checks)" INFO INFO CWE-353 "A07:2021" "$RESILIENCE_DIR/integrity_check.txt"

BYPASS_COUNT=0
[ -s "$RESILIENCE_DIR/root_bypass.log" ] && BYPASS_COUNT=$((BYPASS_COUNT + 1))
[ -s "$RESILIENCE_DIR/anti_debug_bypass.log" ] && BYPASS_COUNT=$((BYPASS_COUNT + 1))

if [ "$BYPASS_COUNT" -gt 0 ]; then
  warn "$BYPASS_COUNT security check(s) bypassed at runtime"
  fadd "$BYPASS_COUNT security checks bypassed at runtime" HIGH CERTAIN CWE-284 "A05:2021" "$RESILIENCE_DIR"
fi

ok "Resilience testing complete -> $RESILIENCE_DIR"
ok "  Root=$ROOT_COUNT, Emulator=$EMU_COUNT, Debug=$DEBUG_COUNT, Integrity=$INTEGRITY_COUNT, Bypasses=$BYPASS_COUNT"
fsnapshot
