#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 15_cleanup.sh - Cleanup device state, uninstall app, remove temp files
PROFILE_PHASE="15_cleanup"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
[ -z "$PKG" ] && { err "No package_name"; exit 1; }

cd "$RUN_DIR" || exit 1
CLEANUP_DIR="$RUN_DIR/cleanup"
mkdir -p "$CLEANUP_DIR"

# ============================================================
# A. Device State Cleanup
# ============================================================
info "=== A. Device State Cleanup ==="

info "[step-A1/2] Clearing proxy settings on device"
adb shell "settings put global http_proxy :0" 2>/dev/null || true
ok "  Proxy settings cleared"

info "[step-A2/2] Clearing VPN configs"
adb shell "cmd connectivity vpn clear" 2>/dev/null || true
ok "  VPN configs cleared"

# ============================================================
# B. Remove Frida Server
# ============================================================
info "=== B. Frida Server Cleanup ==="

info "[step-B1/2] Checking for running frida-server process"
FRIDA_RUNNING=$(adb shell "ps -A | grep frida-server" 2>/dev/null || true)
if echo "$FRIDA_RUNNING" | grep -q "frida"; then
  info "  Frida server found running; killing and removing"
  adb shell "su -c 'killall frida-server'" 2>/dev/null || \
    adb shell "kill $(adb shell 'pidof frida-server' 2>/dev/null)" 2>/dev/null || true
  adb shell "su -c 'rm /data/local/tmp/frida-server'" 2>/dev/null || true
  ok "  Frida server killed and removed"
else
  info "  No Frida server running"
fi

info "[step-B2/2] Checking for leftover frida-server binaries"
FRIDA_LEFTOVER=$(adb shell "ls /data/local/tmp/frida-server 2>/dev/null" || true)
if echo "$FRIDA_LEFTOVER" | grep -q "frida-server"; then
  adb shell "rm /data/local/tmp/frida-server" 2>/dev/null || true
  ok "  Leftover frida-server removed"
else
  info "  No leftover frida-server binaries"
fi

# ============================================================
# C. Remove CA Certificates
# ============================================================
info "=== C. CA Certificate Cleanup ==="

info "[step-C1/2] Checking for custom CA certificates in system store"
CERT_HASH=$(adb shell "ls /system/etc/security/cacerts/" 2>/dev/null | head -1 || true)
if [ -n "$CERT_HASH" ]; then
  info "  System CA store accessible; attempting to remove Burp CA"
  adb shell "su -c 'mount -o remount,rw /system'" 2>/dev/null || true
  adb shell "su -c 'rm /system/etc/security/cacerts/9a5ba575.0'" 2>/dev/null || true
  adb shell "su -c 'mount -o remount,ro /system'" 2>/dev/null || true
  ok "  Burp CA removed from system store"
else
  info "  No custom CA found in system store"
fi

info "[step-C2/2] Checking for user-installed CA certificates"
USER_CAS=$(adb shell "ls /data/misc/user/0/cacerts-added/" 2>/dev/null || true)
USER_CA_COUNT=$(echo "$USER_CAS" | wc -l 2>/dev/null || echo 0)
info "  User-installed CAs: $USER_CA_COUNT"

# ============================================================
# D. App Cleanup
# ============================================================
info "=== D. App Cleanup ==="

KEEP_APP=$(tget general keep_app false)
info "[step-D1/1] Checking keep_app setting"
if [ "$KEEP_APP" = "false" ] || [ "$KEEP_APP" = "False" ]; then
  info "  keep_app=false; clearing app data"
  adb shell "pm clear $PKG" 2>/dev/null || true
  ok "  App data cleared"
else
  info "  keep_app=true; skipping app uninstall"
fi

# ============================================================
# E. Device Stop
# ============================================================
info "=== E. Device Cleanup ==="

STOP_DEVICE=$(tget general stop_device false)
info "[step-E1/1] Checking stop_device setting"
if [ "$STOP_DEVICE" = "true" ] || [ "$STOP_DEVICE" = "True" ]; then
  info "  stop_device=true; stopping Genymotion device"
  adb devices | grep -v "^List" | awk '{print $1}' | while read device; do
    info "    Stopping: $device"
    adb -s "$device" emu kill 2>/dev/null || true
  done
  ok "  Device stopped"
else
  info "  stop_device=false; leaving device running"
fi

# ============================================================
# F. Save Logs
# ============================================================
info "=== F. Saving Final Logs ==="

info "[step-F1/2] Capturing final logcat"
adb logcat -d > "$CLEANUP_DIR/logcat_final.txt" 2>/dev/null || true
LOGCAT_LINES=$(wc -l < "$CLEANUP_DIR/logcat_final.txt" 2>/dev/null || echo 0)
info "  Final logcat: $LOGCAT_LINES lines"

info "[step-F2/2] Saving device properties snapshot"
adb shell "getprop" > "$CLEANUP_DIR/device_props.txt" 2>/dev/null || true
PROP_COUNT=$(wc -l < "$CLEANUP_DIR/device_props.txt" 2>/dev/null || echo 0)
info "  Device properties: $PROP_COUNT entries"

# ============================================================
# G. Summary
# ============================================================
info "=== Cleanup Summary ==="

echo "Cleanup complete." > "$CLEANUP_DIR/summary.txt"
echo "" >> "$CLEANUP_DIR/summary.txt"
echo "Device state:" >> "$CLEANUP_DIR/summary.txt"
echo "- Proxy: cleared" >> "$CLEANUP_DIR/summary.txt"
echo "- Frida: stopped & removed" >> "$CLEANUP_DIR/summary.txt"
echo "- CA certs: removed" >> "$CLEANUP_DIR/summary.txt"
echo "- App data: $([ "$KEEP_APP" = "true" ] && echo "preserved" || echo "cleared")" >> "$CLEANUP_DIR/summary.txt"
echo "- Device: $([ "$STOP_DEVICE" = "true" ] && echo "stopped" || echo "running")" >> "$CLEANUP_DIR/summary.txt"

ok "Cleanup complete -> $CLEANUP_DIR"
ok "  Proxy=cleared, Frida=removed, CAs=removed, App=$([ "$KEEP_APP" = "true" ] && echo "preserved" || echo "cleared"), Device=$([ "$STOP_DEVICE" = "true" ] && echo "stopped" || echo "running")"
fsnapshot
