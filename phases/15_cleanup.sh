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

info "=== Cleanup Phase ==="

# ============================================================
# A. Device State Cleanup
# ============================================================
info "=== A. Device State ==="

# Remove any proxy settings on device
adb shell "settings put global http_proxy :0" 2>/dev/null || true
ok "Proxy settings cleared"

# Remove any VPN configs we may have added
adb shell "cmd connectivity vpn clear" 2>/dev/null || true
ok "VPN configs cleared"

# ============================================================
# B. Remove Frida Server
# ============================================================
info "=== B. Frida Server ==="

if adb shell "ps -A | grep frida-server" 2>/dev/null | grep -q "frida"; then
  adb shell "su -c 'killall frida-server'" 2>/dev/null || \
    adb shell "kill $(adb shell 'pidof frida-server' 2>/dev/null)" 2>/dev/null || true
  adb shell "su -c 'rm /data/local/tmp/frida-server'" 2>/dev/null || true
  ok "Frida server removed"
else
  info "No Frida server running"
fi

# ============================================================
# C. Remove CA Certificates
# ============================================================
info "=== C. CA Certificates ==="

# Remove Burp CA from user store
CERT_HASH=$(adb shell "ls /system/etc/security/cacerts/" 2>/dev/null | head -1 || true)
if [ -n "$CERT_HASH" ]; then
  adb shell "su -c 'mount -o remount,rw /system'" 2>/dev/null || true
  adb shell "su -c 'rm /system/etc/security/cacerts/9a5ba575.0'" 2>/dev/null || true
  adb shell "su -c 'mount -o remount,ro /system'" 2>/dev/null || true
  ok "Burp CA removed from system store"
else
  info "No custom CA found"
fi

# ============================================================
# D. Uninstall App (if requested)
# ============================================================
info "=== D. App Cleanup ==="

# Only uninstall if keep_app is not set
KEEP_APP=$(tget general keep_app false)
if [ "$KEEP_APP" = "false" ] || [ "$KEEP_APP" = "False" ]; then
  adb shell "pm clear $PKG" 2>/dev/null || true
  info "App data cleared"
else
  info "keep_app=true, skipping uninstall"
fi

# ============================================================
# E. Stop Device (if requested)
# ============================================================
info "=== E. Device Cleanup ==="

STOP_DEVICE=$(tget general stop_device false)
if [ "$STOP_DEVICE" = "true" ] || [ "$STOP_DEVICE" = "True" ]; then
  info "Stopping Genymotion device..."
  adb devices | grep -v "^List" | awk '{print $1}' | while read device; do
    adb -s "$device" emu kill 2>/dev/null || true
  done
  ok "Device stopped"
else
  info "stop_device=false, leaving device running"
fi

# ============================================================
# F. Save Logs
# ============================================================
info "=== F. Saving Logs ==="

# Save logcat
adb logcat -d > "$CLEANUP_DIR/logcat_final.txt" 2>/dev/null || true
ok "Logcat saved"

# Save device info
adb shell "getprop" > "$CLEANUP_DIR/device_props.txt" 2>/dev/null || true
ok "Device properties saved"

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
fsnapshot
