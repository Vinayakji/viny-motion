#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 02_setup_genymotion.sh - Create/start Genymotion device, install APK
PROFILE_PHASE="02_setup_genymotion"
source "$PIPELINE_ROOT/lib/common.sh"

DEVICE="$(tget genymotion device_name)"
ANDROID_VER="$(tget genymotion android_version)"
RESOLUTION="$(tget genymotion resolution)"
MEMORY="$(tget genymotion memory)"
PKG="$(tget apk package_name)"

cd "$RUN_DIR" || exit 1
info "Setting up Genymotion device: $DEVICE"

# ---- 1. Start Genymotion ----
if [ -x "$HOME/genymotion/genymotion" ] || [ -x "$HOME/genymotion/player" ]; then
  genymotion_start "$DEVICE"
else
  warn "Genymotion not found - ensure it's installed"
  warn "Expected: ~/genymotion/genymotion or ~/genymotion/player"
fi

# ---- 2. Wait for device ----
info "Waiting for device..."
adb wait-for-device 2>/dev/null
sleep 5

# Check if device is ready
DEVICE_STATE="$(adb get-state 2>/dev/null)"
if [ "$DEVICE_STATE" != "device" ]; then
  warn "Device not ready (state: $DEVICE_STATE)"
  warn "You may need to unlock the device or wait for boot"
fi

# ---- 3. Setup proxy ----
setup_proxy

# ---- 4. Install APK ----
APK="$RUN_DIR/app.apk"
if [ -f "$APK" ]; then
  adb_install "$APK"
  
  # Verify installation
  if [ -n "$PKG" ]; then
    if adb shell pm list packages 2>/dev/null | grep -q "$PKG"; then
      ok "APK installed successfully: $PKG"
    else
      warn "APK installation may have failed"
    fi
  fi
else
  warn "No APK found at $APK (run 00_acquire first)"
fi

# ---- 5. Setup Frida server ----
info "Setting up Frida server..."
FRIDA_VERSION="$(frida --version 2>/dev/null || echo '16.0.0')"
FRIDA_SERVER="/tmp/frida-server-${FRIDA_VERSION}-android-$(adb shell getprop ro.product.cpu.abi 2>/dev/null)"

if [ -x "$FRIDA_SERVER" ]; then
  info "Pushing Frida server..."
  adb push "$FRIDA_SERVER" /data/local/tmp/frida-server 2>/dev/null
  adb shell "chmod 755 /data/local/tmp/frida-server" 2>/dev/null
  ok "Frida server pushed"
else
  warn "Frida server not found at $FRIDA_SERVER"
  warn "Download from: https://github.com/frida/frida/releases"
fi

# ---- 6. Start drozer server ----
info "Starting drozer server..."
adb push "$HOME/.local/lib/python3.10/site-packages/drozer/runtime.jar" /data/local/tmp/drozer.jar 2>/dev/null || \
adb push "$(python3 -c 'import drozer; import os; print(os.path.dirname(drozer.__file__))' 2>/dev/null)/runtime.jar" /data/local/tmp/drozer.jar 2>/dev/null || true
adb shell "am startservice -n com.mwr.dz/.services.ServerService" 2>/dev/null || true
adb forward tcp:31415 tcp:31415 2>/dev/null || true
ok "Drozer server started (port 31415)"

ok "Genymotion setup complete"
info "Device: $DEVICE | State: $(adb get-state 2>/dev/null || echo unknown)"
