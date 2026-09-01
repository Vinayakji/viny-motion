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
info "[step-1/8] Checking Genymotion installation"
if [ -x "$HOME/genymotion/genymotion" ] || [ -x "$HOME/genymotion/player" ]; then
  info "  Found Genymotion binary; starting device '$DEVICE'"
  genymotion_start "$DEVICE"
  ok "  Genymotion start command issued"
else
  warn "  Genymotion not found at ~/genymotion/genymotion or ~/genymotion/player"
  warn "  Ensure Genymotion is installed; continuing with existing device"
fi

# ---- 2. Wait for device ----
info "[step-2/8] Waiting for ADB device to become available"
info "  Running: adb wait-for-device"
adb wait-for-device 2>/dev/null
info "  Device detected; waiting 5s for boot to complete..."
sleep 5

DEVICE_STATE="$(adb get-state 2>/dev/null)"
DEVICE_MODEL="$(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r')"
ANDROID_VERSION="$(adb shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')"
API_LEVEL="$(adb shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')"
info "  Device state: $DEVICE_STATE"
info "  Model: $DEVICE_MODEL | Android: $ANDROID_VERSION (API $API_LEVEL)"
if [ "$DEVICE_STATE" != "device" ]; then
  warn "  Device not fully ready; you may need to unlock the screen"
fi

# ---- 3. Setup proxy ----
info "[step-3/8] Configuring HTTP proxy for traffic interception"
setup_proxy
info "  Proxy configured; all HTTP/HTTPS traffic will route through Burp"

# ---- 4. Install APK ----
info "[step-4/8] Installing APK on device"
APK="$RUN_DIR/app.apk"
if [ -f "$APK" ]; then
  APK_SIZE="$(du -h "$APK" | cut -f1)"
  info "  APK: $(basename "$APK") ($APK_SIZE)"
  info "  Running: adb install -r $APK"
  adb_install "$APK"
  
  if [ -n "$PKG" ]; then
    if adb shell pm list packages 2>/dev/null | grep -q "$PKG"; then
      INSTALL_PATH="$(adb shell pm path "$PKG" 2>/dev/null | head -1 | sed 's/package://')"
      ok "  APK installed successfully: $PKG"
      info "  Install path: $INSTALL_PATH"
    else
      warn "  APK installation may have failed; package not found in pm list"
    fi
  fi
else
  warn "  No APK found at $APK (run 00_acquire first)"
fi

# ---- 5. Setup Frida server ----
info "[step-5/8] Setting up Frida server for dynamic instrumentation"
FRIDA_VERSION="$(frida --version 2>/dev/null || echo '16.0.0')"
FRIDA_ARCH="$(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')"
FRIDA_SERVER="/tmp/frida-server-${FRIDA_VERSION}-android-${FRIDA_ARCH}"
info "  Frida client version: $FRIDA_VERSION"
info "  Device architecture: $FRIDA_ARCH"
info "  Expected server: $FRIDA_SERVER"

if [ -x "$FRIDA_SERVER" ]; then
  info "  Pushing Frida server to device: /data/local/tmp/frida-server"
  adb push "$FRIDA_SERVER" /data/local/tmp/frida-server 2>/dev/null
  adb shell "chmod 755 /data/local/tmp/frida-server" 2>/dev/null
  ok "  Frida server deployed"
else
  warn "  Frida server binary not found at $FRIDA_SERVER"
  warn "  Download from: https://github.com/frida/frida/releases"
  warn "  Some dynamic tests will be skipped"
fi

# ---- 6. Start drozer server ----
info "[step-6/8] Starting drozer agent on device"
info "  Searching for drozer runtime.jar..."
DROZER_JAR="$(find /home -name 'runtime.jar' -path '*/drozer/*' 2>/dev/null | head -1)"
if [ -n "$DROZER_JAR" ]; then
  info "  Found: $DROZER_JAR"
  info "  Pushing to device: /data/local/tmp/drozer.jar"
  adb push "$DROZER_JAR" /data/local/tmp/drozer.jar 2>/dev/null || true
else
  warn "  drozer runtime.jar not found; skipping push"
fi
info "  Starting drozer ServerService..."
adb shell "am startservice -n com.mwr.dz/.services.ServerService" 2>/dev/null || true
info "  Setting up ADB port forward: tcp:31415 -> tcp:31415"
adb forward tcp:31415 tcp:31415 2>/dev/null || true
ok "  Drozer server started (port 31415)"

# ---- 7. Verify root access ----
info "[step-7/8] Verifying root access on device"
ROOT_UID=$(adb shell "id -u" 2>/dev/null | tr -d '\r' || echo "unknown")
info "  Current UID: $ROOT_UID"
if [ "$ROOT_UID" = "0" ]; then
  ok "  Root access confirmed (uid=0)"
  SU_RESULT=$(adb shell "su -c 'echo root_ok'" 2>/dev/null | tr -d '\r')
  if [ "$SU_RESULT" = "root_ok" ]; then
    ok "  su binary working correctly"
  else
    warn "  su binary present but may not work properly"
  fi
else
  warn "  No root access (uid=$ROOT_UID); some tests will be limited"
  warn "  Genymotion devices are usually pre-rooted; check Settings > About"
fi

# ---- 8. Check MobSF ----
info "[step-8/8] Checking MobSF (Mobile Security Framework) availability"
if curl -s http://127.0.0.1:8000/api/v1/upload > /dev/null 2>&1; then
  ok "  MobSF already running on :8000"
elif [ -d "$HOME/tools/MobSF" ]; then
  info "  MobSF found at ~/tools/MobSF; starting server on port 8000..."
  cd "$HOME/tools/MobSF" && nohup python3 manage.py runserver 8000 &>/dev/null &
  sleep 3
  if curl -s http://127.0.0.1:8000/api/v1/upload > /dev/null 2>&1; then
    ok "  MobSF started successfully"
  else
    warn "  MobSF failed to start; dynamic DAST phase may be skipped"
  fi
else
  warn "  MobSF not found (optional; install from https://github.com/MobSF/Mobile-Security-Framework-MobSF)"
fi

ok "Genymotion setup complete"
info "Final device state: $DEVICE | Model: $DEVICE_MODEL | Android: $ANDROID_VERSION | State: $(adb get-state 2>/dev/null || echo unknown)"
