#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 00_acquire.sh - Download APK from Play Store / APKPure / APKMirror
PROFILE_PHASE="00_acquire"
source "$PIPELINE_ROOT/lib/common.sh"

APK_PATH="$(tget apk path)"
APK_URL="$(tget apk download_url)"
PKG="$(tget apk package_name)"

cd "$RUN_DIR" || exit 1

# If APK already exists, skip download
if [ -n "$APK_PATH" ] && [ -f "$APK_PATH" ]; then
  info "APK already exists: $APK_PATH"
  cp "$APK_PATH" "$RUN_DIR/app.apk"
  ok "APK copied to run dir"
  exit 0
fi

# If URL provided, download it
if [ -n "$APK_URL" ]; then
  info "Downloading APK from: $APK_URL"
  curl -L -o "$RUN_DIR/app.apk" "$APK_URL" 2>/dev/null
  if [ -s "$RUN_DIR/app.apk" ]; then
    ok "APK downloaded: $(du -h "$RUN_DIR/app.apk" | cut -f1)"
  else
    err "Download failed"
    exit 1
  fi
  exit 0
fi

# If package name provided, try to pull from device
if [ -n "$PKG" ]; then
  info "Attempting to pull APK from connected device: $PKG"
  APK_REMOTE="$(adb shell pm path "$PKG" 2>/dev/null | head -1 | sed 's/package://')"
  if [ -n "$APK_REMOTE" ]; then
    adb pull "$APK_REMOTE" "$RUN_DIR/app.apk" 2>/dev/null
    if [ -s "$RUN_DIR/app.apk" ]; then
      ok "APK pulled from device: $(du -h "$RUN_DIR/app.apk" | cut -f1)"
      exit 0
    fi
  fi
  warn "Could not pull APK from device"
fi

err "No APK source specified. Set apk.path, apk.download_url, or apk.package_name in config/target.yaml"
exit 1
