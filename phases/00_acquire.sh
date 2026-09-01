#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 00_acquire.sh - Download APK from Play Store / APKPure / APKMirror
PROFILE_PHASE="00_acquire"
source "$PIPELINE_ROOT/lib/common.sh"

APK_PATH="$(tget apk path)"
APK_URL="$(tget apk download_url)"
PKG="$(tget apk package_name)"

cd "$RUN_DIR" || exit 1

# Step 1: Check if APK already exists locally
info "[step-1/4] Checking for pre-existing APK in config"
if [ -n "$APK_PATH" ] && [ -f "$APK_PATH" ]; then
  info "  Found apk.path=$APK_PATH"
  info "  File size: $(du -h "$APK_PATH" | cut -f1)"
  info "  Copying APK to run directory: $RUN_DIR/app.apk"
  cp "$APK_PATH" "$RUN_DIR/app.apk"
  ok "  APK copied successfully ($(du -h "$RUN_DIR/app.apk" | cut -f1))"
  exit 0
fi
info "  No pre-existing APK found; proceeding to download options"

# Step 2: Download from URL if provided
if [ -n "$APK_URL" ]; then
  info "[step-2/4] Downloading APK from URL: $APK_URL"
  info "  Output: $RUN_DIR/app.apk"
  info "  Follow redirects: yes | Timeout: none | Progress: hidden"
  curl -L -o "$RUN_DIR/app.apk" "$APK_URL" 2>/dev/null
  if [ -s "$RUN_DIR/app.apk" ]; then
    DL_SIZE="$(du -h "$RUN_DIR/app.apk" | cut -f1)"
    DL_BYTES="$(stat -c%s "$RUN_DIR/app.apk" 2>/dev/null || echo 0)"
    ok "  Download complete: $DL_SIZE ($DL_BYTES bytes)"
  else
    err "  Download failed or produced empty file"
    err "  Check URL accessibility and network connectivity"
    exit 1
  fi
  exit 0
fi

# Step 3: Pull from connected device via ADB
if [ -n "$PKG" ]; then
  info "[step-3/4] Attempting to pull APK from connected device"
  info "  Package: $PKG"
  info "  Querying device for APK path via: adb shell pm path $PKG"
  APK_REMOTE="$(adb shell pm path "$PKG" 2>/dev/null | head -1 | sed 's/package://')"
  if [ -n "$APK_REMOTE" ]; then
    info "  Device APK path: $APK_REMOTE"
    info "  Pulling via: adb pull $APK_REMOTE $RUN_DIR/app.apk"
    adb pull "$APK_REMOTE" "$RUN_DIR/app.apk" 2>/dev/null
    if [ -s "$RUN_DIR/app.apk" ]; then
      ok "  APK pulled from device: $(du -h "$RUN_DIR/app.apk" | cut -f1)"
      exit 0
    fi
    warn "  adb pull succeeded but file is empty"
  else
    warn "  Could not locate APK on device (app may not be installed)"
  fi
fi

# Step 4: No source available
err "[step-4/4] No APK source available"
err "  Tried: apk.path=$APK_PATH, apk.download_url=$APK_URL, apk.package_name=$PKG"
err "  Provide one of: apk.path, apk.download_url, or apk.package_name in config/target.yaml"
exit 1
