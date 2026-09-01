#!/usr/bin/env bash
# android16-testing.sh — Android 16 (API 36) specific security testing
set -uo pipefail
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
JADX_DIR="$RUN_DIR/static/jadx"
OUT_DIR="$RUN_DIR/android16"
mkdir -p "$OUT_DIR"

info "=== Android 16 (API 36) Specific Testing ==="

SDK_VER=$(adb shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')
info "Device SDK: $SDK_VER"

# A. Cloud Media Provider
info "[step-A/7] Cloud Media Provider"
CLOUD_MEDIA=$(grep -rn "CloudMediaProvider\|android\.provider\.CloudMediaProvider\|EXTERNAL_CLOUD_MEDIA" "$JADX_DIR/sources/" 2>/dev/null | wc -1)
info "  Cloud media references: $CLOUD_MEDIA"

# B. Health Connect API
info "[step-B/7] Health Connect API"
HEALTH=$(grep -rn "HealthConnect\|androidx\.health\.connect\|HEALTH_CONNECT" "$JADX_DIR/sources/" 2>/dev/null | wc -1)
info "  Health Connect refs: $HEALTH"
[ "$HEALTH" -gt 0 ] && fadd "Health Connect API usage: $HEALTH — verify consent and data isolation" INFO CERTAIN CWE-200 "A04:2021" "$OUT_DIR"

# C. Passkey API
info "[step-C/7] Passkey/FIDO2"
PASSKEY=$(grep -rn "Passkey\|Fido2\|FidoApi\|WebAuthn\|CredentialManager" "$JADX_DIR/sources/" 2>/dev/null | wc -1)
info "  Passkey/FIDO refs: $PASSKEY"

# D. Predictive Back Gesture
info "[step-D/7] Predictive back gesture"
PREDICTIVE=$(grep -rn "onBackInvokedCallback\|OnBackInvokedDispatcher\|enableOnBackInvokedCallback\|PREDICTIVE_BACK" "$JADX_DIR/sources/" 2>/dev/null | wc -1)
info "  Predictive back refs: $PREDICTIVE"

# E. Path Provider
info "[step-E/7] Path Provider"
PATH_PROVIDER=$(grep -rn "PathProvider\|android\.provider\.pathprovider" "$JADX_DIR/sources/" 2>/dev/null | wc -1)
info "  Path provider refs: $PATH_PROVIDER"

# F. Credential Manager
info "[step-F/7] Credential Manager"
CRED_MGR=$(grep -rn "CredentialManager\|CreateCredentialRequest\|GetCredentialRequest" "$JADX_DIR/sources/" 2>/dev/null | wc -1)
info "  Credential Manager refs: $CRED_MGR"

# G. Privacy Enhancing Technologies
info "[step-G/7] Privacy Enhancing Technologies"
PHOTO_PICKER=$(grep -rn "PhotoPicker\|PickVisualMedia\|ACTION_PICK_IMAGES" "$JADX_DIR/sources/" 2>/dev/null | wc -1)
info "  Photo picker refs: $PHOTO_PICKER"

READ_MEDIA_IMAGES=$(grep -rn "READ_MEDIA_IMAGES" "$RUN_DIR/static/manifest.xml" 2>/dev/null | wc -l)
READ_MEDIA_VIDEO=$(grep -rn "READ_MEDIA_VIDEO" "$RUN_DIR/static/manifest.xml" 2>/dev/null | wc -l)
READ_MEDIA_AUDIO=$(grep -rn "READ_MEDIA_AUDIO" "$RUN_DIR/static/manifest.xml" 2>/dev/null | wc -l)
info "  READ_MEDIA_IMAGES: $READ_MEDIA_IMAGES, READ_MEDIA_VIDEO: $READ_MEDIA_VIDEO, READ_MEDIA_AUDIO: $READ_MEDIA_AUDIO"

[ "$READ_MEDIA_IMAGES" -gt 0 ] && fadd "READ_MEDIA_IMAGES permission (Android 16 partial access) — verify not used for full access" INFO PROBABLE CWE-922 "A02:2021" "$OUT_DIR"

# H. 16KB Page Size Enforcement
info "[step-H/7] 16KB page size enforcement"
NATIVE_LIBS=$(find "$RUN_DIR" -name "*.so" 2>/dev/null | wc -l)
UNALIGNED_LIBS=0
if [ "$NATIVE_LIBS" -gt 0 ]; then
  for lib in $(find "$RUN_DIR" -name "*.so" 2>/dev/null); do
    if command -v readelf >/dev/null 2>&1; then
      ALIGNED=$(readelf -l "$lib" 2>/dev/null | grep -c "LOAD.*0x4000" || echo "0")
      [ "$ALIGNED" -eq 0 ] && UNALIGNED_LIBS=$((UNALIGNED_LIBS + 1))
    fi
  done
fi
info "  Native libs: $NATIVE_LIBS, potentially unaligned: $UNALIGNED_LIBS"
[ "$UNALIGNED_LIBS" -gt 0 ] && fadd "$UNALIGNED_LIBS native libs may not be 16KB-page aligned (Android 16 requirement)" HIGH PROBABLE CWE-787 "A06:2021" "$OUT_DIR"

# I. Third-party SDK restrictions
info "[step-I/7] Third-party SDK restrictions"
SDK_CLASSES=$(grep -rn "com\.google\.firebase\|com\.facebook\|com\.amplitude\|com\.segment\|com\.branch\|com\.appsflyer\|com\.adjust" "$JADX_DIR/sources/" 2>/dev/null | wc -1)
info "  Third-party SDK classes: $SDK_CLASSES"

# J. App compatibility
info "[step-J/7] App compatibility checks"
TARGET_SDK=$(grep -o 'targetSdkVersion="[^"]*"' "$RUN_DIR/static/manifest.xml" 2>/dev/null | head -1)
MIN_SDK=$(grep -o 'minSdkVersion="[^"]*"' "$RUN_DIR/static/manifest.xml" 2>/dev/null | head -1)
COMPILE_SDK=$(grep -o 'compileSdkVersion="[^"]*"' "$RUN_DIR/static/manifest.xml" 2>/dev/null | head -1)
info "  Target: $TARGET_SDK, Min: $MIN_SDK, Compile: $COMPILE_SDK"

if echo "$TARGET_SDK" | grep -qE 'targetSdkVersion="3[0-5]"'; then
  warn "  Target SDK may need update for Android 16"
fi

info ""
info "=== Android 16 Summary ==="
ok "Android 16 analysis complete -> $OUT_DIR"
