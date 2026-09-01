#!/usr/bin/env bash
# android14-testing.sh — Android 14 (API 34) specific security testing
set -uo pipefail
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
JADX_DIR="$RUN_DIR/static/jadx"
OUT_DIR="$RUN_DIR/android14"
mkdir -p "$OUT_DIR"

info "=== Android 14 (API 34) Specific Testing ==="

# Get device SDK
SDK_VER=$(adb shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')
info "Device SDK: $SDK_VER"

# A. Foreground Service Types (Android 14)
info "[step-A/6] Foreground Service Type enforcement"
FS_TYPES=$(grep -rn "foregroundServiceType" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
FS_MANIFEST=$(grep -c "foregroundServiceType" "$RUN_DIR/static/manifest.xml" 2>/dev/null || echo "0")
info "  Foreground service type refs: $FS_TYPES (code), $FS_MANIFEST (manifest)"

# Check for proper type declarations
FS_DECLARED=$(grep -o 'foregroundServiceType="[^"]*"' "$RUN_DIR/static/manifest.xml" 2>/dev/null | sort -u)
if [ -n "$FS_DECLARED" ]; then
  info "  Declared types:"
  echo "$FS_DECLARED" | while read -r line; do
    info "    $line"
  done
fi

# B. Partial Media Access (Android 14)
info "[step-B/6] Partial media access (READ_MEDIA_*)"
READ_MEDIA=$(grep -rn "READ_MEDIA_IMAGES\|READ_MEDIA_VIDEO\|READ_MEDIA_AUDIO" "$RUN_DIR/static/manifest.xml" 2>/dev/null | wc -l)
READ_EXTERNAL=$(grep -c "READ_EXTERNAL_STORAGE" "$RUN_DIR/static/manifest.xml" 2>/dev/null || echo "0")
info "  READ_MEDIA_*: $READ_MEDIA, READ_EXTERNAL_STORAGE: $READ_EXTERNAL"
[ "$READ_EXTERNAL" -gt 0 ] && fadd "App uses deprecated READ_EXTERNAL_STORAGE (Android 14 partial media access)" MEDIUM PROBABLE CWE-922 "A02:2021" "$OUT_DIR"

# C. Runtime-Registered Broadcast Receivers (Android 14)
info "[step-C/6] Runtime-registered broadcast receiver restrictions"
REG_RECEIVERS=$(grep -rn "registerReceiver\|ContextCompat.registerReceiver" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  Runtime-registered receivers: $REG_RECEIVERS"

# Check for RECEIVER_EXPORTED / RECEIVER_NOT_EXPORTED flags
EXPORT_FLAGS=$(grep -rn "RECEIVER_EXPORTED\|RECEIVER_NOT_EXPORTED" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  Export flags used: $EXPORT_FLAGS"
if [ "$REG_RECEIVERS" -gt 0 ] && [ "$EXPORT_FLAGS" -eq 0 ]; then
  warn "  Runtime receivers registered without EXPORTED/NOT_EXPORTED flags"
  fadd "Runtime-registered broadcast receivers without export flag ($REG_RECEIVERS receivers)" MEDIUM PROBABLE CWE-927 "A05:2021" "$OUT_DIR"
fi

# D. Implicit Intent Restrictions (Android 14)
info "[step-D/6] Implicit intent restrictions"
IMPLICIT_INTENTS=$(grep -rn "new Intent(\"" "$JADX_DIR/sources/" 2>/dev/null | wc -1)
IMPLICIT_TARGETS=$(grep -rn "sendBroadcast\|startService\|bindService" "$JADX_DIR/sources/" 2>/dev/null | grep -c "new Intent(" || echo "0")
info "  Implicit intents created: $IMPLICIT_INTENTS"
info "  Implicit targets: $IMPLICIT_TARGETS"

# E. Pending Intent Mutability (Android 12+)
info "[step-E/6] Pending intent mutability"
PENDING_INTENTS=$(grep -rn "PendingIntent\." "$JADX_DIR/sources/" 2>/dev/null | wc -l)
MUTABLE_FLAGS=$(grep -rn "FLAG_MUTABLE\|FLAG_IMMUTABLE" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  PendingIntent usage: $PENDING_INTENTS"
info "  Mutability flags: $MUTABLE_FLAGS"
if [ "$PENDING_INTENTS" -gt 0 ] && [ "$MUTABLE_FLAGS" -eq 0 ]; then
  warn "  PendingIntents without mutability flags"
  fadd "PendingIntents without FLAG_MUTABLE/FLAG_IMMUTABLE ($PENDING_INTENTS uses)" MEDIUM PROBABLE CWE-668 "A04:2021" "$OUT_DIR"
fi

# F. Additional Android 14 checks
info "[step-F/6] Additional Android 14 checks"

# Secure background activity starts
BG_STARTS=$(grep -rn "startActivity\|startActivityForResult" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  Background activity starts: $BG_STARTS"

# Open file descriptor restrictions
FD_CHECKS=$(grep -rn "ParcelFileDescriptor\|openFileDescriptor" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  File descriptor usage: $FD_CHECKS"

# Schedule exact alarm restrictions
EXACT_ALARMS=$(grep -rn "setExact\|setExactAndAllowWhileIdle\|AlarmManager" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  Exact alarm usage: $EXACT_ALARMS"
[ "$EXACT_ALARMS" -gt 0 ] && fadd "Exact alarm usage: $EXACT_ALARMS (check SCHEDULE_EXACT_ALARM permission)" INFO CERTAIN CWE-776 "A05:2021" "$OUT_DIR"

# Cross-app intents
CROSS_INTENTS=$(grep -rn "setPackage\|setComponent\|setClassName" "$JADX_DIR/sources/" 2>/dev/null | wc -1)
info "  Cross-app intents: $CROSS_INTENTS"

info ""
info "=== Android 14 Summary ==="
ok "Android 14 analysis complete -> $OUT_DIR"
