#!/usr/bin/env bash
# android15-testing.sh — Android 15 (API 35) specific security testing
set -uo pipefail
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
JADX_DIR="$RUN_DIR/static/jadx"
OUT_DIR="$RUN_DIR/android15"
mkdir -p "$OUT_DIR"

info "=== Android 15 (API 35) Specific Testing ==="

SDK_VER=$(adb shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')
info "Device SDK: $SDK_VER"

# A. PDF Rendering Restrictions
info "[step-A/7] PDF rendering changes"
PDF_REFS=$(grep -rn "PdfRenderer\|PdfDocument\|PdfView\|android\.graphics\.pdf" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  PDF API usage: $PDF_REFS"
[ "$PDF_REFS" -gt 0 ] && fadd "PDF rendering API usage: $PDF_REFS references — verify no custom rendering bypass" INFO PROBABLE CWE-610 "A07:2021" "$OUT_DIR"

# B. 16KB Page Size Support
info "[step-B/7] 16KB page size compatibility"
NATIVE_LIBS=$(find "$RUN_DIR" -name "*.so" 2>/dev/null | wc -l)
info "  Native libraries: $NATIVE_LIBS"
if [ "$NATIVE_LIBS" -gt 0 ]; then
  for lib in $(find "$RUN_DIR" -name "*.so" 2>/dev/null | head -5); do
    if command -v readelf >/dev/null 2>&1; then
      ALIGN=$(readelf -l "$lib" 2>/dev/null | grep "LOAD" | awk '{print $NF}' | head -1)
      info "    $(basename "$lib"): alignment=$ALIGN"
    fi
  done
fi

# C. Privacy Sandbox Changes
info "[step-C/7] Privacy Sandbox"
AD_ID=$(grep -rn "AdvertisingIdClient\|com\.google\.android\.gms\.ads\.identifier\|AD_ID\|advertisingId" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  Ad ID usage: $AD_ID"
[ "$AD_ID" -gt 0 ] && fadd "Advertising ID usage: $AD_ID references — verify Privacy Sandbox compliance" INFO CERTAIN CWE-200 "A04:2021" "$OUT_DIR"

# D. Updated Permissions Model
info "[step-D/7] Updated permissions model"
SENS_PERMS=$(grep -rn "SENSITIVE_PERM_PROTECTION_LEVEL\|permission.*hardcoded\|android:protectionLevel" "$JADX_DIR/sources/" 2>/dev/null | wc -1)
info "  Protection level references: $SENS_PERMS"

# Check for dangerous permissions without runtime checks
DANGEROUS_PERMS=$(grep -rn "CAMERA\|RECORD_AUDIO\|ACCESS_FINE_LOCATION\|READ_CONTACTS\|READ_SMS\|CALL_PHONE\|READ_CALL_LOG\|BODY_SENSORS\|ACTIVITY_RECOGNITION" "$RUN_DIR/static/manifest.xml" 2>/dev/null | wc -l)
info "  Dangerous permissions in manifest: $DANGEROUS_PERMS"

# E. WebView Changes
info "[step-E/7] WebView security updates"
WEBVIEW_HARDENING=$(grep -rn "WebViewAssetLoader\|WebView\.setSafeBrowsingEnabled\|WebViewClient.*shouldInterceptRequest" "$JADX_DIR/sources/" 2>/dev/null | wc -1)
info "  WebView hardening: $WEBVIEW_HARDENING"

JS_BRIDGE=$(grep -rn "addJavascriptInterface\|@JavascriptInterface" "$JADX_DIR/sources/" 2>/dev/null | wc -1)
FILE_ACCESS=$(grep -rn "setAllowFileAccessFromFileURLs\|setAllowUniversalAccessFromFileURLs" "$JADX_DIR/sources/" 2>/dev/null | wc -1)
info "  JS bridges: $JS_BRIDGE, File access: $FILE_ACCESS"
[ "$FILE_ACCESS" -gt 0 ] && fadd "WebView file access from file URLs: $FILE_ACCESS (critical in Android 15)" HIGH PROBABLE CWE-610 "A07:2021" "$OUT_DIR"

# F. Crypto Provider Updates
info "[step-F/7] Cryptographic provider"
BouncyCastle=$(grep -rn "BouncyCastle\|BC\.getInstance\|SpongyCastle" "$JADX_DIR/sources/" 2>/dev/null | wc -1)
Conscrypt=$(grep -rn "Conscrypt\|Platform\.isConscrypt" "$JADX_DIR/sources/" 2>/dev/null | wc -1)
info "  BouncyCastle: $BouncyCastle, Conscrypt: $Conscrypt"
[ "$BouncyCastle" -gt 0 ] && fadd "BouncyCastle crypto provider usage: $BouncyCastle — verify Android 15 compatibility" INFO PROBABLE CWE-327 "A06:2021" "$OUT_DIR"

# G. Additional Android 15 checks
info "[step-G/7] Additional Android 15 checks"

# Edge-to-edge enforcement
EDGE=$(grep -rn "enableEdgeToEdge\|WindowCompat\.setDecorFitsSystemWindows\|LAYOUT_IN_DISPLAY_CUTOUT" "$JADX_DIR/sources/" 2>/dev/null | wc -1)
info "  Edge-to-edge: $EDGE"

# 16KB page size for native libs
NATIVE_ALIGNED=$(find "$RUN_DIR" -name "*.so" -exec sh -c 'readelf -l "{}" 2>/dev/null | grep -q "LOAD.*0x4000"' \; -print 2>/dev/null | wc -l)
info "  16KB-aligned native libs: $NATIVE_ALIGNED"

info ""
info "=== Android 15 Summary ==="
ok "Android 15 analysis complete -> $OUT_DIR"
