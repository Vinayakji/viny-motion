#!/usr/bin/env bash
# flutter-analysis.sh — Flutter/Dart cross-platform APK analysis
set -uo pipefail
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
JADX_DIR="$RUN_DIR/static/jadx"
OUT_DIR="$RUN_DIR/cross_platform/flutter"
mkdir -p "$OUT_DIR"

info "=== Flutter/Dart Analysis ==="

# A. Detect Flutter
info "[step-A/6] Detecting Flutter artifacts"
FLUTTER_LIBS=$(find "$RUN_DIR" -name "libflutter.so" -o -name "libapp.so" 2>/dev/null | wc -l)
DART_FILES=$(find "$JADX_DIR" -name "*.dart" 2>/dev/null | wc -l)
FLUTTER_CLASSES=$(grep -rn "io\.flutter\|FlutterActivity\|FlutterView\|FlutterEngine\|DartFlutter\|dart:" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
FLUTTER_META=$(grep -rn "flutter\|dart" "$RUN_DIR/static/manifest.xml" 2>/dev/null | wc -l)
info "  Flutter libs: $FLUTTER_LIBS, Dart files: $DART_FILES, Flutter classes: $FLUTTER_CLASSES, Meta: $FLUTTER_META"

if [ "$FLUTTER_LIBS" -eq 0 ] && [ "$DART_FILES" -eq 0 ] && [ "$FLUTTER_CLASSES" -lt 2 ]; then
  warn "No Flutter artifacts detected — app may not be Flutter-based"
  info "Continuing analysis for completeness..."
fi

# B. Native library analysis
info "[step-B/6] Flutter native library analysis"
for lib in libflutter.so libapp.so; do
  LIB_PATH=$(find "$RUN_DIR" -name "$lib" 2>/dev/null | head -1)
  if [ -n "$LIB_PATH" ]; then
    info "  Found: $lib ($LIB_PATH)"
    SIZE=$(stat -c%s "$LIB_PATH" 2>/dev/null || echo "0")
    info "  Size: $SIZE bytes"
    
    # Check protections
    if command -v readelf >/dev/null 2>&1; then
      STACK_CANARY=$(readelf -s "$LIB_PATH" 2>/dev/null | grep -c "__stack_chk_fail" || echo "0")
      NX=$(readelf -l "$LIB_PATH" 2>/dev/null | grep -c "GNU_STACK.*RWE" || echo "0")
      PIE=$(readelf -h "$LIB_PATH" 2>/dev/null | grep -c "DYN" || echo "0")
      RELRO=$(readelf -l "$LIB_PATH" 2>/dev/null | grep -c "GNU_RELRO" || echo "0")
      info "  Protections: NX=$NX PIE=$PIE RELRO=$RELRO Canary=$STACK_CANARY"
    fi
    
    # Extract strings for secrets
    STRINGS=$(strings "$LIB_PATH" 2>/dev/null | grep -iE "api[_-]?key|secret|token|password|firebase|http[s]?://" | head -20)
    if [ -n "$STRINGS" ]; then
      warn "  Interesting strings found in $lib"
      echo "$STRINGS" >> "$OUT_DIR/native_strings.txt"
    fi
  fi
done

# C. Dart snapshot analysis
info "[step-C/6] Dart snapshot analysis"
DAPTSNAP=$(find "$RUN_DIR" -name "assets/dart_vm_entry_points.txt" -o -name "assets/kernel_blob.bin" -o -name "assets/isolate_snapshot.bin" 2>/dev/null | wc -l)
info "  Dart snapshot artifacts: $DAPTSNAP"

# D. Flutter channel/MethodChannel analysis
info "[step-D/6] Flutter MethodChannel analysis"
METHOD_CHANNELS=$(grep -rn "MethodChannel\|invokeMethod\|setMethodCallHandler\|platform\.invokeMethod" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  MethodChannel references: $METHOD_CHANNELS"
if [ "$METHOD_CHANNELS" -gt 0 ]; then
  grep -rn "MethodChannel\|invokeMethod" "$JADX_DIR/sources/" 2>/dev/null | head -20 > "$OUT_DIR/method_channels.txt"
  info "  Saved to $OUT_DIR/method_channels.txt"
fi

# E. Flutter security checks
info "[step-E/6] Flutter security assessment"
SSL_PIN=$(grep -rn "certificatePinning\|ssl.*pin\|HttpOverrides\|SecurityContext" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
JAILBREAK=$(grep -rn "jailbreak\|root.*detect\|RootBeer" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
OBFUSCATION=$(grep -rn "flutter_obfuscation\|obfuscate.*true\|--obfuscate" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  SSL pinning refs: $SSL_PIN"
info "  Jailbreak detection: $JAILBREAK"
info "  Obfuscation: $OBFUSCATION"

# F. Generate findings
info "[step-F/6] Creating Flutter findings"
[ "$FLUTTER_LIBS" -gt 0 ] && fadd "Flutter app detected with $FLUTTER_LIBS native libraries" INFO CERTAIN CWE-676 "A06:2021" "$OUT_DIR"
[ "$METHOD_CHANNELS" -gt 0 ] && fadd "Flutter MethodChannel detected: $METHOD_CHANNELS references" INFO CERTAIN CWE-610 "A06:2021" "$OUT_DIR"
[ "$SSL_PIN" -gt 0 ] && fadd "Flutter SSL pinning implementation detected" INFO CERTAIN CWE-295 "A07:2021" "$OUT_DIR"

STRINGS_FOUND=$(wc -l < "$OUT_DIR/native_strings.txt" 2>/dev/null || echo "0")
[ "$STRINGS_FOUND" -gt 0 ] && fadd "Sensitive strings found in Flutter native libraries: $STRINGS_FOUND" MEDIUM PROBABLE CWE-798 "A02:2021" "$OUT_DIR"

ok "Flutter analysis complete -> $OUT_DIR"
