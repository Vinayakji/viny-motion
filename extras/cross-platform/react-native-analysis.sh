#!/usr/bin/env bash
# react-native-analysis.sh — React Native cross-platform APK analysis
set -uo pipefail
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
JADX_DIR="$RUN_DIR/static/jadx"
OUT_DIR="$RUN_DIR/cross_platform/react_native"
mkdir -p "$OUT_DIR"

info "=== React Native Analysis ==="

# A. Detect React Native
info "[step-A/6] Detecting React Native artifacts"
RN_CLASSES=$(grep -rn "com\.facebook\.react\|ReactActivity\|ReactNativeHost\|ReactInstanceManager\|ReactRootView\|com\.facebook\.hermes" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
HERMES=$(find "$RUN_DIR" -name "libhermes.so" -o -name "index.android.bundle" 2>/dev/null | wc -l)
JS_BUNDLE=$(find "$RUN_DIR" -name "assets/index.android.bundle" -o -name "assets/index.android.bundle" 2>/dev/null | head -1)
RN_META=$(grep -rn "react\|hermes" "$RUN_DIR/static/manifest.xml" 2>/dev/null | wc -l)
info "  RN classes: $RN_CLASSES, Hermes: $HERMES, Meta: $RN_META"

if [ "$RN_CLASSES" -eq 0 ] && [ "$HERMES" -eq 0 ] && [ "$RN_META" -lt 2 ]; then
  warn "No React Native artifacts detected — app may not be RN-based"
fi

# B. JavaScript bundle analysis
info "[step-B/6] JavaScript bundle analysis"
if [ -n "$JS_BUNDLE" ] && [ -f "$JS_BUNDLE" ]; then
  BUNDLE_SIZE=$(stat -c%s "$JS_BUNDLE" 2>/dev/null || echo "0")
  info "  JS bundle: $JS_BUNDLE ($BUNDLE_SIZE bytes)"
  
  # Extract URLs, secrets, endpoints
  URLS=$(strings "$JS_BUNDLE" 2>/dev/null | grep -iE "https?://" | sort -u | head -30)
  SECRETS=$(strings "$JS_BUNDLE" 2>/dev/null | grep -iE "api[_-]?key|secret|token|password|firebase" | head -20)
  ENDPOINTS=$(strings "$JS_BUNDLE" 2>/dev/null | grep -iE "/api/|/v1/|/v2/|/graphql|endpoint" | sort -u | head -30)
  
  [ -n "$URLS" ] && echo "$URLS" > "$OUT_DIR/bundle_urls.txt" && info "  URLs found: $(echo "$URLS" | wc -l)"
  [ -n "$SECRETS" ] && echo "$SECRETS" > "$OUT_DIR/bundle_secrets.txt" && warn "  Potential secrets: $(echo "$SECRETS" | wc -l)"
  [ -n "$ENDPOINTS" ] && echo "$ENDPOINTS" > "$OUT_DIR/bundle_endpoints.txt" && info "  Endpoints: $(echo "$ENDPOINTS" | wc -l)"
  
  # Check for source maps
  SOURCEMAP=$(find "$RUN_DIR" -name "*.jsbundle.map" -o -name "*.js.map" 2>/dev/null | wc -l)
  info "  Source maps: $SOURCEMAP"
  [ "$SOURCEMAP" -gt 0 ] && fadd "JavaScript source maps found in React Native app ($SOURCEMAP)" MEDIUM CERTAIN CWE-200 "A04:2021" "$OUT_DIR"
else
  info "  No JS bundle found at expected location"
fi

# C. Hermes engine analysis
info "[step-C/6] Hermes engine analysis"
HERMES_LIB=$(find "$RUN_DIR" -name "libhermes.so" 2>/dev/null | head -1)
if [ -n "$HERMES_LIB" ]; then
  info "  Hermes engine: $HERMES_LIB"
  SIZE=$(stat -c%s "$HERMES_LIB" 2>/dev/null || echo "0")
  info "  Size: $SIZE bytes"
  
  if command -v readelf >/dev/null 2>&1; then
    NX=$(readelf -l "$HERMES_LIB" 2>/dev/null | grep -c "GNU_STACK.*RWE" || echo "0")
    info "  NX: $NX"
  fi
fi

# D. Native module analysis
info "[step-D/6] React Native native module analysis"
BRIDGE_MODULES=$(grep -rn "ReactMethod\|@ReactMethod\|ReactModule\|NativeModule\|TurboModule" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  Bridge module references: $BRIDGE_MODULES"
if [ "$BRIDGE_MODULES" -gt 0 ]; then
  grep -rn "ReactMethod\|@ReactMethod" "$JADX_DIR/sources/" 2>/dev/null | head -30 > "$OUT_DIR/bridge_methods.txt"
  info "  Saved bridge methods to $OUT_DIR/bridge_methods.txt"
fi

# E. Security assessment
info "[step-E/6] React Native security assessment"
SSL_PIN=$(grep -rn "certificatePinning\|ssl.*pin\|SslCertificate\|TrustManager" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
DEBUGGABLE=$(grep -rn "devSupport\|isDebuggable\|DevServerHelper\|ReactNativeHost.*getUseDeveloperSupport" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
INFO "  SSL pinning: $SSL_PIN"
INFO "  Debug support: $DEBUGGABLE"

# F. Create findings
info "[step-F/6] Creating React Native findings"
SECRET_COUNT=$(wc -l < "$OUT_DIR/bundle_secrets.txt" 2>/dev/null || echo "0")
[ "$SECRET_COUNT" -gt 0 ] && fadd "Sensitive strings in JS bundle: $SECRET_COUNT potential secrets" MEDIUM PROBABLE CWE-798 "A02:2021" "$OUT_DIR"
[ "$BRIDGE_MODULES" -gt 0 ] && fadd "React Native bridge modules: $BRIDGE_MODULES native methods exposed" INFO CERTAIN CWE-610 "A06:2021" "$OUT_DIR"
[ "$DEBUGGABLE" -gt 0 ] && fadd "React Native dev mode support detected ($DEBUGGABLE references)" INFO PROBABLE CWE-489 "A05:2021" "$OUT_DIR"

ok "React Native analysis complete -> $OUT_DIR"
