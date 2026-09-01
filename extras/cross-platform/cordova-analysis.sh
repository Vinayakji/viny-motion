#!/usr/bin/env bash
# cordova-analysis.sh — Cordova/PhoneGap cross-platform APK analysis
set -uo pipefail
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
JADX_DIR="$RUN_DIR/static/jadx"
OUT_DIR="$RUN_DIR/cross_platform/cordova"
mkdir -p "$OUT_DIR"

info "=== Cordova/PhoneGap Analysis ==="

# A. Detect Cordova
info "[step-A/5] Detecting Cordova artifacts"
CORDOVA_CLASSES=$(grep -rn "org\.apache\.cordova\|CordovaActivity\|CordovaPlugin\|CordovaInterface\|CordovaWebView" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
CORDOVA_JS=$(find "$RUN_DIR" -name "cordova.js" -o -name "cordova_plugins.js" 2>/dev/null | wc -l)
WWW_DIR=$(find "$RUN_DIR" -path "*/assets/www/*" 2>/dev/null | head -1)
info "  Cordova classes: $CORDOVA_CLASSES, JS files: $CORDOVA_JS, www: $([ -n "$WWW_DIR" ] && echo "found" || echo "not found")"

if [ "$CORDOVA_CLASSES" -eq 0 ] && [ "$CORDOVA_JS" -eq 0 ]; then
  warn "No Cordova artifacts detected"
fi

# B. Plugin analysis
info "[step-B/5] Cordova plugin analysis"
PLUGINS_DIR=$(find "$RUN_DIR" -path "*/assets/www/plugins/*" -type d 2>/dev/null | head -1)
if [ -n "$PLUGINS_DIR" ]; then
  PLUGIN_COUNT=$(ls "$PLUGINS_DIR" 2>/dev/null | wc -l)
  info "  Plugins directory: $PLUGINS_DIR ($PLUGIN_COUNT plugins)"
  ls "$PLUGINS_DIR" > "$OUT_DIR/plugin_list.txt"
else
  info "  No plugins directory found"
  PLUGIN_COUNT=0
fi

# C. Config.xml analysis
info "[step-C/5] Config.xml analysis"
CONFIG_XML=$(find "$RUN_DIR" -name "config.xml" -path "*/assets/www/*" 2>/dev/null | head -1)
if [ -n "$CONFIG_XML" ] && [ -f "$CONFIG_XML" ]; then
  info "  Found config.xml"
  ALLOW_NAV=$(grep -o 'allow-navigation="[^"]*"' "$CONFIG_XML" 2>/dev/null | wc -l)
  ALLOW_INTENT=$(grep -o 'allow-intent="[^"]*"' "$CONFIG_XML" 2>/dev/null | wc -l)
  ACCESS_ORIGINS=$(grep -o 'access origin="[^"]*"' "$CONFIG_XML" 2>/dev/null | wc -l)
  info "  allow-navigation: $ALLOW_NAV, allow-intent: $ALLOW_INTENT, access origins: $ACCESS_ORIGINS"
  
  grep -oE '(allow-navigation|allow-intent|access origin)="[^"]*"' "$CONFIG_XML" > "$OUT_DIR/cordova_config.txt" 2>/dev/null
  
  # Check for dangerous configs
  WILDCARD=$(grep -o 'access origin="\*"' "$CONFIG_XML" 2>/dev/null | wc -l)
  [ "$WILDCARD" -gt 0 ] && fadd "Cordova wildcard access origin (allows all domains)" HIGH CERTAIN CWE-942 "A07:2021" "$OUT_DIR"
  [ "$ALLOW_NAV" -gt 0 ] && fadd "Cordova allow-navigation configured ($ALLOW_NAV entries) — verify not bypassing origin checks" INFO PROBABLE CWE-942 "A07:2021" "$OUT_DIR"
fi

# D. WebView security
info "[step-D/5] Cordova WebView security"
JS_INTERFACE=$(grep -rn "addJavascriptInterface\|@JavascriptInterface" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
FILE_ACCESS=$(grep -rn "setAllowFileAccess\|setAllowFileAccessFromFileURLs\|setAllowUniversalAccessFromFileURLs" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  JS interfaces: $JS_INTERFACE, File access: $FILE_ACCESS"

# E. Create findings
info "[step-E/5] Creating Cordova findings"
[ "$CORDOVA_CLASSES" -gt 0 ] && fadd "Cordova/PhoneGap app detected ($CORDOVA_CLASSES classes)" INFO CERTAIN CWE-676 "A06:2021" "$OUT_DIR"
[ "$PLUGIN_COUNT" -gt 0 ] && fadd "Cordova plugins: $PLUGIN_COUNT installed" INFO CERTAIN CWE-676 "A06:2021" "$OUT_DIR"
[ "$JS_INTERFACE" -gt 0 ] && fadd "Cordova JavaScript interface: $JS_INTERFACE bridges" INFO PROBABLE CWE-610 "A07:2021" "$OUT_DIR"
[ "$FILE_ACCESS" -gt 0 ] && fadd "Cordova file access enabled: $FILE_ACCESS references" MEDIUM PROBABLE CWE-610 "A07:2021" "$OUT_DIR"

ok "Cordova analysis complete -> $OUT_DIR"
