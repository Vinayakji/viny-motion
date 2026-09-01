#!/usr/bin/env bash
# unity-analysis.sh — Unity game engine APK analysis
set -uo pipefail
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
JADX_DIR="$RUN_DIR/static/jadx"
OUT_DIR="$RUN_DIR/cross_platform/unity"
mkdir -p "$OUT_DIR"

info "=== Unity Engine Analysis ==="

# A. Detect Unity
info "[step-A/5] Detecting Unity artifacts"
UNITY_CLASSES=$(grep -rn "com\.unity3d\|UnityPlayer\|UnityActivity\|UnityEngine\|UnityEngine\.Player" "$JADX_DIR/sources/" 2>/dev/null | wc -1)
UNITY_LIB=$(find "$RUN_DIR" -name "libunity.so" -o -name "libil2cpp.so" -o -name "libmain.so" 2>/dev/null | wc -l)
UNITY_DATA=$(find "$RUN_DIR" -name "assets/bin/Data/*" -o -name "globalgamemanagers*" 2>/dev/null | wc -l)
info "  Unity classes: $UNITY_CLASSES, libs: $UNITY_LIB, data files: $UNITY_DATA"

if [ "$UNITY_CLASSES" -eq 0 ] && [ "$UNITY_LIB" -eq 0 ]; then
  warn "No Unity artifacts detected"
fi

# B. IL2CPP analysis
info "[step-B/5] IL2CPP analysis"
IL2CPP_LIB=$(find "$RUN_DIR" -name "libil2cpp.so" 2>/dev/null | head -1)
if [ -n "$IL2CPP_LIB" ] && [ -f "$IL2CPP_LIB" ]; then
  SIZE=$(stat -c%s "$IL2CPP_LIB" 2>/dev/null || echo "0")
  info "  IL2CPP: $IL2CPP_LIB ($SIZE bytes)"
  
  # Metadata
  METADATA=$(find "$RUN_DIR" -name "il2cpp_metadata.dat" -o -name "global-metadata.dat" 2>/dev/null | head -1)
  [ -n "$METADATA" ] && info "  Metadata: $METADATA"
  
  # Strings extraction
  STRINGS=$(strings "$IL2CPP_LIB" 2>/dev/null | grep -iE "https?://|api[_-]?key|secret|token|password|firebase|aws|gcp|azure" | head -30)
  if [ -n "$STRINGS" ]; then
    warn "  Interesting strings in IL2CPP library"
    echo "$STRINGS" > "$OUT_DIR/il2cpp_strings.txt"
  fi
  
  # Native method count
  NATIVE_METHODS=$(strings "$IL2CPP_LIB" 2>/dev/null | grep -c "Java_" || echo "0")
  info "  JNI methods: $NATIVE_METHODS"
fi

# C. Unity-specific classes
info "[step-C/5] Unity runtime classes"
UNITY_NETWORK=$(grep -rn "UnityEngine\.Networking\|UnityWebRequest\|WWW" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
UNITY_PREFS=$(grep -rn "PlayerPrefs" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
UNITY_LOAD=$(grep -rn "AssetBundle\|Resources\.Load\|Addressables" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  Networking: $UNITY_NETWORK, PlayerPrefs: $UNITY_PREFS, Asset loading: $UNITY_LOAD"

# D. Security assessment
info "[step-D/5] Unity security assessment"
SSL_PIN=$(grep -rn "certificatePinning\|ssl.*pin\|Security\.Start.*https" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
DEBUG=$(grep -rn "Debug\.isDebugBuild\|Debug\.isDebug" "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  SSL pinning: $SSL_PIN, Debug checks: $DEBUG"

# E. Create findings
info "[step-E/5] Creating Unity findings"
[ "$UNITY_CLASSES" -gt 0 ] && fadd "Unity game engine detected ($UNITY_CLASSES classes)" INFO CERTAIN CWE-676 "A06:2021" "$OUT_DIR"
[ "$NATIVE_METHODS" -gt 0 ] && fadd "Unity IL2CPP: $NATIVE_METHODS JNI methods" INFO CERTAIN CWE-676 "A06:2021" "$OUT_DIR" 2>/dev/null || true
STRINGS_COUNT=$(wc -l < "$OUT_DIR/il2cpp_strings.txt" 2>/dev/null || echo "0")
[ "$STRINGS_COUNT" -gt 0 ] && fadd "Sensitive strings in IL2CPP: $STRINGS_COUNT" MEDIUM PROBABLE CWE-798 "A02:2021" "$OUT_DIR"
[ "$UNITY_PREFS" -gt 0 ] && fadd "Unity PlayerPrefs: $UNITY_PREFS references (verify not storing sensitive data)" INFO PROBABLE CWE-922 "A02:2021" "$OUT_DIR"

ok "Unity analysis complete -> $OUT_DIR"
