#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 01_static.sh - Static analysis: jadx decompile, manifest, secrets, native libs
PROFILE_PHASE="01_static"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

APK="$RUN_DIR/app.apk"
[ -f "$APK" ] || { err "No APK found at $APK (run 00_acquire first)"; exit 1; }

JADX_DIR="$RUN_DIR/jadx_output"
STATIC_DIR="$RUN_DIR/static"
mkdir -p "$JADX_DIR" "$STATIC_DIR"

cd "$RUN_DIR" || exit 1
info "Static analysis on $(basename "$APK")"

# ---- 1. AAPT metadata ----
info "Extracting APK metadata..."
if command -v aapt >/dev/null 2>&1; then
  aapt dump badging "$APK" > "$STATIC_DIR/aapt_badging.txt" 2>/dev/null
  aapt dump permissions "$APK" > "$STATIC_DIR/aapt_permissions.txt" 2>/dev/null
  ok "AAPT metadata extracted"
fi

# ---- 2. jadx decompile ----
if command -v jadx >/dev/null 2>&1; then
  info "Decompiling with jadx..."
  jadx -d "$JADX_DIR" "$APK" 2>/dev/null
  ok "jadx decompiled to $JADX_DIR"
  
  # Count files
  JAVA_FILES=$(find "$JADX_DIR" -name "*.java" 2>/dev/null | wc -l)
  SMALI_FILES=$(find "$JADX_DIR" -name "*.smali" 2>/dev/null | wc -l)
  info "Java files: $JAVA_FILES, Smali files: $SMALI_FILES"
else
  warn "jadx not found - skipping decompilation"
fi

# ---- 3. AndroidManifest analysis ----
info "Analyzing AndroidManifest.xml..."
MANIFEST=$(find "$JADX_DIR" -name "AndroidManifest.xml" 2>/dev/null | head -1)
if [ -n "$MANIFEST" ]; then
  cp "$MANIFEST" "$STATIC_DIR/AndroidManifest.xml"
  
  # Check for exported components
  EXPORTED=$(grep -c 'exported="true"' "$MANIFEST" 2>/dev/null || echo 0)
  if [ "$EXPORTED" -gt 0 ]; then
    warn "$EXPORTED exported components found"
    grep 'exported="true"' "$MANIFEST" > "$STATIC_DIR/exported_components.txt" 2>/dev/null
  fi
  
  # Check for debuggable
  if grep -q 'android:debuggable="true"' "$MANIFEST" 2>/dev/null; then
    warn "App is DEBUGGABLE"
    fadd "App is debuggable (android:debuggable=true)" HIGH CERTAIN CWE-215 "A05:2021"
  fi
  
  # Check for backup
  if grep -q 'android:allowBackup="true"' "$MANIFEST" 2>/dev/null; then
    warn "Backup is enabled"
    fadd "Backup enabled (android:allowBackup=true)" MEDIUM CERTAIN CWE-212 "A04:2021"
  fi
  
  # Check for cleartext traffic
  if grep -q 'android:usesCleartextTraffic="true"' "$MANIFEST" 2>/dev/null; then
    warn "Cleartext traffic allowed"
    fadd "Cleartext traffic allowed" MEDIUM CERTAIN CWE-319 "A02:2021"
  fi
  
  ok "Manifest analysis complete"
else
  warn "AndroidManifest.xml not found"
fi

# ---- 4. Secrets extraction ----
info "Extracting hardcoded secrets..."
SECRETS="$STATIC_DIR/secrets.txt"
: > "$SECRETS"

# API keys
grep -rhoE 'AIza[0-9A-Za-z_-]{35}' "$JADX_DIR" 2>/dev/null | sort -u > "$STATIC_DIR/firebase_keys.txt"
grep -rhoE 'AKIA[0-9A-Z]{16}' "$JADX_DIR" 2>/dev/null | sort -u > "$STATIC_DIR/aws_keys.txt"
grep -rhoE '[a-zA-Z0-9]{32,}' "$JADX_DIR" 2>/dev/null | head -100 >> "$SECRETS"

# URLs
grep -rhoE 'https?://[a-zA-Z0-9./_-]+' "$JADX_DIR" 2>/dev/null | sort -u > "$STATIC_DIR/urls.txt"

# Hosts
grep -rhoE '[a-z0-9.-]+\.[a-z]{2,}' "$JADX_DIR" 2>/dev/null | sort -u > "$STATIC_DIR/hosts.txt"

if [ -s "$STATIC_DIR/firebase_keys.txt" ]; then
  warn "Firebase keys found: $(wc -l < "$STATIC_DIR/firebase_keys.txt")"
  fadd "Hardcoded Firebase API key" HIGH CERTAIN CWE-798 "A07:2021" "$STATIC_DIR/firebase_keys.txt"
fi

if [ -s "$STATIC_DIR/aws_keys.txt" ]; then
  warn "AWS keys found: $(wc -l < "$STATIC_DIR/aws_keys.txt")"
  fadd "Hardcoded AWS access key" CRITICAL CERTAIN CWE-798 "A07:2021" "$STATIC_DIR/aws_keys.txt"
fi

ok "Secrets extraction complete"

# ---- 5. Native library analysis ----
info "Analyzing native libraries..."
NATIVE_DIR="$STATIC_DIR/native_libs"
mkdir -p "$NATIVE_DIR"
find "$JADX_DIR" -name "*.so" -exec cp {} "$NATIVE_DIR/" \; 2>/dev/null
NATIVE_COUNT=$(ls "$NATIVE_DIR"/*.so 2>/dev/null | wc -l)
info "Native libraries found: $NATIVE_COUNT"

if [ "$NATIVE_COUNT" -gt 0 ]; then
  for lib in "$NATIVE_DIR"/*.so; do
    info "Checking $(basename "$lib") for security issues..."
    # Check for interesting strings
    strings "$lib" 2>/dev/null | grep -iE '(password|secret|key|token|api)' >> "$STATIC_DIR/native_strings.txt" 2>/dev/null
  done
fi

ok "Static analysis complete -> $STATIC_DIR"
fsnapshot
