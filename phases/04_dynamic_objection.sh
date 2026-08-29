#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 04_dynamic_objection.sh - Frida-based runtime hooking via objection (IMPROVED)
# Uses proper API execution with timeouts instead of fragile sleep-based approach
PROFILE_PHASE="04_dynamic_objection"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"
source "$PIPELINE_ROOT/lib/objection_helpers.sh"

PKG="$(tget apk package_name)"
SSL_BYPASS="$(tget frida ssl_bypass)"
ROOT_BYPASS="$(tget frida root_bypass)"

cd "$RUN_DIR" || exit 1
info "Objection testing on $PKG"

OBJECTION_DIR="$RUN_DIR/objection"
mkdir -p "$OBJECTION_DIR"

# Check objection
command -v objection >/dev/null 2>&1 || { warn "objection not installed (pip install objection)"; exit 0; }

# ---- 1. SSL Pinning Bypass ----
if [ "$SSL_BYPASS" = "true" ]; then
  info "Attempting SSL pinning bypass..."
  if objection_run_and_verify "$PKG" "android sslpinning disable" \
    "$OBJECTION_DIR/ssl_bypass.txt" "success\|bypassed\|disabled" 45; then
    fadd "SSL pinning bypass (objection)" MEDIUM CERTAIN CWE-295 "A02:2021" "$OBJECTION_DIR/ssl_bypass.txt"
  else
    warn "SSL pinning bypass failed - will try alternative methods"
  fi
fi

# ---- 2. Root Detection Bypass ----
if [ "$ROOT_BYPASS" = "true" ]; then
  info "Attempting root detection bypass..."
  if objection_run_and_verify "$PKG" "android root disable" \
    "$OBJECTION_DIR/root_bypass.txt" "success\|disabled\|bypassed" 45; then
    fadd "Root detection bypass (objection)" MEDIUM CERTAIN CWE-284 "A01:2021" "$OBJECTION_DIR/root_bypass.txt"
  else
    warn "Root detection bypass failed"
  fi
fi

# ---- 3. Keychain/Keystore Dump ----
info "Dumping keystore..."
objection_run "$PKG" "android keystore list" "$OBJECTION_DIR/keystore.txt" 30

if [ -s "$OBJECTION_DIR/keystore.txt" ]; then
  warn "Keystore entries found"
  dump_objection_structured "$OBJECTION_DIR/keystore.txt" \
    "Keystore entries exposed (objection)" MEDIUM CWE-321 "A02:2021"
fi

# ---- 4. SharedPreferences Dump ----
info "Dumping SharedPreferences..."
objection_run "$PKG" "android sharedpref get" "$OBJECTION_DIR/sharedprefs.txt" 30

# Check for sensitive data in SharedPreferences
if [ -s "$OBJECTION_DIR/sharedprefs.txt" ]; then
  local sensitive_count=$(grep -ci "password\|token\|secret\|api_key\|auth\|credential" "$OBJECTION_DIR/sharedprefs.txt" 2>/dev/null || echo 0)
  if [ "$sensitive_count" -gt 0 ]; then
    warn "$sensitive_count potential secrets in SharedPreferences"
    fadd "Sensitive data in SharedPreferences" HIGH CERTAIN CWE-312 "A04:2021" "$OBJECTION_DIR/sharedprefs.txt"
  fi
fi

# ---- 5. Memory search for secrets ----
info "Searching memory for secrets..."
objection_run "$PKG" "memory dump all /tmp/mem_dump.bin" "$OBJECTION_DIR/memory_dump.txt" 45

if [ -f /tmp/mem_dump.bin ]; then
  strings /tmp/mem_dump.bin 2>/dev/null | grep -iE '(password|secret|key|token|api|auth)' > "$OBJECTION_DIR/memory_strings.txt"
  rm -f /tmp/mem_dump.bin
  
  if [ -s "$OBJECTION_DIR/memory_strings.txt" ]; then
    warn "Secrets found in memory"
    fadd "Secrets in memory (objection)" HIGH HIGH CWE-312 "A04:2021" "$OBJECTION_DIR/memory_strings.txt"
  fi
fi

# ---- 6. Activity enumeration ----
info "Enumerating activities..."
objection_run "$PKG" "android hooking list activities" "$OBJECTION_DIR/activities.txt" 30

# ---- 7. Service enumeration ----
info "Enumerating services..."
objection_run "$PKG" "android hooking list services" "$OBJECTION_DIR/services.txt" 30

# ---- 8. Content Provider enumeration ----
info "Enumerating content providers..."
objection_run "$PKG" "android hooking list classes" "$OBJECTION_DIR/classes.txt" 60

# Check for exported content providers
if [ -s "$OBJECTION_DIR/classes.txt" ]; then
  local provider_count=$(grep -c "ContentProvider\|content://" "$OBJECTION_DIR/classes.txt" 2>/dev/null || echo 0)
  if [ "$provider_count" -gt 0 ]; then
    info "$provider_count content providers found"
  fi
fi

# ---- 9. SSL Certificate extraction ----
info "Extracting SSL certificates..."
objection_run "$PKG" "android sslpinning disable" "$OBJECTION_DIR/ssl_cert_check.txt" 30

# ---- 10. Analyze and create comprehensive report ----
info "Analyzing objection results..."

# Generate summary report
cat > "$OBJECTION_DIR/summary.md" << EOF
# Objection Analysis Summary

## Package: $PKG

### SSL Pinning
- Status: $(if [ "$SSL_BYPASS" = "true" ]; then echo "Bypass attempted"; else echo "Skipped"; fi)
- Evidence: ssl_bypass.txt

### Root Detection
- Status: $(if [ "$ROOT_BYPASS" = "true" ]; then echo "Bypass attempted"; else echo "Skipped"; fi)
- Evidence: root_bypass.txt

### Keystore
- Entries found: $(wc -l < "$OBJECTION_DIR/keystore.txt" 2>/dev/null || echo 0)

### SharedPreferences
- Size: $(wc -l < "$OBJECTION_DIR/sharedprefs.txt" 2>/dev/null || echo 0) lines
- Sensitive entries: $(grep -ci "password\|token\|secret" "$OBJECTION_DIR/sharedprefs.txt" 2>/dev/null || echo 0)

### Memory
- Secrets found: $(wc -l < "$OBJECTION_DIR/memory_strings.txt" 2>/dev/null || echo 0)

### Components
- Activities: $(wc -l < "$OBJECTION_DIR/activities.txt" 2>/dev/null || echo 0)
- Services: $(wc -l < "$OBJECTION_DIR/services.txt" 2>/dev/null || echo 0)
- Classes: $(wc -l < "$OBJECTION_DIR/classes.txt" 2>/dev/null || echo 0)

## Findings
$(if [ -s "$OBJECTION_DIR/memory_strings.txt" ]; then echo "- HIGH: Secrets found in memory"; fi)
$(if [ -s "$OBJECTION_DIR/keystore.txt" ]; then echo "- MEDIUM: Keystore entries exposed"; fi)
$(if grep -qi "password\|token\|secret" "$OBJECTION_DIR/sharedprefs.txt" 2>/dev/null; then echo "- HIGH: Sensitive data in SharedPreferences"; fi)
EOF

ok "Objection testing complete -> $OBJECTION_DIR"
fsnapshot
