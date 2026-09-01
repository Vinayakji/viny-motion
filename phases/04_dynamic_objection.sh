#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 04_dynamic_objection.sh - Frida-based runtime hooking via objection
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
info "objection version: $(objection version 2>/dev/null | head -1 || echo 'unknown')"

# ---- 1. SSL Pinning Bypass ----
info "[step-1/10] SSL Pinning Bypass"
if [ "$SSL_BYPASS" = "true" ]; then
  info "  ssl_bypass=true; running: objection_run_and_verify android sslpinning disable"
  info "  Timeout: 45s | Expected pattern: success|bypassed|disabled"
  if objection_run_and_verify "$PKG" "android sslpinning disable" \
    "$OBJECTION_DIR/ssl_bypass.txt" "success\|bypassed\|disabled" 45; then
    ok "  SSL pinning bypass SUCCEEDED"
    fadd "SSL pinning bypass (objection)" MEDIUM CERTAIN CWE-295 "A02:2021" "$OBJECTION_DIR/ssl_bypass.txt"
  else
    warn "  SSL pinning bypass failed; will try alternative methods in later phases"
  fi
else
  info "  ssl_bypass=false; skipping"
fi

# ---- 2. Root Detection Bypass ----
info "[step-2/10] Root Detection Bypass"
if [ "$ROOT_BYPASS" = "true" ]; then
  info "  root_bypass=true; running: objection_run_and_verify android root disable"
  info "  Timeout: 45s | Expected pattern: success|disabled|bypassed"
  if objection_run_and_verify "$PKG" "android root disable" \
    "$OBJECTION_DIR/root_bypass.txt" "success\|disabled\|bypassed" 45; then
    ok "  Root detection bypass SUCCEEDED"
    fadd "Root detection bypass (objection)" MEDIUM CERTAIN CWE-284 "A01:2021" "$OBJECTION_DIR/root_bypass.txt"
  else
    warn "  Root detection bypass failed"
  fi
else
  info "  root_bypass=false; skipping"
fi

# ---- 3. Keychain/Keystore Dump ----
info "[step-3/10] Android Keystore Dump"
info "  Running: objection_run android keystore list"
info "  Timeout: 30s"
objection_run "$PKG" "android keystore list" "$OBJECTION_DIR/keystore.txt" 30

if [ -s "$OBJECTION_DIR/keystore.txt" ]; then
  KEYSTORE_ENTRIES=$(wc -l < "$OBJECTION_DIR/keystore.txt" 2>/dev/null || echo 0)
  warn "  Keystore entries found: $KEYSTORE_ENTRIES"
  dump_objection_structured "$OBJECTION_DIR/keystore.txt" \
    "Keystore entries exposed (objection)" MEDIUM CWE-321 "A02:2021"
else
  info "  No keystore entries found or keystore empty"
fi

# ---- 4. SharedPreferences Dump ----
info "[step-4/10] SharedPreferences Dump"
info "  Running: objection_run android sharedpref get"
info "  Timeout: 30s"
objection_run "$PKG" "android sharedpref get" "$OBJECTION_DIR/sharedprefs.txt" 30

if [ -s "$OBJECTION_DIR/sharedprefs.txt" ]; then
  SP_LINES=$(wc -l < "$OBJECTION_DIR/sharedprefs.txt" 2>/dev/null || echo 0)
  info "  SharedPreferences output: $SP_LINES lines"
  # Check for sensitive data in SharedPreferences
  local sensitive_count=$(grep -ci "password\|token\|secret\|api_key\|auth\|credential" "$OBJECTION_DIR/sharedprefs.txt" 2>/dev/null || echo 0)
  if [ "$sensitive_count" -gt 0 ]; then
    warn "  $sensitive_count potential secrets found in SharedPreferences"
    fadd "Sensitive data in SharedPreferences" HIGH CERTAIN CWE-312 "A04:2021" "$OBJECTION_DIR/sharedprefs.txt"
  else
    info "  No sensitive keywords detected in SharedPreferences"
  fi
else
  info "  SharedPreferences dump empty or unavailable"
fi

# ---- 5. Memory search for secrets ----
info "[step-5/10] Memory Dump & Secret Search"
info "  Running: objection_run memory dump all /tmp/mem_dump.bin"
info "  Timeout: 45s"
objection_run "$PKG" "memory dump all /tmp/mem_dump.bin" "$OBJECTION_DIR/memory_dump.txt" 45

if [ -f /tmp/mem_dump.bin ]; then
  MEM_SIZE="$(du -h /tmp/mem_dump.bin 2>/dev/null | cut -f1)"
  info "  Memory dump size: $MEM_SIZE"
  info "  Extracting strings matching: password|secret|key|token|api|auth"
  strings /tmp/mem_dump.bin 2>/dev/null | grep -iE '(password|secret|key|token|api|auth)' > "$OBJECTION_DIR/memory_strings.txt"
  rm -f /tmp/mem_dump.bin
  
  MEM_STRINGS=$(wc -l < "$OBJECTION_DIR/memory_strings.txt" 2>/dev/null || echo 0)
  if [ "$MEM_STRINGS" -gt 0 ]; then
    warn "  $MEM_STRINGS potential secrets found in memory"
    fadd "Secrets in memory (objection)" HIGH HIGH CWE-312 "A04:2021" "$OBJECTION_DIR/memory_strings.txt"
  else
    info "  No sensitive strings found in memory dump"
  fi
else
  info "  Memory dump file not created; dump may have failed"
fi

# ---- 6. Activity enumeration ----
info "[step-6/10] Activity Enumeration"
info "  Running: objection_run android hooking list activities"
info "  Timeout: 30s"
objection_run "$PKG" "android hooking list activities" "$OBJECTION_DIR/activities.txt" 30

if [ -s "$OBJECTION_DIR/activities.txt" ]; then
  ACT_COUNT=$(wc -l < "$OBJECTION_DIR/activities.txt" 2>/dev/null || echo 0)
  info "  Activities discovered: $ACT_COUNT"
else
  info "  No activities found"
fi

# ---- 7. Service enumeration ----
info "[step-7/10] Service Enumeration"
info "  Running: objection_run android hooking list services"
info "  Timeout: 30s"
objection_run "$PKG" "android hooking list services" "$OBJECTION_DIR/services.txt" 30

if [ -s "$OBJECTION_DIR/services.txt" ]; then
  SVC_COUNT=$(wc -l < "$OBJECTION_DIR/services.txt" 2>/dev/null || echo 0)
  info "  Services discovered: $SVC_COUNT"
else
  info "  No services found"
fi

# ---- 8. Content Provider / class enumeration ----
info "[step-8/10] Class Enumeration (for ContentProvider discovery)"
info "  Running: objection_run android hooking list classes"
info "  Timeout: 60s (large apps may take longer)"
objection_run "$PKG" "android hooking list classes" "$OBJECTION_DIR/classes.txt" 60

if [ -s "$OBJECTION_DIR/classes.txt" ]; then
  CLASS_COUNT=$(wc -l < "$OBJECTION_DIR/classes.txt" 2>/dev/null || echo 0)
  info "  Classes discovered: $CLASS_COUNT"
  # Check for exported content providers
  local provider_count=$(grep -c "ContentProvider\|content://" "$OBJECTION_DIR/classes.txt" 2>/dev/null || echo 0)
  if [ "$provider_count" -gt 0 ]; then
    info "  ContentProvider-related classes found: $provider_count"
  fi
else
  info "  Class listing empty or timed out"
fi

# ---- 9. SSL Certificate extraction ----
info "[step-9/10] SSL Certificate Extraction"
info "  Running: objection_run android sslpinning disable (certificate check)"
info "  Timeout: 30s"
objection_run "$PKG" "android sslpinning disable" "$OBJECTION_DIR/ssl_cert_check.txt" 30

if [ -s "$OBJECTION_DIR/ssl_cert_check.txt" ]; then
  SSL_LINES=$(wc -l < "$OBJECTION_DIR/ssl_cert_check.txt" 2>/dev/null || echo 0)
  info "  SSL certificate check output: $SSL_LINES lines"
fi

# ---- 10. Analyze and create comprehensive report ----
info "[step-10/10] Generating Objection Analysis Report"

info "  Building summary.md..."
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
info "  Report written to $OBJECTION_DIR/summary.md"

ok "Objection testing complete -> $OBJECTION_DIR"
fsnapshot
