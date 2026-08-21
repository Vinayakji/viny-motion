#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 04_dynamic_objection.sh - Frida-based runtime hooking via objection
PROFILE_PHASE="04_dynamic_objection"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

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
  objection -g "$PKG" explore --startup-command "android sslpinning disable" \
    > "$OBJECTION_DIR/ssl_bypass.txt" 2>&1 &
  OBJECTION_PID=$!
  sleep 10
  kill $OBJECTION_PID 2>/dev/null || true
  
  if grep -qi "success\|bypassed\|disabled" "$OBJECTION_DIR/ssl_bypass.txt" 2>/dev/null; then
    ok "SSL pinning bypass attempted"
  else
    warn "SSL pinning bypass may have failed"
  fi
fi

# ---- 2. Root Detection Bypass ----
if [ "$ROOT_BYPASS" = "true" ]; then
  info "Attempting root detection bypass..."
  objection -g "$PKG" explore --startup-command "android root disable" \
    > "$OBJECTION_DIR/root_bypass.txt" 2>&1 &
  OBJECTION_PID=$!
  sleep 10
  kill $OBJECTION_PID 2>/dev/null || true
  
  if grep -qi "success\|disabled\|bypassed" "$OBJECTION_DIR/root_bypass.txt" 2>/dev/null; then
    ok "Root detection bypass attempted"
  else
    warn "Root detection bypass may have failed"
  fi
fi

# ---- 3. Keychain/Keystore Dump ----
info "Dumping keystore..."
objection -g "$PKG" explore --startup-command "android keystore list" \
  > "$OBJECTION_DIR/keystore.txt" 2>&1 &
OBJECTION_PID=$!
sleep 10
kill $OBJECTION_PID 2>/dev/null || true

# ---- 4. SharedPreferences Dump ----
info "Dumping SharedPreferences..."
objection -g "$PKG" explore --startup-command "android sharedpref get" \
  > "$OBJECTION_DIR/sharedprefs.txt" 2>&1 &
OBJECTION_PID=$!
sleep 10
kill $OBJECTION_PID 2>/dev/null || true

# ---- 5. Memory search for secrets ----
info "Searching memory for secrets..."
objection -g "$PKG" explore --startup-command "memory dump all /tmp/mem_dump.bin" \
  > "$OBJECTION_DIR/memory_dump.txt" 2>&1 &
OBJECTION_PID=$!
sleep 15
kill $OBJECTION_PID 2>/dev/null || true

if [ -f /tmp/mem_dump.bin ]; then
  strings /tmp/mem_dump.bin 2>/dev/null | grep -iE '(password|secret|key|token|api|auth)' > "$OBJECTION_DIR/memory_strings.txt"
  rm -f /tmp/mem_dump.bin
fi

# ---- 6. Analyze results ----
info "Analyzing objection results..."

if [ -s "$OBJECTION_DIR/keystore.txt" ]; then
  warn "Keystore entries found"
  fadd "Keystore entries exposed (objection)" MEDIUM MEDIUM CWE-321 "A02:2021" "$OBJECTION_DIR/keystore.txt"
fi

if [ -s "$OBJECTION_DIR/memory_strings.txt" ]; then
  warn "Secrets found in memory"
  fadd "Secrets in memory (objection)" HIGH HIGH CWE-312 "A04:2021" "$OBJECTION_DIR/memory_strings.txt"
fi

ok "Objection testing complete -> $OBJECTION_DIR"
fsnapshot
