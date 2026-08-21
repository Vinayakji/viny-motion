#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 03_dynamic_drozer.sh - Drozer enumeration + exploitation modules
PROFILE_PHASE="03_dynamic_drozer"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
[ -z "$PKG" ] && { err "No package_name in config"; exit 1; }

cd "$RUN_DIR" || exit 1
info "Drozer testing on $PKG"

DROZER_DIR="$RUN_DIR/drozer"
mkdir -p "$DROZER_DIR"

# Check drozer
command -v drozer >/dev/null 2>&1 || { warn "drozer not installed (pip install drozer)"; exit 0; }

# ---- 1. Connect to drozer ----
info "Connecting to drozer..."
drozer console connect --command "list" > "$DROZER_DIR/modules.txt" 2>/dev/null || true

# ---- 2. Enumeration modules ----
info "Running enumeration modules..."

# App enumerate
drozer console connect --command "run app.package.info -a $PKG" > "$DROZER_DIR/package_info.txt" 2>/dev/null || true

# Manifest
drozer console connect --command "run app.package.manifest $PKG" > "$DROZER_DIR/manifest.txt" 2>/dev/null || true

# Activities
drozer console connect --command "run app.activity.info -a $PKG" > "$DROZER_DIR/activities.txt" 2>/dev/null || true

# Services
drozer console connect --command "run app.service.info -a $PKG" > "$DROZER_DIR/services.txt" 2>/dev/null || true

# Content Providers
drozer console connect --command "run app.provider.info -a $PKG" > "$DROZER_DIR/providers.txt" 2>/dev/null || true

# Broadcast Receivers
drozer console connect --command "run app.broadcast.info -a $PKG" > "$DROZER_DIR/receivers.txt" 2>/dev/null || true

# ---- 3. Exploitation modules ----
info "Running exploitation modules..."

# Content provider testing
drozer console connect --command "run app.provider.query content://$PKG" > "$DROZER_DIR/provider_query.txt" 2>/dev/null || true

# SQL injection test
drozer console connect --command "run app.provider.inject content://$PKG --selection \"1=1\"" > "$DROZER_DIR/provider_inject.txt" 2>/dev/null || true

# Path traversal test
drozer console connect --command "run scanner.provider.traversal -a $PKG" > "$DROZER_DIR/path_traversal.txt" 2>/dev/null || true

# ---- 4. Analyze results ----
info "Analyzing drozer results..."

# Check for exported components
if grep -q "exported=true" "$DROZER_DIR/activities.txt" 2>/dev/null; then
  warn "Exported activities found"
  fadd "Exported activities (drozer)" MEDIUM CERTAIN CWE-284 "A01:2021" "$DROZER_DIR/activities.txt"
fi

if grep -q "exported=true" "$DROZER_DIR/services.txt" 2>/dev/null; then
  warn "Exported services found"
  fadd "Exported services (drozer)" MEDIUM CERTAIN CWE-284 "A01:2021" "$DROZER_DIR/services.txt"
fi

# Check for SQL injection
if grep -qi "sql\|error\|exception" "$DROZER_DIR/provider_inject.txt" 2>/dev/null; then
  warn "Potential SQL injection in content provider"
  fadd "SQL injection in content provider (drozer)" HIGH HIGH CWE-89 "A03:2021" "$DROZER_DIR/provider_inject.txt"
fi

ok "Drozer testing complete -> $DROZER_DIR"
fsnapshot
