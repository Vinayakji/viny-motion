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
# drozer 3.x console requires a pty for batch input; wrap with `script`.
drozer_cmd() {
  local outfile="${1:-/dev/null}"
  shift
  printf '%s\n' "$@" "exit" | script -qec "timeout 90 drozer console connect" /dev/null 2>/dev/null > "$outfile"
}

# ---- 1. Start drozer agent embedded server + port forward ----
# drozer-agent 3.1.0 (com.withsecure.dz): foreground-allowlist via MainActivity,
# then start ServerService with START_EMBEDDED category (Android 11 background-start rule).
info "[step-1/10] Starting drozer agent server and establishing port forward"
info "  Launching agent MainActivity (foreground allowlist)..."
adb shell "am start -n com.withsecure.dz/com.WithSecure.dz.activities.MainActivity" 2>/dev/null || true
sleep 2
info "  Starting ServerService (START_EMBEDDED)..."
adb shell "am startservice -n com.withsecure.dz/com.WithSecure.dz.services.ServerService -c com.WithSecure.dz.START_EMBEDDED" 2>/dev/null || true
info "  Setting up ADB port forward: tcp:31415 -> tcp:31415"
adb forward tcp:31415 tcp:31415 2>/dev/null
info "  Waiting 4s for drozer server to initialize..."
sleep 4
if ! adb shell "ss -tln 2>/dev/null | grep -q 31415"; then
  err "  Drozer server NOT listening on 31415 — cannot continue"
  exit 1
fi
ok "  Drozer server ready on port 31415"

# ---- 2. List all modules ----
info "[step-2/10] Listing all available drozer modules"
drozer_cmd "$DROZER_DIR/all_modules.txt" "list"
MODULE_COUNT=$(wc -l < "$DROZER_DIR/all_modules.txt" 2>/dev/null || echo 0)
info "  Available modules: $MODULE_COUNT"

# ============================================================
# A. PACKAGE INFO (all flags)
# ============================================================
info "[step-3/10] === A. Package Enumeration ==="

info "  [A1] Gathering package info (app.package.info -a $PKG)"
drozer_cmd "$DROZER_DIR/A1_package_info.txt" \
  "run app.package.info -a $PKG"

info "  [A2] Getting APK installation path (app.package.path)"
drozer_cmd "$DROZER_DIR/A2_package_path.txt" \
  "run app.package.path -a $PKG"

info "  [A3] Getting application UID (app.package.uid)"
drozer_cmd "$DROZER_DIR/A3_package_uid.txt" \
  "run app.package.uid -a $PKG"

info "  [A4] Mapping attack surface (app.package.attacksurface)"
drozer_cmd "$DROZER_DIR/A4_attack_surface.txt" \
  "run app.package.attacksurface $PKG"

info "  [A5] Extracting full manifest (app.package.manifest)"
drozer_cmd "$DROZER_DIR/A5_manifest.txt" \
  "run app.package.manifest $PKG"

info "  [A6] Extracting signing certificate (app.package.certificate)"
drozer_cmd "$DROZER_DIR/A6_certificate.txt" \
  "run app.package.certificate $PKG"

info "  [A7] Checking debuggable flag (app.package.info)"
drozer_cmd "$DROZER_DIR/A7_debuggable.txt" \
  "run app.package.info -a $PKG"

info "  [A8] Checking backup flag (app.package.info)"
drozer_cmd "$DROZER_DIR/A8_backup.txt" \
  "run app.package.info -a $PKG"

ok "  Package enumeration complete (8 commands)"

# ============================================================
# B. ACTIVITIES (all flags)
# ============================================================
info "[step-4/10] === B. Activity Enumeration ==="

info "  [B1] Listing all activities (app.activity.info -a $PKG)"
drozer_cmd "$DROZER_DIR/B1_activities.txt" \
  "run app.activity.info -a $PKG"

info "  [B2] Finding sendable activities (app.activity.send)"
drozer_cmd "$DROZER_DIR/B2_activities_send.txt" \
  "run app.activity.send -a $PKG"

ok "  Activities complete (2 commands)"

# ============================================================
# C. SERVICES (all flags)
# ============================================================
info "[step-5/10] === C. Service Enumeration ==="

info "  [C1] Listing all services (app.service.info -a $PKG)"
drozer_cmd "$DROZER_DIR/C1_services.txt" \
  "run app.service.info -a $PKG"

ok "  Services complete (1 command)"

# ============================================================
# D. CONTENT PROVIDERS (all flags)
# ============================================================
info "[step-6/10] === D. Content Provider Enumeration & Testing ==="

info "  [D1] Listing content providers (app.provider.info -a $PKG)"
drozer_cmd "$DROZER_DIR/D1_providers.txt" \
  "run app.provider.info -a $PKG"

info "  [D2] Finding provider URIs (app.provider.find -a $PKG)"
drozer_cmd "$DROZER_DIR/D2_provider_find.txt" \
  "run app.provider.find -a $PKG"

info "  [D3] Querying root URI with vertical display"
drozer_cmd "$DROZER_DIR/D3_provider_root_query.txt" \
  "run app.provider.query content://$PKG/ --vertical"

info "  [D4] Querying with projection (_id column only)"
drozer_cmd "$DROZER_DIR/D4_provider_projection.txt" \
  "run app.provider.query content://$PKG/ --projection _id --vertical"

info "  [D5] Querying with WHERE clause (1=1)"
drozer_cmd "$DROZER_DIR/D5_provider_where.txt" \
  "run app.provider.query content://$PKG/ --where '_id=1' --vertical"

info "  [D6] Querying with SORT order (_id DESC)"
drozer_cmd "$DROZER_DIR/D6_provider_sort.txt" \
  "run app.provider.query content://$PKG/ --sort '_id DESC' --vertical"

info "  [D7] Attempting to read via provider URI"
drozer_cmd "$DROZER_DIR/D7_provider_read.txt" \
  "run app.provider.read --uri content://$PKG/"

info "  [D8] Attempting to insert via provider"
drozer_cmd "$DROZER_DIR/D8_provider_insert.txt" \
  "run app.provider.insert --uri content://$PKG/ --extra string key value"

info "  [D9] Attempting to update via provider"
drozer_cmd "$DROZER_DIR/D9_provider_update.txt" \
  "run app.provider.update --uri content://$PKG/ --where '_id=1' --extra string key newvalue"

info "  [D10] Attempting to delete via provider"
drozer_cmd "$DROZER_DIR/D10_provider_delete.txt" \
  "run app.provider.delete --uri content://$PKG/ --where '_id=1'"

ok "  Content providers complete (10 commands)"

# ============================================================
# E. BROADCAST RECEIVERS (all flags)
# ============================================================
info "[step-7/10] === E. Broadcast Receiver Enumeration & Testing ==="

info "  [E1] Listing broadcast receivers (app.broadcast.info -a $PKG)"
drozer_cmd "$DROZER_DIR/E1_receivers.txt" \
  "run app.broadcast.info -a $PKG"

info "  [E2] Sending BOOT_COMPLETED broadcast"
drozer_cmd "$DROZER_DIR/E2_broadcast_send_boot.txt" \
  "run app.broadcast.send --component $PKG --action android.intent.action.BOOT_COMPLETED"

info "  [E3] Sending custom action broadcast with extras"
drozer_cmd "$DROZER_DIR/E3_broadcast_send_custom.txt" \
  "run app.broadcast.send --component $PKG --action com.$PKG.CUSTOM_ACTION --extra string data test"

info "  [E4] Sending BATTERY_LOW broadcast"
drozer_cmd "$DROZER_DIR/E4_broadcast_send_battery.txt" \
  "run app.broadcast.send --action android.intent.action.BATTERY_LOW"

info "  [E5] Sending CONNECTIVITY_CHANGE broadcast"
drozer_cmd "$DROZER_DIR/E5_broadcast_send_connectivity.txt" \
  "run app.broadcast.send --action android.net.conn.CONNECTIVITY_CHANGE"

info "  [E6] Attempting to send to non-exported receiver (InternalReceiver)"
drozer_cmd "$DROZER_DIR/E6_broadcast_send_internal.txt" \
  "run app.broadcast.send --component $PKG/.InternalReceiver --action com.$PKG.INTERNAL"

ok "  Broadcast receivers complete (6 commands)"

# ============================================================
# F. INTENT INJECTION (all flags)
# ============================================================
info "[step-8/10] === F. Intent Injection Testing ==="

info "  [F1] Sending VIEW intent with file:// URI (shared_prefs)"
drozer_cmd "$DROZER_DIR/F1_intent_view_file.txt" \
  "run app.intent.send --action android.intent.action.VIEW --data-uri 'file:///data/data/$PKG/shared_prefs'"

info "  [F2] Sending VIEW intent with http:// URI (proxy redirect)"
drozer_cmd "$DROZER_DIR/F2_intent_view_http.txt" \
  "run app.intent.send --action android.intent.action.VIEW --data-uri 'http://127.0.0.1:8080' --flags 0x10000000"

info "  [F3] Sending SEND intent with text payload to ShareActivity"
drozer_cmd "$DROZER_DIR/F3_intent_send_data.txt" \
  "run app.intent.send --action android.intent.action.SEND --type 'text/plain' --extra string text 'injected data' --component $PKG/.ShareActivity"

info "  [F4] Sending VIEW intent with content:// URI (grant-read)"
drozer_cmd "$DROZER_DIR/F4_intent_view_content.txt" \
  "run app.intent.send --action android.intent.action.VIEW --data-uri 'content://$PKG/' --grant-read-uri-permission"

info "  [F5] Sending PICK intent for image/*"
drozer_cmd "$DROZER_DIR/F5_intent_pick.txt" \
  "run app.intent.send --action android.intent.action.PICK --type 'image/*'"

info "  [F6] Sending GET_CONTENT intent for */*"
drozer_cmd "$DROZER_DIR/F6_intent_get_content.txt" \
  "run app.intent.send --action android.intent.action.GET_CONTENT --type '*/*'"

info "  [F7] Attempting non-exported activity launch with grant permissions"
drozer_cmd "$DROZER_DIR/F7_intent_nonexported.txt" \
  "run app.intent.send --component $PKG/.ExportedActivity --action com.$PKG.ACTION --flags 0x10000000 --grant-read-uri-permission --grant-write-uri-permission"

ok "  Intent injection complete (7 commands)"

# ============================================================
# G. SHELL ACCESS (all flags)
# ============================================================
info "[step-9/10] === G. Shell Access Testing ==="

info "  [G1] Checking drozer shell UID (shell.exec id)"
drozer_cmd "$DROZER_DIR/G1_shell_id.txt" \
  "run shell.exec id"

info "  [G2] Executing /system/bin/id via shell.exec"
drozer_cmd "$DROZER_DIR/G2_shell_call_id.txt" \
  "run shell.exec id"

info "  [G3] Executing /system/bin/ps via shell.exec"
drozer_cmd "$DROZER_DIR/G3_shell_call_ps.txt" \
  "run shell.exec ps"

info "  [G4] Reading /etc/hosts via shell.exec"
drozer_cmd "$DROZER_DIR/G4_shell_call_cat.txt" \
  "run shell.exec cat /etc/hosts"

info "  [G5] Attempting interactive shell (shell.start)"
drozer_cmd "$DROZER_DIR/G5_shell_start.txt" \
  "run shell.start"

ok "  Shell access complete (5 commands)"

# ============================================================
# H. SCANNER MODULES (all flags)
# ============================================================
info "[step-10/10] === H. Scanner Modules ==="

info "  [H1] Running SQL injection scanner (scanner.provider.injection)"
drozer_cmd "$DROZER_DIR/H1_sqli.txt" \
  "run scanner.provider.injection -a $PKG"

if grep -qi "vulnerable\|injection" "$DROZER_DIR/H1_sqli.txt" 2>/dev/null; then
  warn "  SQL injection vulnerability DETECTED"
  fadd "SQL injection in content provider" HIGH HIGH CWE-89 "A03:2021" "$DROZER_DIR/H1_sqli.txt"
else
  info "  No SQL injection detected"
fi

info "  [H2] Running path traversal scanner (scanner.provider.traversal)"
drozer_cmd "$DROZER_DIR/H2_traversal.txt" \
  "run scanner.provider.traversal -a $PKG"

if grep -qi "traversal\|\.\.\/" "$DROZER_DIR/H2_traversal.txt" 2>/dev/null; then
  warn "  Path traversal DETECTED"
  fadd "Path traversal via content provider" HIGH HIGH CWE-22 "A01:2021" "$DROZER_DIR/H2_traversal.txt"
else
  info "  No path traversal detected"
fi

info "  [H3] Running file access scanner (scanner.provider.file)"
drozer_cmd "$DROZER_DIR/H3_file_access.txt" \
  "run scanner.provider.file -a $PKG"

if grep -qi "read\|write" "$DROZER_DIR/H3_file_access.txt" 2>/dev/null; then
  warn "  File access via provider DETECTED"
  fadd "Content provider file access" HIGH HIGH CWE-22 "A01:2021" "$DROZER_DIR/H3_file_access.txt"
else
  info "  No file access detected"
fi

info "  [H4] Running blob access scanner (scanner.provider.blob)"
drozer_cmd "$DROZER_DIR/H4_blob_access.txt" \
  "run scanner.provider.blob -a $PKG"

if grep -qi "blob\|large" "$DROZER_DIR/H4_blob_access.txt" 2>/dev/null; then
  warn "  Blob/large object access DETECTED"
  fadd "Content provider blob access" MEDIUM MEDIUM CWE-200 "A01:2021" "$DROZER_DIR/H4_blob_access.txt"
else
  info "  No blob access detected"
fi

ok "  Scanners complete (4 modules)"

# ============================================================
# I. EXPLOITATION ATTEMPTS (all flags)
# ============================================================
info "=== I. Exploitation Attempts ==="

info "  [I1] SQL injection probe: WHERE '1=1 OR 1=1'"
drozer_cmd "$DROZER_DIR/I1_inject_where.txt" \
  "run app.provider.query content://$PKG/ --where '1=1 OR 1=1' --vertical"

info "  [I2] Union-based injection probe: UNION SELECT 1,2,3--"
drozer_cmd "$DROZER_DIR/I2_inject_union.txt" \
  "run app.provider.query content://$PKG/ --where '1=1 UNION SELECT 1,2,3--' --vertical"

info "  [I3] Null injection probe: NULL IS NULL"
drozer_cmd "$DROZER_DIR/I3_inject_null.txt" \
  "run app.provider.query content://$PKG/ --where '1=1 AND NULL IS NULL' --vertical"

info "  [I4] Attempting to read sensitive files via provider (8 targets)"
READ_TARGETS=(
  "/data/data/$PKG/shared_prefs"
  "/data/data/$PKG/databases"
  "/data/data/$PKG/files"
  "/data/data/$PKG/cache"
  "/etc/hosts"
  "/proc/version"
  "/proc/self/environ"
  "/data/local/tmp"
)
for f in "${READ_TARGETS[@]}"; do
  SAFE_NAME=$(echo "$f" | tr '/' '_' | sed 's/^_//')
  info "    Reading: $f"
  drozer_cmd "$DROZER_DIR/I4_read_${SAFE_NAME}.txt" \
    "run app.provider.read --uri content://$PKG/$f" 2>/dev/null || true
done

info "  [I5] Attempting provider INSERT with test data"
drozer_cmd "$DROZER_DIR/I5_insert_test.txt" \
  "run app.provider.insert --uri content://$PKG/ --extra string test_key test_value"

info "  [I6] Attempting provider UPDATE with test data"
drozer_cmd "$DROZER_DIR/I6_update_test.txt" \
  "run app.provider.update --uri content://$PKG/ --where '1=1' --extra string test_key pwned"

info "  [I7] Sending BOOT_COMPLETED broadcast (abuse test)"
drozer_cmd "$DROZER_DIR/I7_delete_test.txt" \
  "run app.broadcast.send --component $PKG --action android.intent.action.BOOT_COMPLETED"

info "  [I8] Service abuse with credential extras (username=admin, password=password123)"
drozer_cmd "$DROZER_DIR/I8_service_abuse.txt" \
  "run app.service.send --component $PKG --extra string username admin --extra string password password123"

ok "  Exploitation attempts complete (8 probes)"

# ============================================================
# J. RESULTS ANALYSIS
# ============================================================
info "=== J. Results Analysis ==="

info "  [J1] Extracting attack surface summary"
ATTACK_SURFACE=$(cat "$DROZER_DIR/A4_attack_surface.txt" 2>/dev/null)

info "  [J2] Building results summary"
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
info "  Summary written to $DROZER_DIR/SUMMARY.txt"

info "  [J3] Creating findings from scanner results"
grep -qi "debuggable" "$DROZER_DIR/A7_debuggable.txt" 2>/dev/null && \
  fadd "App is debuggable" HIGH CERTAIN CWE-215 "A05:2021" "$DROZER_DIR/A7_debuggable.txt"

grep -qi "backup" "$DROZER_DIR/A8_backup.txt" 2>/dev/null && \
  fadd "Backup enabled" MEDIUM CERTAIN CWE-212 "A04:2021" "$DROZER_DIR/A8_backup.txt"

grep -qi "uid=0\|root" "$DROZER_DIR/G1_shell_id.txt" 2>/dev/null && \
  fadd "Root shell access achieved" CRITICAL CERTAIN CWE-269 "A01:2021" "$DROZER_DIR/G1_shell_id.txt"

# Clean up
info "  [J4] Cleaning up drozer port forward"
adb forward --remove tcp:31415 2>/dev/null || true
info "  Port forward removed"

ok "Drozer testing complete -> $DROZER_DIR"
fsnapshot
