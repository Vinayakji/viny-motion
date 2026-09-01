#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 07_storage_dump.sh - Extract SharedPreferences, SQLite, files, keychain, external storage
PROFILE_PHASE="07_storage_dump"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
[ -z "$PKG" ] && { err "No package_name in config"; exit 1; }

cd "$RUN_DIR" || exit 1
info "Storage dump for $PKG"

STORAGE_DIR="$RUN_DIR/storage"
mkdir -p "$STORAGE_DIR/shared_prefs" "$STORAGE_DIR/databases" "$STORAGE_DIR/files"

# ---- 1. Resolve app data path ----
info "[step-1/7] Resolving application data directory"

info "  [path-1/2] Package path: adb shell pm path $PKG"
APP_DATA="$(adb shell pm path "$PKG" 2>/dev/null | head -1 | sed 's/package://')"
info "    APK path: $APP_DATA"

info "  [path-2/2] Data directory: adb shell run-as $PKG pwd"
DATA_DIR="$(adb shell run-as "$PKG" pwd 2>/dev/null || echo /data/data/$PKG)"
info "    Data dir: $DATA_DIR"

# ---- 2. Dump SharedPreferences ----
info "[step-2/7] Dumping SharedPreferences XML files"
info "  Listing: adb shell ls $DATA_DIR/shared_prefs/"

SP_FILE_COUNT=0
while IFS= read -r f; do
  [ -z "$f" ] && continue
  info "  Pulling: $f"
  adb shell "cat $DATA_DIR/shared_prefs/$f" > "$STORAGE_DIR/shared_prefs/$f" 2>/dev/null || true
  SP_FILE_COUNT=$((SP_FILE_COUNT + 1))
done < <(adb shell "ls $DATA_DIR/shared_prefs/" 2>/dev/null)

info "  SharedPreferences files pulled: $SP_FILE_COUNT"

# Check for sensitive data
info "  Scanning SharedPreferences for sensitive keywords: password|secret|token|key|auth|credential"
SP_SENSITIVE=0
for f in "$STORAGE_DIR/shared_prefs/"*.xml; do
  [ -f "$f" ] || continue
  MATCHES=$(grep -ciE '(password|secret|token|key|auth|credential)' "$f" 2>/dev/null || echo 0)
  if [ "$MATCHES" -gt 0 ]; then
    warn "  $(basename "$f"): $MATCHES sensitive keyword(s) found"
    SP_SENSITIVE=$((SP_SENSITIVE + MATCHES))
  fi
done

if [ "$SP_SENSITIVE" -gt 0 ]; then
  warn "  Total sensitive keywords across all SharedPreferences: $SP_SENSITIVE"
  fadd "Sensitive data in SharedPreferences" MEDIUM CERTAIN CWE-312 "A04:2021" "$STORAGE_DIR/shared_prefs/"
else
  info "  No sensitive keywords found in SharedPreferences files"
fi

# ---- 3. Dump SQLite databases ----
info "[step-3/7] Dumping SQLite databases"
info "  Listing: adb shell ls $DATA_DIR/databases/"

DB_FILE_COUNT=0
while IFS= read -r f; do
  [ -z "$f" ] && continue
  info "  Pulling database: $f"
  adb shell "run-as $PKG cat $DATA_DIR/databases/$f" > "$STORAGE_DIR/databases/$f" 2>/dev/null || \
  adb pull "$DATA_DIR/databases/$f" "$STORAGE_DIR/databases/$f" 2>/dev/null || true
  DB_FILE_COUNT=$((DB_FILE_COUNT + 1))
done < <(adb shell "ls $DATA_DIR/databases/" 2>/dev/null)

info "  Database files pulled: $DB_FILE_COUNT"

# Check for unencrypted databases
info "  Analyzing databases for encryption status (file magic bytes)"
DB_UNENCRYPTED=0
for f in "$STORAGE_DIR/databases/"*; do
  [ -f "$f" ] || continue
  DB_NAME=$(basename "$f")
  FILE_TYPE=$(file "$f" 2>/dev/null || echo "unknown")

  if echo "$FILE_TYPE" | grep -qi "sqlite"; then
    if command -v sqlite3 >/dev/null 2>&1; then
      TABLES=$(sqlite3 "$f" ".tables" 2>/dev/null || true)
      if [ -n "$TABLES" ]; then
        DB_UNENCRYPTED=$((DB_UNENCRYPTED + 1))
        TABLE_COUNT=$(echo "$TABLES" | wc -w)
        info "    $DB_NAME: UNENCRYPTED — $TABLE_COUNT tables: $TABLES"
        sqlite3 "$f" ".dump" > "$STORAGE_DIR/databases/${DB_NAME}.dump" 2>/dev/null || true
        fadd "Unencrypted SQLite database ($DB_NAME, $TABLE_COUNT tables)" LOW CERTAIN CWE-311 "A04:2021" "$f"
      else
        info "    $DB_NAME: SQLite format but no accessible tables (empty or encrypted)"
      fi
    else
      info "    $DB_NAME: sqlite3 not available; cannot verify encryption"
    fi
  else
    info "    $DB_NAME: not SQLite format ($(echo "$FILE_TYPE" | head -c 60))"
  fi
done

info "  Unencrypted databases found: $DB_UNENCRYPTED"

# ---- 4. Dump files directory ----
info "[step-4/7] Dumping app files directory"
info "  Listing: adb shell ls -la $DATA_DIR/files/"

FILE_COUNT=0
while IFS= read -r line; do
  FILE=$(echo "$line" | awk '{print $NF}')
  [ -z "$FILE" ] && continue
  [ "$FILE" = "." ] || [ "$FILE" = ".." ] && continue
  info "  Pulling file: $FILE"
  adb shell "run-as $PKG cat $DATA_DIR/files/$FILE" > "$STORAGE_DIR/files/$FILE" 2>/dev/null || true
  FILE_COUNT=$((FILE_COUNT + 1))
done < <(adb shell "ls -la $DATA_DIR/files/" 2>/dev/null)

info "  Files pulled: $FILE_COUNT"

# ---- 5. Check file permissions ----
info "[step-5/7] Checking application file and directory permissions"
info "  Listing: adb shell ls -la $DATA_DIR/"

adb shell "ls -la $DATA_DIR/" 2>/dev/null > "$STORAGE_DIR/permissions.txt"
PERM_LINES=$(wc -l < "$STORAGE_DIR/permissions.txt" 2>/dev/null || echo 0)
info "    Permission entries: $PERM_LINES"

INSECURE_PERMS=$(grep -c "world-readable\|world-writable\|rwxrwx" "$STORAGE_DIR/permissions.txt" 2>/dev/null || echo 0)
if [ "$INSECURE_PERMS" -gt 0 ]; then
  warn "  $INSECURE_PERMS insecure permission entries detected"
  fadd "Insecure file permissions ($INSECURE_PERMS entries)" MEDIUM CERTAIN CWE-276 "A01:2021" "$STORAGE_DIR/permissions.txt"
else
  info "  All file permissions appear standard (no world-rwx)"
fi

# ---- 6. Check external storage ----
info "[step-6/7] Checking external/sdcard storage"
info "  Listing: adb shell ls /sdcard/Android/data/$PKG/"

adb shell "ls /sdcard/Android/data/$PKG/" 2>/dev/null > "$STORAGE_DIR/external_data.txt" || true
EXTERNAL_LINES=$(wc -l < "$STORAGE_DIR/external_data.txt" 2>/dev/null || echo 0)
info "    External data entries: $EXTERNAL_LINES"

info "  Listing: adb shell ls /sdcard/Download/"
adb shell "ls /sdcard/Download/" 2>/dev/null > "$STORAGE_DIR/downloads.txt" || true
DOWNLOAD_LINES=$(wc -l < "$STORAGE_DIR/downloads.txt" 2>/dev/null || echo 0)
info "    Download directory entries: $DOWNLOAD_LINES"

if [ "$EXTERNAL_LINES" -gt 0 ]; then
  warn "  $EXTERNAL_LINES entries in external data directory"
  fadd "App external data accessible ($EXTERNAL_LINES entries)" LOW CERTAIN CWE-200 "A01:2021" "$STORAGE_DIR/external_data.txt"
else
  info "  External data directory is empty or inaccessible"
fi

# ---- 7. Summary ----
info "[step-7/7] Storage dump summary"
info "  SharedPreferences files: $SP_FILE_COUNT (sensitive keywords: $SP_SENSITIVE)"
info "  Database files: $DB_FILE_COUNT (unencrypted: $DB_UNENCRYPTED)"
info "  Files: $FILE_COUNT"
info "  Permission entries: $PERM_LINES (insecure: $INSECURE_PERMS)"
info "  External data entries: $EXTERNAL_LINES"

ok "Storage dump complete -> $STORAGE_DIR"
fsnapshot
