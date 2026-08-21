#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 07_storage_dump.sh - Extract SharedPreferences, SQLite, files, keychain
PROFILE_PHASE="07_storage_dump"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
[ -z "$PKG" ] && { err "No package_name in config"; exit 1; }

cd "$RUN_DIR" || exit 1
info "Storage dump for $PKG"

STORAGE_DIR="$RUN_DIR/storage"
mkdir -p "$STORAGE_DIR/shared_prefs" "$STORAGE_DIR/databases" "$STORAGE_DIR/files"

# ---- 1. Get app data path ----
APP_DATA="$(adb shell pm path "$PKG" 2>/dev/null | head -1 | sed 's/package://')"
DATA_DIR="$(adb shell run-as "$PKG" pwd 2>/dev/null || echo /data/data/$PKG)"
info "Data directory: $DATA_DIR"

# ---- 2. Dump SharedPreferences ----
info "Dumping SharedPreferences..."
adb shell "ls $DATA_DIR/shared_prefs/" 2>/dev/null | while read -r f; do
  adb shell "cat $DATA_DIR/shared_prefs/$f" > "$STORAGE_DIR/shared_prefs/$f" 2>/dev/null || true
done

SP_COUNT=$(ls "$STORAGE_DIR/shared_prefs/" 2>/dev/null | wc -l)
info "SharedPreferences files: $SP_COUNT"

# Check for sensitive data in SharedPreferences
for f in "$STORAGE_DIR/shared_prefs/"*.xml; do
  [ -f "$f" ] || continue
  if grep -qiE '(password|secret|token|key|auth|credential)' "$f" 2>/dev/null; then
    warn "Sensitive data in $(basename "$f")"
    fadd "Sensitive data in SharedPreferences" MEDIUM CERTAIN CWE-312 "A04:2021" "$f"
  fi
done

# ---- 3. Dump SQLite databases ----
info "Dumping SQLite databases..."
adb shell "ls $DATA_DIR/databases/" 2>/dev/null | while read -r f; do
  adb shell "run-as $PKG cat $DATA_DIR/databases/$f" > "$STORAGE_DIR/databases/$f" 2>/dev/null || \
  adb pull "$DATA_DIR/databases/$f" "$STORAGE_DIR/databases/$f" 2>/dev/null || true
done

DB_COUNT=$(ls "$STORAGE_DIR/databases/" 2>/dev/null | wc -l)
info "SQLite databases: $DB_COUNT"

# Check for SQLCipher (unencrypted databases)
for f in "$STORAGE_DIR/databases/"*; do
  [ -f "$f" ] || continue
  if file "$f" 2>/dev/null | grep -qi "sqlite"; then
    # Try to read database
    if command -v sqlite3 >/dev/null 2>&1; then
      TABLES="$(sqlite3 "$f" ".tables" 2>/dev/null || true)"
      if [ -n "$TABLES" ]; then
        warn "Unencrypted database: $(basename "$f")"
        sqlite3 "$f" ".dump" > "$STORAGE_DIR/databases/$(basename "$f").dump" 2>/dev/null || true
        fadd "Unencrypted SQLite database" LOW CERTAIN CWE-311 "A04:2021" "$f"
      fi
    fi
  fi
done

# ---- 4. Dump files directory ----
info "Dumping files directory..."
adb shell "ls -la $DATA_DIR/files/" 2>/dev/null | while read -r line; do
  FILE=$(echo "$line" | awk '{print $NF}')
  [ -n "$FILE" ] && [ "$FILE" != "." ] && [ "$FILE" != ".." ] && \
    adb shell "run-as $PKG cat $DATA_DIR/files/$FILE" > "$STORAGE_DIR/files/$FILE" 2>/dev/null || true
done

# ---- 5. Check for insecure file permissions ----
info "Checking file permissions..."
adb shell "ls -la $DATA_DIR/" 2>/dev/null > "$STORAGE_DIR/permissions.txt"

if grep -q "world-readable\|world-writable\|rwxrwx" "$STORAGE_DIR/permissions.txt" 2>/dev/null; then
  warn "Insecure file permissions detected"
  fadd "Insecure file permissions" MEDIUM CERTAIN CWE-276 "A01:2021" "$STORAGE_DIR/permissions.txt"
fi

# ---- 6. Check for local backups ----
info "Checking for local backups..."
adb shell "ls /sdcard/Android/data/$PKG/" 2>/dev/null > "$STORAGE_DIR/external_data.txt"
adb shell "ls /sdcard/Download/" 2>/dev/null > "$STORAGE_DIR/downloads.txt"

if [ -s "$STORAGE_DIR/external_data.txt" ]; then
  warn "External data found"
  fadd "App external data accessible" LOW CERTAIN CWE-200 "A01:2021" "$STORAGE_DIR/external_data.txt"
fi

ok "Storage dump complete -> $STORAGE_DIR"
fsnapshot
