#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 10_backup_extract.sh - ADB backup extraction and analysis
PROFILE_PHASE="10_backup_extract"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
[ -z "$PKG" ] && { err "No package_name"; exit 1; }

cd "$RUN_DIR" || exit 1
BACKUP_DIR="$RUN_DIR/backup"
mkdir -p "$BACKUP_DIR"

# ============================================================
# A. Check if backup is allowed
# ============================================================
info "=== A. Backup Permission Check ==="

info "[step-A1/3] Checking AndroidManifest.xml for allowBackup attribute"
MANIFEST="$RUN_DIR/static/AndroidManifest.xml"
ALLOW_BACKUP="unknown"
if [ -f "$MANIFEST" ]; then
  info "  Manifest found: $MANIFEST"
  if grep -q 'allowBackup="true"' "$MANIFEST" 2>/dev/null; then
    ALLOW_BACKUP="true"
    warn "  allowBackup=true in manifest — app data extractable via adb backup"
    fadd "ADB backup enabled (allowBackup=true)" MEDIUM CERTAIN CWE-200 "A04:2021" "$MANIFEST"
  elif grep -q 'allowBackup="false"' "$MANIFEST" 2>/dev/null; then
    ALLOW_BACKUP="false"
    ok "  allowBackup=false — backup disabled"
  else
    ALLOW_BACKUP="default (true)"
    warn "  allowBackup attribute absent — defaults to true on older SDKs"
    fadd "ADB backup enabled (default)" LOW CERTAIN CWE-200 "A04:2021" "$MANIFEST"
  fi
else
  warn "  AndroidManifest.xml not found"
fi

info "[step-A2/3] Verifying backup capability via drozer"
DROZER_BACKUP=$(echo "run app.package.backup $PKG" | drozer console connect 2>/dev/null || true)
if echo "$DROZER_BACKUP" | grep -qi "true"; then
  warn "  Drozer confirms backup is enabled"
fi

info "[step-A3/3] Backup permission result: allowBackup=$ALLOW_BACKUP"

# ============================================================
# B. Attempt ADB Backup
# ============================================================
info "=== B. ADB Backup Attempt ==="

if [ "$ALLOW_BACKUP" != "false" ]; then
  info "[step-B1/3] Initiating ADB backup"
  info "  Command: adb backup -f $BACKUP_DIR/backup.ab -noapk $PKG"
  info "  NOTE: Device will show confirmation dialog; operator must tap 'BACK UP MY DATA'"

  adb backup -f "$BACKUP_DIR/backup.ab" -noapk "$PKG" &
  BACKUP_PID=$!
  info "  Backup process PID: $BACKUP_PID"
  info "  Waiting 5s for device confirmation dialog..."
  sleep 5
  info "  Check device screen for backup confirmation; tap 'BACK UP MY DATA' (no password)"

  info "[step-B2/3] Waiting for backup to complete"
  wait $BACKUP_PID 2>/dev/null || true

  if [ -f "$BACKUP_DIR/backup.ab" ]; then
    BACKUP_SIZE=$(stat -c%s "$BACKUP_DIR/backup.ab" 2>/dev/null || echo 0)
    info "  Backup file created: $BACKUP_SIZE bytes"

    if [ "$BACKUP_SIZE" -gt 8 ]; then
      ok "  Backup contains data ($BACKUP_SIZE bytes)"

      # ============================================================
      # C. Extract Backup
      # ============================================================
      info "=== C. Extracting Backup Contents ==="

      EXTRACTED=false
      info "  [method-1/3] Trying android-backup-extractor (abe)"
      if command -v abe >/dev/null 2>&1; then
        info "    Unpacking: abe unpack backup.ab backup.tar"
        abe unpack "$BACKUP_DIR/backup.ab" "$BACKUP_DIR/backup.tar" 2>/dev/null
        if [ -f "$BACKUP_DIR/backup.tar" ]; then
          info "    Extracting tar: tar xf backup.tar"
          cd "$BACKUP_DIR" && tar xf backup.tar 2>/dev/null
          EXTRACTED=true
          ok "  Backup extracted via abe"
        fi
      fi

      if ! $EXTRACTED; then
        info "  [method-2/3] Trying Java-based abe.jar"
        if command -v java >/dev/null 2>&1 && [ -f "$HOME/tools/android-backup-extractor/abe.jar" ]; then
          info "    Unpacking: java -jar abe.jar unpack backup.ab backup.tar"
          java -jar "$HOME/tools/android-backup-extractor/abe.jar" unpack "$BACKUP_DIR/backup.ab" "$BACKUP_DIR/backup.tar" 2>/dev/null
          cd "$BACKUP_DIR" && tar xf backup.tar 2>/dev/null
          EXTRACTED=true
          ok "  Backup extracted via abe.jar"
        fi
      fi

      if ! $EXTRACTED; then
        info "  [method-3/3] Trying python3 backup module"
        if python3 -c "import backup" 2>/dev/null; then
          python3 -c "
import backup
with open('$BACKUP_DIR/backup.ab', 'rb') as f:
    data = backup.unpack(f)
    with open('$BACKUP_DIR/backup.tar', 'wb') as out:
        out.write(data)
" 2>/dev/null
          cd "$BACKUP_DIR" && tar xf backup.tar 2>/dev/null
          EXTRACTED=true
          ok "  Backup extracted via python"
        fi
      fi

      if ! $EXTRACTED; then
        warn "  No backup extraction tool available (install android-backup-extractor)"
        info "  Manual: java -jar abe.jar unpack backup.ab backup.tar"
      fi

      # ============================================================
      # D. Analyze Extracted Data
      # ============================================================
      info "=== D. Analyzing Backup Contents ==="

      info "  [analyze-1/5] Searching for sensitive file types (db, xml, json, key, pem, p12, jks, bks, keystore, conf, ini)"
      find "$BACKUP_DIR" -type f \( \
        -name "*.db" -o -name "*.sqlite" -o -name "*.xml" -o -name "*.json" \
        -o -name "*.key" -o -name "*.pem" -o -name "*.p12" -o -name "*.jks" \
        -o -name "*.bks" -o -name "*.keystore" -o -name "shared_prefs*" \
        -o -name "*.conf" -o -name "*.cfg" -o -name "*.ini" \
      \) > "$BACKUP_DIR/interesting_files.txt" 2>/dev/null

      INTERESTING_COUNT=$(wc -l < "$BACKUP_DIR/interesting_files.txt" 2>/dev/null || echo 0)
      info "  Sensitive file matches: $INTERESTING_COUNT"
      if [ "$INTERESTING_COUNT" -gt 0 ]; then
        warn "  Interesting files found in backup:"
        head -10 "$BACKUP_DIR/interesting_files.txt" | while IFS= read -r f; do info "    $f"; done
        fadd "Sensitive files found in ADB backup ($INTERESTING_COUNT files)" HIGH CERTAIN CWE-200 "A04:2021" "$BACKUP_DIR/interesting_files.txt"
      fi

      info "  [analyze-2/5] Grep for secrets in all extracted files (password|token|secret|api_key|private_key|BEGIN CERTIFICATE)"
      find "$BACKUP_DIR" -type f -exec grep -liE "(password|token|secret|api.?key|private.?key|BEGIN CERTIFICATE)" {} \; > "$BACKUP_DIR/secrets_in_backup.txt" 2>/dev/null || true

      SECRETS_COUNT=$(wc -l < "$BACKUP_DIR/secrets_in_backup.txt" 2>/dev/null || echo 0)
      info "  Files containing secrets: $SECRETS_COUNT"
      if [ "$SECRETS_COUNT" -gt 0 ]; then
        warn "  SECRETS found in backup!"
        fadd "Secrets found in ADB backup ($SECRETS_COUNT files)" CRITICAL CERTAIN CWE-200 "A04:2021" "$BACKUP_DIR/secrets_in_backup.txt"
      fi

      info "  [analyze-3/5] Analyzing SQLite databases found in backup"
      DB_IN_BACKUP=$(find "$BACKUP_DIR" -name "*.db" -o -name "*.sqlite" 2>/dev/null | wc -l)
      info "  Databases found: $DB_IN_BACKUP"
      find "$BACKUP_DIR" -name "*.db" -o -name "*.sqlite" 2>/dev/null | while read db; do
        info "    Analyzing: $(basename "$db")"
        TABLES=$(sqlite3 "$db" ".tables" 2>/dev/null || true)
        if [ -n "$TABLES" ]; then
          info "      Tables: $TABLES"
          sqlite3 "$db" ".dump" > "${db}.dump" 2>/dev/null || true
          if grep -qiE "(password|token|secret|credit.?card|ssn|social.?security)" "${db}.dump" 2>/dev/null; then
            fadd "Sensitive data in database: $(basename "$db")" HIGH CERTAIN CWE-200 "A04:2021" "${db}.dump"
          fi
        fi
      done

      info "  [analyze-4/5] Scanning SharedPreferences for sensitive data"
      SP_IN_BACKUP=$(find "$BACKUP_DIR" -path "*/shared_prefs/*" -name "*.xml" 2>/dev/null | wc -l)
      info "  SharedPreferences files found: $SP_IN_BACKUP"
      find "$BACKUP_DIR" -path "*/shared_prefs/*" -name "*.xml" 2>/dev/null | while read sp; do
        if grep -qiE "(password|token|secret|api.?key|auth)" "$sp" 2>/dev/null; then
          warn "    $(basename "$sp"): contains sensitive keywords"
          fadd "Sensitive data in SharedPreferences backup" HIGH CERTAIN CWE-200 "A04:2021" "$sp"
        fi
      done

      info "  [analyze-5/5] Backup analysis complete"

    else
      warn "  Backup file too small ($BACKUP_SIZE bytes) — likely empty"
    fi
  else
    warn "  Backup file not created; backup may have been cancelled on device"
  fi
else
  info "  Backup disabled (allowBackup=false); skipping ADB backup"
fi

# ============================================================
# E. Check for Insecure Backup Methods
# ============================================================
info "=== E. Backup Encryption Check ==="

info "[step-E1/1] Checking backup header for encryption marker"
if [ -f "$BACKUP_DIR/backup.ab" ]; then
  HEADER=$(head -c 24 "$BACKUP_DIR/backup.ab" 2>/dev/null | xxd 2>/dev/null || true)
  if echo "$HEADER" | grep -q "414E44524549442031"; then
    info "  Format: ANDROID BACKUP (header magic: ANDROID 1)"
    info "  Encryption: NONE — backup is unencrypted"
    fadd "Unencrypted ADB backup" LOW CERTAIN CWE-311 "A04:2021" "$BACKUP_DIR/backup.ab"
  else
    info "  Header does not match expected Android backup format"
  fi
else
  info "  No backup.ab file to check"
fi

ok "Backup extraction complete -> $BACKUP_DIR"
ok "  Backup: ${BACKUP_SIZE:-0} bytes | Extracted: ${EXTRACTED:-false} | Databases: ${DB_IN_BACKUP:-0} | Secrets: ${SECRETS_COUNT:-0}"
fsnapshot
