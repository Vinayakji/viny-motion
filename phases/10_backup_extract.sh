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
info "=== A. Backup Check ==="

# Check manifest for allowBackup
MANIFEST="$RUN_DIR/static/AndroidManifest.xml"
ALLOW_BACKUP="unknown"
if [ -f "$MANIFEST" ]; then
  if grep -q 'allowBackup="true"' "$MANIFEST" 2>/dev/null; then
    ALLOW_BACKUP="true"
    warn "allowBackup=true in manifest"
    fadd "ADB backup enabled (allowBackup=true)" MEDIUM CERTAIN CWE-200 "A04:2021" "$MANIFEST"
  elif grep -q 'allowBackup="false"' "$MANIFEST" 2>/dev/null; then
    ALLOW_BACKUP="false"
    ok "allowBackup=false"
  else
    ALLOW_BACKUP="default (true)"
    warn "allowBackup not specified (defaults to true)"
    fadd "ADB backup enabled (default)" LOW CERTAIN CWE-200 "A04:2021" "$MANIFEST"
  fi
fi

# Check via drozer
DROZER_BACKUP=$(echo "run app.package.backup $PKG" | drozer console connect 2>/dev/null || true)
if echo "$DROZER_BACKUP" | grep -qi "true"; then
  warn "Backup confirmed enabled via drozer"
fi

# ============================================================
# B. Attempt ADB Backup
# ============================================================
info "=== B. ADB Backup ==="

if [ "$ALLOW_BACKUP" != "false" ]; then
  info "Attempting ADB backup (may require device interaction)..."

  # Kill adb backup if running
  adb backup -f "$BACKUP_DIR/backup.ab" -noapk "$PKG" &
  BACKUP_PID=$!

  # Wait for device confirmation dialog (timeout 30s)
  sleep 5
  info "Check device screen for backup confirmation dialog"
  info "Tap 'BACK UP MY DATA' (do NOT enter password for easier extraction)"

  # Wait for backup to complete
  wait $BACKUP_PID 2>/dev/null || true

  if [ -f "$BACKUP_DIR/backup.ab" ]; then
    BACKUP_SIZE=$(stat -c%s "$BACKUP_DIR/backup.ab" 2>/dev/null || echo 0)
    ok "Backup created: $BACKUP_SIZE bytes"

    if [ "$BACKUP_SIZE" -gt 8 ]; then
      # ============================================================
      # C. Extract Backup
      # ============================================================
      info "=== C. Extracting Backup ==="

      # Method 1: android-backup-extractor
      if command -v abe >/dev/null 2>&1; then
        abe unpack "$BACKUP_DIR/backup.ab" "$BACKUP_DIR/backup.tar" 2>/dev/null
        if [ -f "$BACKUP_DIR/backup.tar" ]; then
          cd "$BACKUP_DIR" && tar xf backup.tar 2>/dev/null
          ok "Backup extracted via abe"
        fi
      # Method 2: Java-based extraction
      elif command -v java >/dev/null 2>&1 && [ -f "$HOME/tools/android-backup-extractor/abe.jar" ]; then
        java -jar "$HOME/tools/android-backup-extractor/abe.jar" unpack "$BACKUP_DIR/backup.ab" "$BACKUP_DIR/backup.tar" 2>/dev/null
        cd "$BACKUP_DIR" && tar xf backup.tar 2>/dev/null
        ok "Backup extracted via abe.jar"
      # Method 3: Python
      elif python3 -c "import backup" 2>/dev/null; then
        python3 -c "
import backup
with open('$BACKUP_DIR/backup.ab', 'rb') as f:
    data = backup.unpack(f)
    with open('$BACKUP_DIR/backup.tar', 'wb') as out:
        out.write(data)
" 2>/dev/null
        cd "$BACKUP_DIR" && tar xf backup.tar 2>/dev/null
        ok "Backup extracted via python"
      else
        warn "No backup extraction tool available (install android-backup-extractor)"
        info "Manual: java -jar abe.jar unpack backup.ab backup.tar"
      fi

      # ============================================================
      # D. Analyze Extracted Data
      # ============================================================
      info "=== D. Analyzing Backup ==="

      # Find interesting files
      find "$BACKUP_DIR" -type f \( \
        -name "*.db" -o -name "*.sqlite" -o -name "*.xml" -o -name "*.json" \
        -o -name "*.key" -o -name "*.pem" -o -name "*.p12" -o -name "*.jks" \
        -o -name "*.bks" -o -name "*.keystore" -o -name "shared_prefs*" \
        -o -name "*.conf" -o -name "*.cfg" -o -name "*.ini" \
      \) > "$BACKUP_DIR/interesting_files.txt" 2>/dev/null

      if [ -s "$BACKUP_DIR/interesting_files.txt" ]; then
        warn "Interesting files in backup:"
        cat "$BACKUP_DIR/interesting_files.txt"
        fadd "Sensitive files found in ADB backup" HIGH CERTAIN CWE-200 "A04:2021" "$BACKUP_DIR/interesting_files.txt"
      fi

      # Search for secrets in extracted files
      find "$BACKUP_DIR" -type f -exec grep -liE "(password|token|secret|api.?key|private.?key|BEGIN CERTIFICATE)" {} \; > "$BACKUP_DIR/secrets_in_backup.txt" 2>/dev/null || true

      if [ -s "$BACKUP_DIR/secrets_in_backup.txt" ]; then
        warn "Secrets found in backup!"
        fadd "Secrets found in ADB backup" CRITICAL CERTAIN CWE-200 "A04:2021" "$BACKUP_DIR/secrets_in_backup.txt"
      fi

      # Check for databases
      find "$BACKUP_DIR" -name "*.db" -o -name "*.sqlite" | while read db; do
        info "Database found: $db"
        # Dump tables
        sqlite3 "$db" ".tables" > "${db}.tables" 2>/dev/null || true
        sqlite3 "$db" ".dump" > "${db}.dump" 2>/dev/null || true

        # Search for sensitive data
        grep -liE "(password|token|secret|credit.?card|ssn|social.?security)" "${db}.dump" 2>/dev/null && \
          fadd "Sensitive data in database: $(basename "$db")" HIGH CERTAIN CWE-200 "A04:2021" "${db}.dump"
      done

      # Check for SharedPreferences
      find "$BACKUP_DIR" -path "*/shared_prefs/*" -name "*.xml" | while read sp; do
        info "SharedPreferences: $sp"
        grep -qiE "(password|token|secret|api.?key|auth)" "$sp" 2>/dev/null && \
          fadd "Sensitive data in SharedPreferences backup" HIGH CERTAIN CWE-200 "A04:2021" "$sp"
      done

    else
      warn "Backup file too small (empty backup)"
    fi
  else
    warn "Backup creation failed"
  fi
else
  info "Backup disabled, skipping"
fi

# ============================================================
# E. Check for Insecure Backup Methods
# ============================================================
info "=== E. Backup Security ==="

# Check if backup password is required
if [ -f "$BACKUP_DIR/backup.ab" ]; then
  # Check backup header
  HEADER=$(head -c 24 "$BACKUP_DIR/backup.ab" 2>/dev/null | xxd 2>/dev/null || true)
  if echo "$HEADER" | grep -q "414E44524549442031"; then
    info "Backup format: Android Backup (unencrypted)"
    fadd "Unencrypted ADB backup" LOW CERTAIN CWE-311 "A04:2021" "$BACKUP_DIR/backup.ab"
  fi
fi

ok "Backup extraction complete -> $BACKUP_DIR"
fsnapshot
