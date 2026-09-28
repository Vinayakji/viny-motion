#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 01_static.sh - Static analysis: jadx decompile, manifest, secrets, native libs
PROFILE_PHASE="01_static"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

APK="$RUN_DIR/app.apk"
[ -f "$APK" ] || { err "No APK found at $APK (run 00_acquire first)"; exit 1; }

JADX_DIR="$RUN_DIR/jadx_output"
STATIC_DIR="$RUN_DIR/static"
mkdir -p "$JADX_DIR" "$STATIC_DIR"

cd "$RUN_DIR" || exit 1
APK_SIZE="$(du -h "$APK" | cut -f1)"
info "Static analysis on $(basename "$APK") ($APK_SIZE)"

# ---- 1. AAPT metadata ----
info "[step-1/6] AAPT metadata extraction"
if command -v aapt >/dev/null 2>&1; then
  info "  Running: aapt dump badging $APK > $STATIC_DIR/aapt_badging.txt"
  aapt dump badging "$APK" > "$STATIC_DIR/aapt_badging.txt" 2>/dev/null
  info "  Running: aapt dump permissions $APK > $STATIC_DIR/aapt_permissions.txt"
  aapt dump permissions "$APK" > "$STATIC_DIR/aapt_permissions.txt" 2>/dev/null
  # Extract key metadata
  APP_NAME="$(grep -m1 'application-label:' "$STATIC_DIR/aapt_badging.txt" 2>/dev/null | cut -d: -f2)"
  APP_VERSION="$(grep -m1 'versionName=' "$STATIC_DIR/aapt_badging.txt" 2>/dev/null | sed 's/.*versionName=//' | tr -d "'")"
  APP_VERSIONCODE="$(grep -m1 'versionCode=' "$STATIC_DIR/aapt_badging.txt" 2>/dev/null | sed 's/.*versionCode=//' | tr -d "'")"
  info "  App name: $APP_NAME"
  info "  Version: $APP_VERSION (code: $APP_VERSIONCODE)"
  PERM_COUNT=$(grep -c 'uses-permission' "$STATIC_DIR/aapt_permissions.txt" 2>/dev/null || echo 0)
  info "  Permissions declared: $PERM_COUNT"
  ok "  AAPT metadata extracted"
else
  warn "  aapt not found in PATH; skipping AAPT extraction"
fi

# ---- 2. jadx decompile ----
info "[step-2/6] jadx decompilation"
if command -v jadx >/dev/null 2>&1; then
  JADX_PATH="$(which jadx)"
  info "  jadx path: $JADX_PATH"
  info "  Running: jadx -d $JADX_DIR $APK (this may take 1-3 minutes for large APKs)"
  jadx -d "$JADX_DIR" "$APK" 2>/dev/null
  JAVA_FILES=$(find "$JADX_DIR" -name "*.java" 2>/dev/null | wc -l)
  SMALI_FILES=$(find "$JADX_DIR" -name "*.smali" 2>/dev/null | wc -l)
  DECOMP_SIZE="$(du -sh "$JADX_DIR" 2>/dev/null | cut -f1)"
  info "  Decompilation output: $DECOMP_SIZE"
  info "  Java files: $JAVA_FILES, Smali files: $SMALI_FILES"
  ok "  jadx decompilation complete"
else
  warn "  jadx not found; skipping decompilation (install: sudo apt install jadx)"
fi

# ---- 3. AndroidManifest analysis ----
info "[step-3/6] AndroidManifest.xml analysis"
MANIFEST=$(find "$JADX_DIR" -name "AndroidManifest.xml" 2>/dev/null | head -1)
if [ -n "$MANIFEST" ]; then
  MANIFEST_LINES=$(wc -l < "$MANIFEST")
  info "  Found manifest: $MANIFEST ($MANIFEST_LINES lines)"
  cp "$MANIFEST" "$STATIC_DIR/AndroidManifest.xml"
  
  # Check for exported components
  EXPORTED=$(grep -c 'exported="true"' "$MANIFEST" 2>/dev/null || echo 0)
  if [ "$EXPORTED" -gt 0 ]; then
    warn "  $EXPORTED exported components found"
    grep 'exported="true"' "$MANIFEST" > "$STATIC_DIR/exported_components.txt" 2>/dev/null
  else
    info "  No explicitly exported components"
  fi
  
  # Check for debuggable — flag controls which phases run
  if grep -q 'android:debuggable="true"' "$MANIFEST" 2>/dev/null; then
    warn "  App is DEBUGGABLE (android:debuggable=true)"
    echo "1" > "$RUN_DIR/.debuggable"
    info "  Flag set: .debuggable=1 (will skip Frida/objection/bypass phases)"
    fadd "App is debuggable (android:debuggable=true)" HIGH CERTAIN CWE-215 "A05:2021"
  else
    info "  android:debuggable not set or false"
    echo "0" > "$RUN_DIR/.debuggable"
    info "  Flag set: .debuggable=0 (Frida/objection/bypass phases enabled)"
  fi
  
  # Check for backup
  if grep -q 'android:allowBackup="true"' "$MANIFEST" 2>/dev/null; then
    warn "  Backup is enabled (android:allowBackup=true)"
    fadd "Backup enabled (android:allowBackup=true)" MEDIUM CERTAIN CWE-212 "A04:2021"
  else
    info "  android:allowBackup not enabled"
  fi
  
  # Check for cleartext traffic
  if grep -q 'android:usesCleartextTraffic="true"' "$MANIFEST" 2>/dev/null; then
    warn "  Cleartext traffic allowed"
    fadd "Cleartext traffic allowed" MEDIUM CERTAIN CWE-319 "A02:2021"
  else
    info "  No cleartext traffic flag"
  fi
  
  ok "  Manifest analysis complete"
else
  warn "  AndroidManifest.xml not found in jadx output"
fi

# ---- 4. Secrets extraction ----
info "[step-4/6] Hardcoded secrets extraction"
SECRETS="$STATIC_DIR/secrets.txt"
: > "$SECRETS"

info "  Scanning for Firebase API keys (pattern: AIza[0-9A-Za-z_-]{35})"
grep -rhoE 'AIza[0-9A-Za-z_-]{35}' "$JADX_DIR" 2>/dev/null | sort -u > "$STATIC_DIR/firebase_keys.txt"
FB_COUNT=$(wc -l < "$STATIC_DIR/firebase_keys.txt" 2>/dev/null || echo 0)
info "  Firebase keys found: $FB_COUNT"

info "  Scanning for AWS access keys (pattern: AKIA[0-9A-Z]{16})"
grep -rhoE 'AKIA[0-9A-Z]{16}' "$JADX_DIR" 2>/dev/null | sort -u > "$STATIC_DIR/aws_keys.txt"
AWS_COUNT=$(wc -l < "$STATIC_DIR/aws_keys.txt" 2>/dev/null || echo 0)
info "  AWS keys found: $AWS_COUNT"

info "  Scanning for generic long strings (potential secrets, 32+ chars)"
grep -rhoE '[a-zA-Z0-9]{32,}' "$JADX_DIR" 2>/dev/null | head -100 >> "$SECRETS"
GENERIC_COUNT=$(wc -l < "$SECRETS" 2>/dev/null || echo 0)
info "  Generic potential secrets: $GENERIC_COUNT"

info "  Scanning for hardcoded credential keywords (gitleaks-style, 100+ patterns)"
grep -rhoP -f "$PIPELINE_ROOT/config/secret-keyword-regex.txt" "$JADX_DIR" 2>/dev/null | sort -u > "$STATIC_DIR/credential_keywords.txt"
KEYWORD_COUNT=$(wc -l < "$STATIC_DIR/credential_keywords.txt" 2>/dev/null || echo 0)
info "  Credential-keyword assignments found: $KEYWORD_COUNT"
[ "$KEYWORD_COUNT" -gt 0 ] && { warn "  $KEYWORD_COUNT hardcoded credential assignments"; fadd "$KEYWORD_COUNT hardcoded credential assignments (gitleaks patterns)" HIGH PROBABLE CWE-798 "A07:2021" --component "source" --tags "secrets,sast" --remediation "Remove hardcoded secrets; use a secrets manager / env vars" "$STATIC_DIR/credential_keywords.txt"; } || ok "  No credential-keyword assignments"

info "  Scanning with master secrets scanner (38 patterns + primary regex)"
if [ -f "$PIPELINE_ROOT/secrets_scanner.py" ]; then
  python3 "$PIPELINE_ROOT/secrets_scanner.py" "$JADX_DIR" > "$STATIC_DIR/secrets_scanner.txt" 2>&1
  MASTER_COUNT=$(grep -oE "\([0-9]+ findings\)" "$STATIC_DIR/secrets_scanner.txt" | grep -oE "[0-9]+" | head -1 || echo 0)
  info "  Master scanner findings: ${MASTER_COUNT:-0}"
  [ "${MASTER_COUNT:-0}" -gt 0 ] && fadd "${MASTER_COUNT} secrets via master scanner (38 patterns)" HIGH PROBABLE CWE-798 "A07:2021" --component "source" --tags "secrets,sast" --remediation "Remove hardcoded secrets; use a secrets manager / env vars" "$STATIC_DIR/secrets_scanner.txt"
else
  warn "  secrets_scanner.py not present — skipping master scan"
fi

info "  Scanning for hardcoded URLs"
grep -rhoE 'https?://[a-zA-Z0-9./_-]+' "$JADX_DIR" 2>/dev/null | sort -u > "$STATIC_DIR/urls.txt"
URL_COUNT=$(wc -l < "$STATIC_DIR/urls.txt" 2>/dev/null || echo 0)
info "  Unique URLs found: $URL_COUNT"

info "  Scanning for hardcoded hostnames"
grep -rhoE '[a-z0-9.-]+\.[a-z]{2,}' "$JADX_DIR" 2>/dev/null | sort -u > "$STATIC_DIR/hosts.txt"
HOST_COUNT=$(wc -l < "$STATIC_DIR/hosts.txt" 2>/dev/null || echo 0)
info "  Unique hostnames found: $HOST_COUNT"

if [ -s "$STATIC_DIR/firebase_keys.txt" ]; then
  warn "  Firebase keys found: $FB_COUNT"
  fadd "Hardcoded Firebase API key" HIGH CERTAIN CWE-798 "A07:2021" "$STATIC_DIR/firebase_keys.txt"
fi

if [ -s "$STATIC_DIR/aws_keys.txt" ]; then
  warn "  AWS keys found: $AWS_COUNT"
  fadd "Hardcoded AWS access key" CRITICAL CERTAIN CWE-798 "A07:2021" "$STATIC_DIR/aws_keys.txt"
fi

ok "  Secrets extraction complete"

# ---- 5. Native library analysis ----
info "[step-5/6] Native library analysis"
NATIVE_DIR="$STATIC_DIR/native_libs"
mkdir -p "$NATIVE_DIR"
find "$JADX_DIR" -name "*.so" -exec cp {} "$NATIVE_DIR/" \; 2>/dev/null
NATIVE_COUNT=$(ls "$NATIVE_DIR"/*.so 2>/dev/null | wc -l)
info "  Native .so libraries found: $NATIVE_COUNT"

if [ "$NATIVE_COUNT" -gt 0 ]; then
  for lib in "$NATIVE_DIR"/*.so; do
    LIB_NAME="$(basename "$lib")"
    LIB_SIZE="$(du -h "$lib" | cut -f1)"
    info "  Analyzing $LIB_NAME ($LIB_SIZE) for sensitive strings..."
    strings "$lib" 2>/dev/null | grep -iE '(password|secret|key|token|api)' >> "$STATIC_DIR/native_strings.txt" 2>/dev/null
  done
  NATIVE_STRINGS=$(wc -l < "$STATIC_DIR/native_strings.txt" 2>/dev/null || echo 0)
  info "  Sensitive strings in native libs: $NATIVE_STRINGS"
fi

ok "  Native library analysis complete"

# ---- 6. Deep code analysis (preliminary) ----
info "[step-6/6] Deep code analysis on decompiled Java source"
CODE_DIR="$RUN_DIR/code_analysis"
mkdir -p "$CODE_DIR"

if [ -d "$JADX_DIR" ]; then
  JAVA_COUNT=$(find "$JADX_DIR" -name "*.java" 2>/dev/null | wc -l)
  info "  Total Java files to analyze: $JAVA_COUNT"
  
  # Dangerous function patterns
  info "  [cat-1/10] Scanning for dangerous runtime functions (exec, ProcessBuilder, System.exit)"
  grep -rhoEiE '(Runtime\.getRuntime\(\)\.exec|ProcessBuilder|System\.exit|Thread\.sleep|Thread\.stop)' "$JADX_DIR" 2>/dev/null | sort -u > "$CODE_DIR/dangerous_functions.txt"
  DANG_COUNT=$(wc -l < "$CODE_DIR/dangerous_functions.txt" 2>/dev/null || echo 0)
  info "    Matches: $DANG_COUNT"
  
  # HTTP/network code
  info "  [cat-2/10] Scanning for HTTP clients (OkHttp, Retrofit, Volley, HttpURLConnection)"
  grep -rhoEiE '(HttpURLConnection|OkHttpClient|Retrofit|Volley|HttpClient|URLConnection)' "$JADX_DIR" 2>/dev/null | sort -u > "$CODE_DIR/http_clients.txt"
  HTTP_COUNT=$(wc -l < "$CODE_DIR/http_clients.txt" 2>/dev/null || echo 0)
  info "    Matches: $HTTP_COUNT"
  
  # Hardcoded secrets
  info "  [cat-3/10] Scanning for hardcoded secrets (password/secret/apikey/token = \"...\")"
  grep -rhoEiE '(password|secret|apikey|api_key|token|private_key)\s*=\s*"[^"]{8,}"' "$JADX_DIR" 2>/dev/null | sort -u > "$CODE_DIR/hardcoded_secrets.txt"
  SECRET_COUNT=$(wc -l < "$CODE_DIR/hardcoded_secrets.txt" 2>/dev/null || echo 0)
  info "    Matches: $SECRET_COUNT"
  
  # Debug/logging
  info "  [cat-4/10] Scanning for debug/logging statements (Log.d, println, System.out)"
  grep -rhoEiE '(Log\.(d|v|i|w|e)|println|System\.out|System\.err)' "$JADX_DIR" 2>/dev/null | sort | uniq -c | sort -rn > "$CODE_DIR/debug_logging.txt"
  LOG_LINES=$(wc -l < "$CODE_DIR/debug_logging.txt" 2>/dev/null || echo 0)
  info "    Distinct logging patterns: $LOG_LINES"
  
  # Cleartext URLs
  info "  [cat-5/10] Scanning for cleartext HTTP URLs"
  grep -rhoE 'http://[^"'"'"' ]*' "$JADX_DIR" 2>/dev/null | sort -u > "$CODE_DIR/cleartext_urls.txt"
  CLEARTEXT_COUNT=$(wc -l < "$CODE_DIR/cleartext_urls.txt" 2>/dev/null || echo 0)
  info "    Cleartext URLs found: $CLEARTEXT_COUNT"
  
  # Dangerous permissions
  info "  [cat-6/10] Scanning for dangerous permission usage (SEND_SMS, CALL_PHONE, etc)"
  grep -rhoEiE '(SEND_SMS|CALL_PHONE|WRITE_EXTERNAL|READ_CONTACTS|CAMERA|RECORD_AUDIO)' "$JADX_DIR" 2>/dev/null | sort -u > "$CODE_DIR/dangerous_permissions.txt"
  PERM_USED=$(wc -l < "$CODE_DIR/dangerous_permissions.txt" 2>/dev/null || echo 0)
  info "    Matches: $PERM_USED"
  
  # Crypto
  info "  [cat-7/10] Scanning for crypto patterns (DES, MD5, SHA1, ECB, getInstance)"
  grep -rhoEiE '(DES|MD5|SHA1|ECB|NoPadding|getInstance)' "$JADX_DIR" 2>/dev/null | sort -u > "$CODE_DIR/crypto_patterns.txt"
  CRYPTO_COUNT=$(wc -l < "$CODE_DIR/crypto_patterns.txt" 2>/dev/null || echo 0)
  info "    Matches: $CRYPTO_COUNT"
  
  # WebView
  info "  [cat-8/10] Scanning for WebView patterns (JS enabled, addJavascriptInterface, loadUrl)"
  grep -rhoEiE '(setJavaScriptEnabled|addJavascriptInterface|loadUrl|evaluateJavascript)' "$JADX_DIR" 2>/dev/null | sort -u > "$CODE_DIR/webview_patterns.txt"
  WV_COUNT=$(wc -l < "$CODE_DIR/webview_patterns.txt" 2>/dev/null || echo 0)
  info "    Matches: $WV_COUNT"
  
  # Intent/IPC
  info "  [cat-9/10] Scanning for Intent/IPC patterns (startActivity, sendBroadcast, PendingIntent)"
  grep -rhoEiE '(startActivity|sendBroadcast|startService|bindService|PendingIntent)' "$JADX_DIR" 2>/dev/null | sort | uniq -c | sort -rn > "$CODE_DIR/intent_ipc.txt"
  IPC_LINES=$(wc -l < "$CODE_DIR/intent_ipc.txt" 2>/dev/null || echo 0)
  info "    Distinct IPC patterns: $IPC_LINES"
  
  # SQL patterns
  info "  [cat-10/10] Scanning for SQL patterns (rawQuery, execSQL, query, insert, update, delete)"
  grep -rhoEiE '(rawQuery|execSQL|query\(|insert\(|delete\(|update\()' "$JADX_DIR" 2>/dev/null | sort -u > "$CODE_DIR/sql_patterns.txt"
  SQL_COUNT=$(wc -l < "$CODE_DIR/sql_patterns.txt" 2>/dev/null || echo 0)
  info "    Matches: $SQL_COUNT"
  
  # Count total findings across categories
  CODE_TOTAL=0
  for f in "$CODE_DIR"/*.txt; do
    cnt=$(wc -l < "$f" 2>/dev/null || echo 0)
    CODE_TOTAL=$((CODE_TOTAL + cnt))
  done
  ok "  Deep code analysis complete: $CODE_TOTAL patterns across 10 categories"
  
  # Flag high-risk items
  [ -s "$CODE_DIR/hardcoded_secrets.txt" ] && fadd "Hardcoded secrets in source: $SECRET_COUNT matches" HIGH CERTAIN CWE-798 "A07:2021"
  [ -s "$CODE_DIR/dangerous_functions.txt" ] && fadd "Dangerous runtime functions: $DANG_COUNT matches" MEDIUM CONFIRMED CWE-0 "A05:2021"
fi

ok "Static + code analysis complete -> $STATIC_DIR, $CODE_DIR"
fsnapshot
