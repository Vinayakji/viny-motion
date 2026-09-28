#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 16_code_analysis.sh - Deep decompiled code analysis (all modules, classes, methods)
PROFILE_PHASE="16_code_analysis"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
[ -z "$PKG" ] && { err "No package_name"; exit 1; }

cd "$RUN_DIR" || exit 1
CODE_DIR="$RUN_DIR/code_analysis"
mkdir -p "$CODE_DIR"

JADX_DIR="$RUN_DIR/jadx_output"
[ -d "$JADX_DIR" ] || JADX_DIR="$RUN_DIR/static/jadx"
[ -d "$JADX_DIR" ] || { err "jadx output not found — run 01_static first"; exit 1; }

# ============================================================
# A. Dangerous Function Calls
# ============================================================
info "=== A. Dangerous Function Calls ==="

info "[step-A1/4] Scanning for Runtime.exec / ProcessBuilder (OS command injection)"
grep -rn "Runtime\.exec\|ProcessBuilder\|\.exec(" "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/dangerous_exec.txt" || true
EXEC_COUNT=$(wc -l < "$CODE_DIR/dangerous_exec.txt" 2>/dev/null || echo 0)
info "  Runtime.exec/ProcessBuilder matches: $EXEC_COUNT"
[ "$EXEC_COUNT" -gt 0 ] && { warn "  $EXEC_COUNT dangerous exec/process calls found"; fadd "$EXEC_COUNT dangerous exec/process calls" HIGH MEDIUM CWE-78 "A03:2021" "$CODE_DIR/dangerous_exec.txt"; }

info "[step-A2/4] Scanning for System.loadLibrary / System.load (native code loading)"
grep -rn "System\.loadLibrary\|System\.load(" "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/native_loads.txt" || true
NATIVE_LOAD=$(wc -l < "$CODE_DIR/native_loads.txt" 2>/dev/null || echo 0)
info "  Native library loads: $NATIVE_LOAD"

info "[step-A3/4] Scanning for reflection usage (Method.invoke, getDeclaredMethod, Class.forName)"
grep -rn "Method\.invoke\|Method\.call\|getDeclaredMethod\|getDeclaredField\|\.class\.forName" "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/reflection.txt" || true
REFL_COUNT=$(wc -l < "$CODE_DIR/reflection.txt" 2>/dev/null || echo 0)
info "  Reflection invocations: $REFL_COUNT"
[ "$REFL_COUNT" -gt 5 ] && fadd "$REFL_COUNT reflection invocations (potential obfuscation)" LOW LOW CWE-95 "A03:2021" "$CODE_DIR/reflection.txt"

info "[step-A4/4] Scanning for deserialization entry points (ObjectInputStream, readObject, fromJson)"
grep -rn "ObjectInputStream\|readObject\|fromJson\|unserialize\|pickle" "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/deserialization.txt" || true
DESER_COUNT=$(wc -l < "$CODE_DIR/deserialization.txt" 2>/dev/null || echo 0)
info "  Deserialization entry points: $DESER_COUNT"
[ "$DESER_COUNT" -gt 0 ] && { warn "  $DESER_COUNT deserialization entry points"; fadd "$DESER_COUNT deserialization entry points" MEDIUM MEDIUM CWE-502 "A08:2021" "$CODE_DIR/deserialization.txt"; }

# ============================================================
# B. Network & HTTP Analysis
# ============================================================
info "=== B. Network & HTTP Analysis ==="

info "[step-B1/4] Scanning for cleartext HTTP URLs"
grep -rn '"http://' "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/cleartext_urls.txt" || true
HTTP_COUNT=$(wc -l < "$CODE_DIR/cleartext_urls.txt" 2>/dev/null || echo 0)
info "  Cleartext HTTP URLs: $HTTP_COUNT"
[ "$HTTP_COUNT" -gt 0 ] && { warn "  $HTTP_COUNT hardcoded HTTP URLs (cleartext)"; fadd "$HTTP_COUNT hardcoded HTTP URLs (cleartext)" MEDIUM CERTAIN CWE-319 "A02:2021" "$CODE_DIR/cleartext_urls.txt"; }

info "[step-B2/4] Scanning for network security config references"
grep -rn "networkSecurityConfig\|cleartextTrafficPermitted\|usesCleartextTraffic" "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/netsec_config.txt" || true
NETSEC_COUNT=$(wc -l < "$CODE_DIR/netsec_config.txt" 2>/dev/null || echo 0)
info "  Network security config refs: $NETSEC_COUNT"

info "[step-B3/4] Scanning for TLS/TrustManager references (potential bypass)"
grep -rn "TrustManager\|X509TrustManager\|SSLContext\|HostnameVerifier\|checkServerTrusted\|ALLOW_ALL\|SSLSocketFactory" "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/tls_bypass.txt" || true
TLS_COUNT=$(wc -l < "$CODE_DIR/tls_bypass.txt" 2>/dev/null || echo 0)
info "  TLS/TrustManager references: $TLS_COUNT"
[ "$TLS_COUNT" -gt 0 ] && fadd "$TLS_COUNT TLS/TrustManager references (check for bypass)" MEDIUM MEDIUM CWE-295 "A07:2021" "$CODE_DIR/tls_bypass.txt"

info "[step-B4/4] Scanning for WebView security configuration"
grep -rn "addJavascriptInterface\|setJavaScriptEnabled\|setAllowFileAccess\|setAllowContentAccess\|WebView" "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/webview_usage.txt" || true
WV_COUNT=$(wc -l < "$CODE_DIR/webview_usage.txt" 2>/dev/null || echo 0)
info "  WebView references: $WV_COUNT"
[ "$WV_COUNT" -gt 0 ] && fadd "$WV_COUNT WebView references (check for JS bridge)" MEDIUM MEDIUM CWE-610 "A03:2021" "$CODE_DIR/webview_usage.txt"

# ============================================================
# C. Secrets & Hardcoded Values
# ============================================================
info "=== C. Secrets & Hardcoded Values ==="

info "[step-C1/5] Scanning for Firebase API keys (AIza...)"
grep -rn "AIza[0-9A-Za-z_-]\{35\}" "$JADX_DIR/sources/" 2>/dev/null > "$CODE_DIR/firebase_keys.txt" || true
FIREBASE_KEYS=$(wc -l < "$CODE_DIR/firebase_keys.txt" 2>/dev/null || echo 0)
info "  Firebase API keys: $FIREBASE_KEYS"

info "[step-C2/5] Scanning for AWS keys (AKIA...)"
grep -rn "AKIA[0-9A-Z]\{16\}" "$JADX_DIR/sources/" 2>/dev/null > "$CODE_DIR/aws_keys.txt" || true
AWS_KEYS=$(wc -l < "$CODE_DIR/aws_keys.txt" 2>/dev/null || echo 0)
info "  AWS keys: $AWS_KEYS"

info "[step-C3/5] Scanning for Stripe keys (sk_live, sk_test, rk_live, rk_test)"
grep -rn "sk_live\|sk_test\|rk_live\|rk_test" "$JADX_DIR/sources/" 2>/dev/null > "$CODE_DIR/stripe_keys.txt" || true
STRIPE_KEYS=$(wc -l < "$CODE_DIR/stripe_keys.txt" 2>/dev/null || echo 0)
info "  Stripe keys: $STRIPE_KEYS"

info "[step-C4/5] Scanning for GitHub tokens (ghp_, github_pat_)"
grep -rn "ghp_\|github_pat_" "$JADX_DIR/sources/" 2>/dev/null > "$CODE_DIR/github_tokens.txt" || true
GITHUB_TOKENS=$(wc -l < "$CODE_DIR/github_tokens.txt" 2>/dev/null || echo 0)
info "  GitHub tokens: $GITHUB_TOKENS"

info "[step-C5/5] Scanning for hardcoded secret strings (password=, secret=, token=, api_key=)"
grep -rn "password\s*=\s*\"\|secret\s*=\s*\"\|token\s*=\s*\"\|api_key\s*=\s*\"" "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/hardcoded_strings.txt" || true
SECRET_COUNT=$(wc -l < "$CODE_DIR/hardcoded_strings.txt" 2>/dev/null || echo 0)
info "  Hardcoded secret strings: $SECRET_COUNT"
[ "$SECRET_COUNT" -gt 0 ] && { warn "  $SECRET_COUNT hardcoded secret strings found"; fadd "$SECRET_COUNT hardcoded secret strings" HIGH CERTAIN CWE-798 "A07:2021" "$CODE_DIR/hardcoded_strings.txt"; }

info "[step-C6/6] Scanning for hardcoded credential keywords (gitleaks-style, 100+ patterns)"
grep -rhoP -f "$PIPELINE_ROOT/config/secret-keyword-regex.txt" "$JADX_DIR/sources/" 2>/dev/null | sort -u > "$CODE_DIR/credential_keywords.txt"
CRED_COUNT=$(wc -l < "$CODE_DIR/credential_keywords.txt" 2>/dev/null || echo 0)
info "  Credential-keyword assignments: $CRED_COUNT"
[ "$CRED_COUNT" -gt 0 ] && { warn "  $CRED_COUNT hardcoded credential assignments"; fadd "$CRED_COUNT hardcoded credential assignments (gitleaks patterns)" HIGH PROBABLE CWE-798 "A07:2021" --component "source" --tags "secrets,sast" --remediation "Remove hardcoded secrets; use a secrets manager / env vars" "$CODE_DIR/credential_keywords.txt"; }

info "[step-C7/7] Scanning with master secrets scanner (38 patterns + primary regex)"
if [ -f "$PIPELINE_ROOT/secrets_scanner.py" ]; then
  python3 "$PIPELINE_ROOT/secrets_scanner.py" "$JADX_DIR/sources/" > "$CODE_DIR/secrets_scanner.txt" 2>&1
  MASTER_COUNT=$(grep -oE "\([0-9]+ findings\)" "$CODE_DIR/secrets_scanner.txt" | grep -oE "[0-9]+" | head -1 || echo 0)
  info "  Master scanner findings: ${MASTER_COUNT:-0}"
  [ "${MASTER_COUNT:-0}" -gt 0 ] && fadd "${MASTER_COUNT} secrets via master scanner (38 patterns)" HIGH PROBABLE CWE-798 "A07:2021" --component "source" --tags "secrets,sast" --remediation "Remove hardcoded secrets; use a secrets manager / env vars" "$CODE_DIR/secrets_scanner.txt"
else
  warn "  secrets_scanner.py not present — skipping master scan"
fi

# ============================================================
# D. Logging & Debug Analysis
# ============================================================
info "=== D. Logging & Debug Analysis ==="

info "[step-D1/4] Scanning for LogLevel.ALL / LogLevel.BODY / LogLevel.HEADERS (HTTP traffic logging)"
grep -rn "LogLevel\.ALL\|LogLevel\.BODY\|LogLevel\.HEADERS" "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/loglevel_all.txt" || true
LOGLEVEL_COUNT=$(wc -l < "$CODE_DIR/loglevel_all.txt" 2>/dev/null || echo 0)
info "  LogLevel.ALL/BODY/HEADERS usages: $LOGLEVEL_COUNT"
[ "$LOGLEVEL_COUNT" -gt 0 ] && { warn "  $LOGLEVEL_COUNT LogLevel.ALL/BODY/HEADERS usages — logs full HTTP traffic including auth headers"; fadd "$LOGLEVEL_COUNT LogLevel.ALL/BODY/HEADERS usages (logs HTTP traffic)" HIGH MEDIUM CWE-532 "A09:2021" "$CODE_DIR/loglevel_all.txt"; }

info "[step-D2/4] Counting total Log.* calls (Log.d, Log.v, Log.i, Log.w, Log.e)"
grep -rn "Log\.\(d\|v\|i\|w\|e\)\s*(" "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/all_logcalls.txt" || true
LOGCALL_COUNT=$(wc -l < "$CODE_DIR/all_logcalls.txt" 2>/dev/null || echo 0)
info "  Total Log.* calls: $LOGCALL_COUNT"

info "[step-D3/4] Scanning for sensitive data in log statements (token, password, secret, key, auth)"
grep -rn "Log\.\(d\|v\|i\).*\(token\|password\|secret\|key\|auth\|credential\)" "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/sensitive_logging.txt" || true
SENS_LOG=$(wc -l < "$CODE_DIR/sensitive_logging.txt" 2>/dev/null || echo 0)
info "  Sensitive data logging: $SENS_LOG"
[ "$SENS_LOG" -gt 0 ] && { warn "  $SENS_LOG Log.* calls with sensitive data keywords"; fadd "$SENS_LOG Log.* calls with sensitive data keywords" HIGH MEDIUM CWE-532 "A09:2021" "$CODE_DIR/sensitive_logging.txt"; }

info "[step-D4/4] Scanning for debug guard checks (isDebug, BuildConfig.DEBUG)"
grep -rn "isDebug\|BuildConfig\.DEBUG\|DEBUG\|isDebuggable" "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/debug_guards.txt" || true
DEBUG_GUARD=$(wc -l < "$CODE_DIR/debug_guards.txt" 2>/dev/null || echo 0)
info "  Debug guard checks: $DEBUG_GUARD"

# ============================================================
# E. Permissions & Access Control
# ============================================================
info "=== E. Permissions & Access Control ==="

info "[step-E1/3] Scanning for dangerous permission usage in code"
grep -rn "getDeviceId\|getImei\|getSubscriberId\|getLine1Number\|READ_PHONE_STATE\|READ_SMS\|CAMERA\|RECORD_AUDIO\|ACCESS_FINE_LOCATION\|ACCESS_COARSE_LOCATION" "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/permission_usage.txt" || true
PERM_COUNT=$(wc -l < "$CODE_DIR/permission_usage.txt" 2>/dev/null || echo 0)
info "  Dangerous permission refs: $PERM_COUNT"

info "[step-E2/3] Scanning for content provider access patterns"
grep -rn "ContentResolver\|content://\|getContentResolver" "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/content_providers.txt" || true
CP_COUNT=$(wc -l < "$CODE_DIR/content_providers.txt" 2>/dev/null || echo 0)
info "  Content provider access: $CP_COUNT"

info "[step-E3/3] Scanning for SharedPreferences usage (potential unencrypted storage)"
grep -rn "SharedPreferences\|getSharedPreferences\|PreferenceManager" "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/shared_prefs.txt" || true
SP_COUNT=$(wc -l < "$CODE_DIR/shared_prefs.txt" 2>/dev/null || echo 0)
info "  SharedPreferences refs: $SP_COUNT"

# ============================================================
# F. Secure Storage Analysis
# ============================================================
info "=== F. Secure Storage Analysis ==="

info "[step-F1/3] Scanning for EncryptedSharedPreferences (good practice)"
grep -rn "EncryptedSharedPreferences\|MasterKey\|AES256_GCM\|AES256_SIV" "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/encrypted_storage.txt" || true
ENC_STORAGE=$(wc -l < "$CODE_DIR/encrypted_storage.txt" 2>/dev/null || echo 0)
info "  EncryptedSharedPreferences refs: $ENC_STORAGE (good)"

info "[step-F2/3] Scanning for SQLite / Room / SQLDelight usage"
grep -rn "SQLiteDatabase\|rawQuery\|execSQL\|SQLiteOpenHelper\|Room\|SQLDelight" "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/sqlite_usage.txt" || true
SQL_COUNT=$(wc -l < "$CODE_DIR/sqlite_usage.txt" 2>/dev/null || echo 0)
info "  SQLite/DB refs: $SQL_COUNT"

info "[step-F3/3] Scanning for Android KeyStore usage"
grep -rn "KeyStore\|AndroidKeyStore\|keyStore\.get\|keyStore\.set" "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/keystore_usage.txt" || true
KS_COUNT=$(wc -l < "$CODE_DIR/keystore_usage.txt" 2>/dev/null || echo 0)
info "  KeyStore refs: $KS_COUNT"

# ============================================================
# G. Crypto Analysis (subset — code-level focus)
# ============================================================
info "=== G. Crypto Implementation ==="

info "[step-G1/2] Scanning for weak crypto algorithms in code (DES, 3DES, RC4, ECB, MD5, SHA1)"
grep -rn "DES\b\|3DES\b\|RC4\b\|ECB\|MD5\b\|SHA1\b" "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/weak_crypto.txt" || true
WEAK_CRYPTO=$(wc -l < "$CODE_DIR/weak_crypto.txt" 2>/dev/null || echo 0)
info "  Weak crypto references: $WEAK_CRYPTO"
[ "$WEAK_CRYPTO" -gt 0 ] && fadd "$WEAK_CRYPTO weak crypto algorithm references" MEDIUM MEDIUM CWE-327 "A02:2021" "$CODE_DIR/weak_crypto.txt"

info "[step-G2/2] Scanning for insecure random (java.util.Random, Math.random)"
grep -rn "java\.util\.Random\b\|Math\.random" "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/insecure_random.txt" || true
RAND_COUNT=$(wc -l < "$CODE_DIR/insecure_random.txt" 2>/dev/null || echo 0)
info "  Insecure random: $RAND_COUNT"
[ "$RAND_COUNT" -gt 0 ] && fadd "$RAND_COUNT uses of java.util.Random (insecure)" MEDIUM MEDIUM CWE-330 "A02:2021" "$CODE_DIR/insecure_random.txt"

# ============================================================
# H. Intent & IPC Analysis
# ============================================================
info "=== H. Intent & IPC Analysis ==="

info "[step-H1/2] Scanning for PendingIntent flags and usage"
grep -rn "FLAG_MUTABLE\|FLAG_IMMUTABLE\|PendingIntent\." "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/pending_intent.txt" || true
PI_COUNT=$(wc -l < "$CODE_DIR/pending_intent.txt" 2>/dev/null || echo 0)
info "  PendingIntent refs: $PI_COUNT"

info "[step-H2/2] Scanning for intent redirection patterns"
grep -rn "setClassName\|setComponent\|setPackage\|Intent.*getExtra\|getIntent\|intent\.getData" "$JADX_DIR/sources/" 2>/dev/null \
  > "$CODE_DIR/intent_redirect.txt" || true
IR_COUNT=$(wc -l < "$CODE_DIR/intent_redirect.txt" 2>/dev/null || echo 0)
info "  Intent redirect/flow: $IR_COUNT"

# ============================================================
# I. Code Quality Metrics
# ============================================================
info "=== I. Code Quality Metrics ==="

info "[step-I1/4] Counting Java source files"
JAVA_FILES=$(find "$JADX_DIR/sources/" -name "*.java" 2>/dev/null | wc -l)
info "  Java files: $JAVA_FILES"

info "[step-I2/4] Counting classes and interfaces"
CLASS_COUNT=$(grep -rl "class \|interface \|enum " "$JADX_DIR/sources/" 2>/dev/null | wc -l)
info "  Classes/interfaces: $CLASS_COUNT"

info "[step-I3/4] Counting method declarations"
METHOD_COUNT=$(grep -rn "public \|private \|protected \|static " "$JADX_DIR/sources/" 2>/dev/null | grep -c "()" || echo 0)
info "  Method declarations: $METHOD_COUNT"

info "[step-I4/4] Mapping top-level package structure"
info "  Package structure:"
find "$JADX_DIR/sources/" -mindepth 3 -maxdepth 5 -type d 2>/dev/null | \
  sed "s|$JADX_DIR/sources/||" | head -20 | while read p; do
  FC=$(find "$JADX_DIR/sources/$p" -maxdepth 1 -name "*.java" 2>/dev/null | wc -l)
  [ "$FC" -gt 0 ] && info "    $p ($FC files)"
done

# ============================================================
# Summary
# ============================================================
info "=== Code Analysis Summary ==="
info "  Files: $JAVA_FILES | Classes: $CLASS_COUNT | Methods: $METHOD_COUNT"
info "  Dangerous exec: $EXEC_COUNT | LogLevel.ALL: $LOGLEVEL_COUNT | Sensitive logging: $SENS_LOG"
info "  Cleartext URLs: $HTTP_COUNT | TLS/TrustManager: $TLS_COUNT | WebView: $WV_COUNT"
info "  Weak crypto: $WEAK_CRYPTO | Insecure random: $RAND_COUNT | Hardcoded secrets: $SECRET_COUNT"
info "  Firebase: $FIREBASE_KEYS | AWS: $AWS_KEYS | Stripe: $STRIPE_KEYS | GitHub: $GITHUB_TOKENS"

ok "Code analysis complete -> $CODE_DIR"
fsnapshot
