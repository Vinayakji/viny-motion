#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 14_crypto_audit.sh - Cryptographic implementation audit
PROFILE_PHASE="14_crypto_audit"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
[ -z "$PKG" ] && { err "No package_name"; exit 1; }

cd "$RUN_DIR" || exit 1
CRYPTO_DIR="$RUN_DIR/crypto"
mkdir -p "$CRYPTO_DIR"

# ============================================================
# A. Static Analysis — Cryptographic Usage
# ============================================================
info "=== A. Static Crypto Analysis ==="

JADX_DIR="$RUN_DIR/static/jadx"
if [ -d "$JADX_DIR" ]; then

  # A1. Weak algorithms
  info "[step-A1/11] Scanning for weak cryptographic algorithms (DES, 3DES, RC4, RC2, Blowfish, MD5, SHA1)"
  grep -rn "DES\b\|3DES\b\|RC4\b\|RC2\b\|Blowfish\b\|MD5\b\|SHA1\b" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/weak_algos.txt" || true
  WEAK_COUNT=$(wc -l < "$CRYPTO_DIR/weak_algos.txt" 2>/dev/null || echo 0)
  info "  Weak algorithm matches: $WEAK_COUNT"
  [ "$WEAK_COUNT" -gt 0 ] && { warn "  $WEAK_COUNT weak cryptographic algorithm references found"; fadd "$WEAK_COUNT weak cryptographic algorithm references" HIGH HIGH CWE-327 "A02:2021" "$CRYPTO_DIR/weak_algos.txt"; }

  # A2. Hardcoded keys/secrets
  info "[step-A2/11] Scanning for hardcoded keys and secrets (SecretKeySpec, PBEKeySpec, long base64 strings)"
  grep -rn "\"[A-Za-z0-9+/=]\{16,\}\"\|SecretKeySpec\|PBEKeySpec\|generateSecret\|getInstance.*AES\|DESede\|Blowfish" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/hardcoded_keys.txt" || true
  KEY_COUNT=$(wc -l < "$CRYPTO_DIR/hardcoded_keys.txt" 2>/dev/null || echo 0)
  info "  Potential hardcoded keys: $KEY_COUNT"
  [ "$KEY_COUNT" -gt 0 ] && { warn "  $KEY_COUNT potential hardcoded cryptographic keys"; fadd "$KEY_COUNT potential hardcoded cryptographic keys" CRITICAL HIGH CWE-798 "A02:2021" "$CRYPTO_DIR/hardcoded_keys.txt"; }

  # A3. ECB mode usage
  info "[step-A3/11] Scanning for ECB mode cipher usage (insecure — reveals patterns in ciphertext)"
  grep -rn "AES/ECB\|DES/ECB\|ECB\|Cipher.getInstance.*ECB" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/ecb_mode.txt" || true
  ECB_COUNT=$(wc -l < "$CRYPTO_DIR/ecb_mode.txt" 2>/dev/null || echo 0)
  info "  ECB mode matches: $ECB_COUNT"
  [ "$ECB_COUNT" -gt 0 ] && { warn "  $ECB_COUNT ECB mode cipher usages — insecure (reveals plaintext patterns)"; fadd "$ECB_COUNT ECB mode cipher usages (insecure)" HIGH HIGH CWE-327 "A02:2021" "$CRYPTO_DIR/ecb_mode.txt"; }

  # A4. IV usage
  info "[step-A4/11] Scanning for IV (Initialization Vector) usage patterns"
  grep -rn "IvParameterSpec\|IV\b\|initialization.vector" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/iv_usage.txt" || true
  IV_COUNT=$(wc -l < "$CRYPTO_DIR/iv_usage.txt" 2>/dev/null || echo 0)
  info "  IV usage references: $IV_COUNT"

  # Check for hardcoded IVs
  info "  Checking for hardcoded/static IVs (0x00 arrays, literal strings)"
  grep -rn "IvParameterSpec.*\"\\|new byte\[\].*IvParameterSpec\|0x00.*IvParameterSpec\|{0,0,0,0" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/static_iv.txt" || true
  STATIC_IV=$(wc -l < "$CRYPTO_DIR/static_iv.txt" 2>/dev/null || echo 0)
  info "  Static/hardcoded IVs: $STATIC_IV"
  [ "$STATIC_IV" -gt 0 ] && { warn "  $STATIC_IV static/hardcoded IVs found — weakens encryption"; fadd "$STATIC_IV static/hardcoded IVs (insecure)" HIGH HIGH CWE-329 "A02:2021" "$CRYPTO_DIR/static_iv.txt"; }

  # A5. Insecure random
  info "[step-A5/11] Scanning for insecure random number generation (java.util.Random, Math.random)"
  grep -rn "java.util.Random\b\|Math.random\|new Random" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/insecure_random.txt" || true
  RAND_COUNT=$(wc -l < "$CRYPTO_DIR/insecure_random.txt" 2>/dev/null || echo 0)
  info "  Insecure random matches: $RAND_COUNT"
  [ "$RAND_COUNT" -gt 0 ] && { warn "  $RAND_COUNT uses of insecure random (java.util.Random)"; fadd "$RAND_COUNT uses of insecure random (java.util.Random)" MEDIUM HIGH CWE-330 "A02:2021" "$CRYPTO_DIR/insecure_random.txt"; }

  # A6. SecureRandom usage (good)
  info "[step-A6/11] Scanning for SecureRandom usage (cryptographically secure — positive indicator)"
  grep -rn "SecureRandom\|/dev/urandom" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/secure_random.txt" || true
  SRAND_COUNT=$(wc -l < "$CRYPTO_DIR/secure_random.txt" 2>/dev/null || echo 0)
  info "  SecureRandom usage: $SRAND_COUNT (good)"

  # A7. Base64 (not encryption)
  info "[step-A7/11] Scanning for Base64 usage (encoding, not encryption — may indicate weak security)"
  grep -rn "Base64.encode\|Base64.decode\|android.util.Base64" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/base64.txt" || true
  B64_COUNT=$(wc -l < "$CRYPTO_DIR/base64.txt" 2>/dev/null || echo 0)
  info "  Base64 references: $B64_COUNT (note: Base64 is not encryption)"

  # A8. TLS/SSL configuration
  info "[step-A8/11] Scanning for TLS/SSL configuration (TrustManager, SSLContext, HostnameVerifier, pinning)"
  grep -rn "CertificatePinner\|TrustManager\|X509TrustManager\|SSLContext\|HostnameVerifier\|checkServerTrusted\|checkClientTrusted" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/tls_config.txt" || true
  TLS_COUNT=$(wc -l < "$CRYPTO_DIR/tls_config.txt" 2>/dev/null || echo 0)
  info "  TLS/SSL configuration references: $TLS_COUNT"

  # Check for custom TrustManagers (potential bypass)
  info "  Checking for weak TrustManagers (checkServerTrusted with empty array — accepts all certs)"
  grep -rn "checkServerTrusted.*\\[\\]" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/weak_trust_manager.txt" || true
  WEAK_TM=$(wc -l < "$CRYPTO_DIR/weak_trust_manager.txt" 2>/dev/null || echo 0)
  info "  Weak TrustManagers: $WEAK_TM"
  [ "$WEAK_TM" -gt 0 ] && { warn "  $WEAK_TM weak TrustManager implementations (accept all certs)"; fadd "$WEAK_TM weak TrustManager implementations (accept all certs)" CRITICAL HIGH CWE-295 "A07:2021" "$CRYPTO_DIR/weak_trust_manager.txt"; }

  # A9. KeyStore usage
  info "[step-A9/11] Scanning for KeyStore usage (Android Keystore for secure key storage)"
  grep -rn "KeyStore\|KeyManager\|KeyPairGenerator\|KeyGenerator" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/keystore_usage.txt" || true
  KS_COUNT=$(wc -l < "$CRYPTO_DIR/keystore_usage.txt" 2>/dev/null || echo 0)
  info "  KeyStore references: $KS_COUNT"

  # A10. Key Derivation
  info "[step-A10/11] Scanning for key derivation functions (PBKDF2, scrypt, argon2, HKDF)"
  grep -rn "PBKDF2\|scrypt\|argon2\|Hkdf\|SecretKeyFactory" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/kdf.txt" || true
  KDF_COUNT=$(wc -l < "$CRYPTO_DIR/kdf.txt" 2>/dev/null || echo 0)
  info "  Key derivation references: $KDF_COUNT"

  # A11. Native crypto (JNI)
  info "[step-A11/11] Scanning for native crypto (JNI — loads .so libraries for encryption)"
  grep -rn "System.loadLibrary\|native.*encrypt\|native.*decrypt\|CryptoNative\|OpenSSL" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/native_crypto.txt" || true
  NATIVE_COUNT=$(wc -l < "$CRYPTO_DIR/native_crypto.txt" 2>/dev/null || echo 0)
  info "  Native crypto references: $NATIVE_COUNT"

  ok "  Static results: Weak=$WEAK_COUNT, Keys=$KEY_COUNT, ECB=$ECB_COUNT, IV=$IV_COUNT, StaticIV=$STATIC_IV, Rand=$RAND_COUNT, TLS=$TLS_COUNT, WeakTM=$WEAK_TM, KDF=$KDF_COUNT, Native=$NATIVE_COUNT"
else
  warn "  jadx directory not found; skipping static crypto analysis"
fi

# ============================================================
# B. Dynamic Analysis — Runtime Crypto
# ============================================================
info "=== B. Dynamic Crypto Analysis ==="

CRYPTO_SCRIPT="$PIPELINE_ROOT/extras/frida-scripts/crypto-monitor.js"
if [ -f "$CRYPTO_SCRIPT" ] && command -v frida >/dev/null 2>&1; then
  info "[step-B1/4] Starting Frida crypto monitoring script"
  info "  Script: $CRYPTO_SCRIPT"
  info "  Timeout: 30s"
  timeout 30 frida -U -f "$PKG" -l "$CRYPTO_SCRIPT" --no-pause 2>/dev/null > "$CRYPTO_DIR/crypto_hooks.log" &
  FRIDA_PID=$!
  info "  Frida PID: $FRIDA_PID"
  sleep 3

  info "  [launch/1] Launching app via monkey to trigger crypto operations"
  adb shell "monkey -p $PKG -c android.intent.category.LAUNCHER 1" 2>/dev/null || true
  info "  Waiting 15s for crypto operations to be logged..."
  sleep 15

  info "  [stop/2] Stopping Frida"
  kill $FRIDA_PID 2>/dev/null || true
  wait $FRIDA_PID 2>/dev/null || true

  HOOK_LINES=0
  if [ -s "$CRYPTO_DIR/crypto_hooks.log" ]; then
    HOOK_LINES=$(wc -l < "$CRYPTO_DIR/crypto_hooks.log" 2>/dev/null || echo 0)
    info "  Hook log: $HOOK_LINES entries"

    info "  [analyze-1/5] Counting algorithm usage from hook output"
    grep "algorithm" "$CRYPTO_DIR/crypto_hooks.log" 2>/dev/null | sort | uniq -c | sort -rn > "$CRYPTO_DIR/algo_usage.txt" 2>/dev/null || true
    ALGO_TYPES=$(wc -l < "$CRYPTO_DIR/algo_usage.txt" 2>/dev/null || echo 0)
    info "  Unique algorithm types: $ALGO_TYPES"

    info "  [analyze-2/5] Checking for ECB mode at runtime"
    grep "ECB" "$CRYPTO_DIR/crypto_hooks.log" > "$CRYPTO_DIR/ecb_detected.txt" 2>/dev/null || true
    RUNTIME_ECB=$(wc -l < "$CRYPTO_DIR/ecb_detected.txt" 2>/dev/null || echo 0)
    info "  ECB detected at runtime: $RUNTIME_ECB"
    [ "$RUNTIME_ECB" -gt 0 ] && { warn "  ECB mode confirmed at runtime"; fadd "ECB mode used at runtime" HIGH HIGH CWE-327 "A02:2021" "$CRYPTO_DIR/ecb_detected.txt"; }

    info "  [analyze-3/5] Checking for hardcoded keys at runtime"
    grep "hardcoded_key\|key=" "$CRYPTO_DIR/crypto_hooks.log" > "$CRYPTO_DIR/hardcoded_key_detected.txt" 2>/dev/null || true
    RUNTIME_KEY=$(wc -l < "$CRYPTO_DIR/hardcoded_key_detected.txt" 2>/dev/null || echo 0)
    info "  Hardcoded keys detected at runtime: $RUNTIME_KEY"
    [ "$RUNTIME_KEY" -gt 0 ] && { warn "  Hardcoded key confirmed at runtime"; fadd "Hardcoded key detected at runtime" CRITICAL HIGH CWE-798 "A02:2021" "$CRYPTO_DIR/hardcoded_key_detected.txt"; }

    info "  [analyze-4/5] Checking for IV reuse at runtime"
    grep "iv_reuse\|static_iv" "$CRYPTO_DIR/crypto_hooks.log" > "$CRYPTO_DIR/iv_reuse_detected.txt" 2>/dev/null || true
    RUNTIME_IV=$(wc -l < "$CRYPTO_DIR/iv_reuse_detected.txt" 2>/dev/null || echo 0)
    info "  IV reuse detected at runtime: $RUNTIME_IV"
    [ "$RUNTIME_IV" -gt 0 ] && { warn "  IV reuse confirmed at runtime"; fadd "IV reuse detected at runtime" HIGH HIGH CWE-329 "A02:2021" "$CRYPTO_DIR/iv_reuse_detected.txt"; }

    info "  [analyze-5/5] Scanning for sensitive data in crypto operations"
    grep "token\|password\|secret\|api_key" "$CRYPTO_DIR/crypto_hooks.log" | grep -iv "encrypt\|decrypt" > "$CRYPTO_DIR/sensitive_crypto.txt" 2>/dev/null || true
    SENS_CRYPTO=$(wc -l < "$CRYPTO_DIR/sensitive_crypto.txt" 2>/dev/null || echo 0)
    info "  Sensitive data in crypto ops: $SENS_CRYPTO"
    [ "$SENS_CRYPTO" -gt 0 ] && { warn "  $SENS_CRYPTO sensitive data entries in crypto operations"; fadd "Sensitive data in crypto operations" MEDIUM MEDIUM CWE-312 "A04:2021" "$CRYPTO_DIR/sensitive_crypto.txt"; }
  else
    warn "  Crypto hook log empty — no crypto operations captured"
  fi
else
  warn "  Frida crypto hook script not available; skipping dynamic crypto analysis"
fi

# ============================================================
# C. SSL/TLS Analysis
# ============================================================
info "=== C. SSL/TLS Analysis ==="

info "[step-C1/3] Checking for SSL pinning references"
SSL_PINNING=0
if [ -d "$JADX_DIR" ]; then
  SSL_PINNING=$(grep -rc "CertificatePinner\|ssl_pinning\|pinning" "$JADX_DIR/sources/" 2>/dev/null || echo 0)
fi
info "  SSL Pinning references: $SSL_PINNING"

info "[step-C2/3] Scanning for weak TLS versions (TLSv1.0, TLSv1.1, SSLv3, SSLv2)"
if [ -d "$JADX_DIR" ]; then
  grep -rn "TLSv1\b\|TLSv1\.1\|SSLv3\|SSLv2" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/weak_tls.txt" || true
else
  : > "$CRYPTO_DIR/weak_tls.txt"
fi
WEAK_TLS=$(wc -l < "$CRYPTO_DIR/weak_tls.txt" 2>/dev/null || echo 0)
info "  Weak TLS version references: $WEAK_TLS"
[ "$WEAK_TLS" -gt 0 ] && { warn "  $WEAK_TLS weak TLS version references"; fadd "$WEAK_TLS weak TLS version references" HIGH HIGH CWE-326 "A02:2021" "$CRYPTO_DIR/weak_tls.txt"; }

info "[step-C3/3] Analyzing network_security_config.xml for debug trust anchors"
NSC="$RUN_DIR/static/network_security_config.xml"
if [ -f "$NSC" ]; then
  info "  Network security config found: $NSC"
  if grep -q "debuggable.*true\|trust-anchors.*user" "$NSC" 2>/dev/null; then
    warn "  Debug trust anchors found in network security config"
    fadd "Debug trust anchors in network security config" MEDIUM MEDIUM CWE-295 "A07:2021" "$NSC"
  else
    info "  No debug trust anchors in NSC"
  fi
else
  info "  No network_security_config.xml found"
fi

ok "Crypto audit complete -> $CRYPTO_DIR"
ok "  Static: Weak=$WEAK_COUNT, Keys=$KEY_COUNT, ECB=$ECB_COUNT, TLS=$TLS_COUNT | Dynamic: Hooks=$HOOK_LINES | SSL Pinning=$SSL_PINNING"
fsnapshot
