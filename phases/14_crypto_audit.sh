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
  grep -rn "DES\b\|3DES\b\|RC4\b\|RC2\b\|Blowfish\b\|MD5\b\|SHA1\b" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/weak_algos.txt" || true
  WEAK_COUNT=$(wc -l < "$CRYPTO_DIR/weak_algos.txt" 2>/dev/null || echo 0)
  info "Weak algorithm usage: $WEAK_COUNT"
  [ "$WEAK_COUNT" -gt 0 ] && fadd "$WEAK_COUNT weak cryptographic algorithm references" HIGH HIGH CWE-327 "A02:2021" "$CRYPTO_DIR/weak_algos.txt"

  # A2. Hardcoded keys/secrets
  grep -rn "\"[A-Za-z0-9+/=]\{16,\}\"\|SecretKeySpec\|PBEKeySpec\|generateSecret\|getInstance.*AES\|DESede\|Blowfish" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/hardcoded_keys.txt" || true
  KEY_COUNT=$(wc -l < "$CRYPTO_DIR/hardcoded_keys.txt" 2>/dev/null || echo 0)
  info "Potential hardcoded keys: $KEY_COUNT"
  [ "$KEY_COUNT" -gt 0 ] && fadd "$KEY_COUNT potential hardcoded cryptographic keys" CRITICAL HIGH CWE-798 "A02:2021" "$CRYPTO_DIR/hardcoded_keys.txt"

  # A3. ECB mode usage
  grep -rn "AES/ECB\|DES/ECB\|ECB\|Cipher.getInstance.*ECB" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/ecb_mode.txt" || true
  ECB_COUNT=$(wc -l < "$CRYPTO_DIR/ecb_mode.txt" 2>/dev/null || echo 0)
  [ "$ECB_COUNT" -gt 0 ] && fadd "$ECB_COUNT ECB mode cipher usages (insecure)" HIGH HIGH CWE-327 "A02:2021" "$CRYPTO_DIR/ecb_mode.txt"

  # A4. IV reuse / static IV
  grep -rn "IvParameterSpec\|IV\b\|initialization.vector" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/iv_usage.txt" || true
  IV_COUNT=$(wc -l < "$CRYPTO_DIR/iv_usage.txt" 2>/dev/null || echo 0)
  info "IV usage: $IV_COUNT"

  # Check for hardcoded IVs
  grep -rn "IvParameterSpec.*\"\\|new byte\[\].*IvParameterSpec\|0x00.*IvParameterSpec\|{0,0,0,0" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/static_iv.txt" || true
  STATIC_IV=$(wc -l < "$CRYPTO_DIR/static_iv.txt" 2>/dev/null || echo 0)
  [ "$STATIC_IV" -gt 0 ] && fadd "$STATIC_IV static/hardcoded IVs (insecure)" HIGH HIGH CWE-329 "A02:2021" "$CRYPTO_DIR/static_iv.txt"

  # A5. Insecure random
  grep -rn "java.util.Random\b\|Math.random\|new Random" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/insecure_random.txt" || true
  RAND_COUNT=$(wc -l < "$CRYPTO_DIR/insecure_random.txt" 2>/dev/null || echo 0)
  info "Insecure random usage: $RAND_COUNT"
  [ "$RAND_COUNT" -gt 0 ] && fadd "$RAND_COUNT uses of insecure random (java.util.Random)" MEDIUM HIGH CWE-330 "A02:2021" "$CRYPTO_DIR/insecure_random.txt"

  # A6. SecureRandom usage (good)
  grep -rn "SecureRandom\|/dev/urandom" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/secure_random.txt" || true
  SRAND_COUNT=$(wc -l < "$CRYPTO_DIR/secure_random.txt" 2>/dev/null || echo 0)
  info "SecureRandom usage: $SRAND_COUNT (good)"

  # A7. Base64 (not encryption)
  grep -rn "Base64.encode\|Base64.decode\|android.util.Base64" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/base64.txt" || true
  B64_COUNT=$(wc -l < "$CRYPTO_DIR/base64.txt" 2>/dev/null || echo 0)
  info "Base64 usage: $B64_COUNT (not encryption)"

  # A8. Certificate pinning
  grep -rn "CertificatePinner\|TrustManager\|X509TrustManager\|SSLContext\|HostnameVerifier\|checkServerTrusted\|checkClientTrusted" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/tls_config.txt" || true
  TLS_COUNT=$(wc -l < "$CRYPTO_DIR/tls_config.txt" 2>/dev/null || echo 0)
  info "TLS/SSL configuration: $TLS_COUNT"

  # Check for custom TrustManagers (potential bypass)
  grep -rn "checkServerTrusted.*\\[\\]" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/weak_trust_manager.txt" || true
  WEAK_TM=$(wc -l < "$CRYPTO_DIR/weak_trust_manager.txt" 2>/dev/null || echo 0)
  [ "$WEAK_TM" -gt 0 ] && fadd "$WEAK_TM weak TrustManager implementations (accept all certs)" CRITICAL HIGH CWE-295 "A07:2021" "$CRYPTO_DIR/weak_trust_manager.txt"

  # A9. KeyStore usage
  grep -rn "KeyStore\|KeyManager\|KeyPairGenerator\|KeyGenerator" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/keystore_usage.txt" || true
  KS_COUNT=$(wc -l < "$CRYPTO_DIR/keystore_usage.txt" 2>/dev/null || echo 0)
  info "KeyStore usage: $KS_COUNT"

  # A10. Key Derivation
  grep -rn "PBKDF2\|scrypt\|argon2\|Hkdf\|SecretKeyFactory" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/kdf.txt" || true
  KDF_COUNT=$(wc -l < "$CRYPTO_DIR/kdf.txt" 2>/dev/null || echo 0)
  info "Key Derivation: $KDF_COUNT"

  # A11. Native crypto (JNI)
  grep -rn "System.loadLibrary\|native.*encrypt\|native.*decrypt\|CryptoNative\|OpenSSL" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/native_crypto.txt" || true
  NATIVE_COUNT=$(wc -l < "$CRYPTO_DIR/native_crypto.txt" 2>/dev/null || echo 0)
  info "Native crypto: $NATIVE_COUNT"
fi

# ============================================================
# B. Dynamic Analysis — Runtime Crypto
# ============================================================
info "=== B. Dynamic Crypto Analysis ==="

CRYPTO_SCRIPT="$PIPELINE_ROOT/extras/frida-scripts/crypto-monitor.js"
if [ -f "$CRYPTO_SCRIPT" ] && command -v frida >/dev/null 2>&1; then
  info "Hooking crypto operations..."
  timeout 30 frida -U -f "$PKG" -l "$CRYPTO_SCRIPT" --no-pause 2>/dev/null > "$CRYPTO_DIR/crypto_hooks.log" &
  FRIDA_PID=$!
  sleep 3

  # Launch app and trigger crypto
  adb shell "monkey -p $PKG -c android.intent.category.LAUNCHER 1" 2>/dev/null || true
  sleep 15

  kill $FRIDA_PID 2>/dev/null || true
  wait $FRIDA_PID 2>/dev/null || true

  # Analyze crypto usage
  if [ -s "$CRYPTO_DIR/crypto_hooks.log" ]; then
    # Count algorithms
    grep "algorithm" "$CRYPTO_DIR/crypto_hooks.log" | sort | uniq -c | sort -rn > "$CRYPTO_DIR/algo_usage.txt" 2>/dev/null || true

    # Find ECB usage
    grep "ECB" "$CRYPTO_DIR/crypto_hooks.log" > "$CRYPTO_DIR/ecb_detected.txt" 2>/dev/null || true
    [ -s "$CRYPTO_DIR/ecb_detected.txt" ] && fadd "ECB mode used at runtime" HIGH HIGH CWE-327 "A02:2021" "$CRYPTO_DIR/ecb_detected.txt"

    # Find hardcoded keys
    grep "hardcoded_key\|key=" "$CRYPTO_DIR/crypto_hooks.log" > "$CRYPTO_DIR/hardcoded_key_detected.txt" 2>/dev/null || true
    [ -s "$CRYPTO_DIR/hardcoded_key_detected.txt" ] && fadd "Hardcoded key detected at runtime" CRITICAL HIGH CWE-798 "A02:2021" "$CRYPTO_DIR/hardcoded_key_detected.txt"

    # Find IV reuse
    grep "iv_reuse\|static_iv" "$CRYPTO_DIR/crypto_hooks.log" > "$CRYPTO_DIR/iv_reuse_detected.txt" 2>/dev/null || true
    [ -s "$CRYPTO_DIR/iv_reuse_detected.txt" ] && fadd "IV reuse detected at runtime" HIGH HIGH CWE-329 "A02:2021" "$CRYPTO_DIR/iv_reuse_detected.txt"

    # Sensitive data in crypto operations
    grep "token\|password\|secret\|api_key" "$CRYPTO_DIR/crypto_hooks.log" | grep -iv "encrypt\|decrypt" > "$CRYPTO_DIR/sensitive_crypto.txt" 2>/dev/null || true
    [ -s "$CRYPTO_DIR/sensitive_crypto.txt" ] && fadd "Sensitive data in crypto operations" MEDIUM MEDIUM CWE-312 "A04:2021" "$CRYPTO_DIR/sensitive_crypto.txt"
  fi
else
  warn "Frida crypto hook script not available"
fi

# ============================================================
# C. SSL/TLS Analysis
# ============================================================
info "=== C. SSL/TLS Analysis ==="

# Check for SSL pinning
SSL_PINNING=$(grep -rc "CertificatePinner\|ssl_pinning\|pinning" "$JADX_DIR/sources/" 2>/dev/null || echo 0)
info "SSL Pinning references: $SSL_PINNING"

# Check TLS version usage
grep -rn "TLSv1\b\|TLSv1\.1\|SSLv3\|SSLv2" "$JADX_DIR/sources/" 2>/dev/null > "$CRYPTO_DIR/weak_tls.txt" || true
WEAK_TLS=$(wc -l < "$CRYPTO_DIR/weak_tls.txt" 2>/dev/null || echo 0)
[ "$WEAK_TLS" -gt 0 ] && fadd "$WEAK_TLS weak TLS version references" HIGH HIGH CWE-326 "A02:2021" "$CRYPTO_DIR/weak_tls.txt"

# Network security config analysis
NSC="$RUN_DIR/static/network_security_config.xml"
if [ -f "$NSC" ]; then
  grep -q "debuggable.*true\|trust-anchors.*user" "$NSC" 2>/dev/null && \
    fadd "Debug trust anchors in network security config" MEDIUM MEDIUM CWE-295 "A07:2021" "$NSC"
fi

ok "Crypto audit complete -> $CRYPTO_DIR"
fsnapshot
