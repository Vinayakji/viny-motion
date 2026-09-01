# Static Analysis Patterns Reference
> Version: 1.0 | Last Updated: 2026-09-01

## Grep Patterns for Security Testing

### Secrets & Hardcoded Credentials
```bash
# API Keys
grep -rn "api[_-]\?key\|API[_-]\?KEY\|apiKey\|ApiKey" sources/
grep -rn "AIzaSy\|AKIA\|SG\.\|sk_live\|pk_live" sources/

# Tokens
grep -rn "token\|Token\|TOKEN\|bearer\|Bearer\|BEARER" sources/
grep -rn "jwt\|JWT\|access_token\|refresh_token" sources/

# Passwords & Secrets
grep -rn "password\|Password\|PASSWORD\|passwd\|secret\|SECRET" sources/
grep -rn "private[_-]\?key\|PRIVATE[_-]\?KEY\|privateKey" sources/

# Firebase
grep -rn "firebase\|Firebase\|FIREBASE\|google-services\.json" sources/
grep -rn "AIzaSy\|project_id\|storageBucket\|messaging_sender_id" sources/

# Cloud credentials
grep -rn "aws_access_key\|aws_secret_key\|AKIA[A-Z0-9]" sources/
grep -rn "gcloud\|gcp\|azure\|subscription_id" sources/
```

### Weak Cryptography
```bash
# Weak algorithms
grep -rn "DES\b\|3DES\b\|MD5\|SHA1\b\|RC4\|ECB\|Blowfish" sources/
grep -rn "getInstance.*DES\|getInstance.*MD5\|getInstance.*SHA-1" sources/

# Hardcoded keys
grep -rn "SecretKeySpec\|new SecretKeySpec\|KeySpec" sources/
grep -rn "\"AES\"\|\"DES\"\|\"RSA\"\|\"HmacSHA" sources/

# Insecure random
grep -rn "Math\.random\|java\.util\.Random\|new Random" sources/
grep -rn "SecureRandom" sources/  # Check if NOT used
```

### Insecure Storage
```bash
# External storage
grep -rn "getExternalFilesDir\|getExternalStorageDirectory\|Environment\.getExternal" sources/
grep -rn "WRITE_EXTERNAL_STORAGE\|READ_EXTERNAL_STORAGE" AndroidManifest.xml

# SharedPreferences (sensitive data)
grep -rn "SharedPreferences\|getSharedPreferences\|edit()\.put" sources/
grep -rn "MODE_WORLD_READABLE\|MODE_WORLD_WRITABLE" sources/

# SQLite (unencrypted)
grep -rn "SQLiteDatabase\|rawQuery\|execSQL\|SQLiteOpenHelper" sources/
grep -rn "SQLCipher\|net\.zetetic" sources/  # Check if encrypted
```

### Network Security
```bash
# Cleartext traffic
grep -rn "http://" sources/
grep -rn "usesCleartextTraffic\|cleartextTrafficPermitted" sources/ AndroidManifest.xml

# TLS issues
grep -rn "TLSv1\.0\|TLSv1\.1\|SSLv3" sources/
grep -rn "SSLContext\.getInstance.*TLS" sources/
grep -rn "SSLContext\.getInstance.*SSL" sources/

# Certificate bypass
grep -rn "HostnameVerifier\|ALLOW_ALL_HOSTNAME" sources/
grep -rn "TrustAllCerts\|X509TrustManager.*checkClientTrusted" sources/
grep -rn "checkServerTrusted.*\{\s*\}" sources/

# Pinning
grep -rn "CertificatePinner\|PinningTrustManager\|pin-set" sources/
grep -rn "sslSocketFactory\|TrustManagerFactory" sources/
```

### Command Injection
```bash
# Runtime exec
grep -rn "Runtime\.getRuntime()\.exec\|ProcessBuilder" sources/
grep -rn "exec(\|execStart\|su " sources/

# Shell commands
grep -rn "/system/bin/sh\|/bin/sh\|cmd /c" sources/
grep -rn "Runtime.*exec.*\+" sources/  # String concat in exec
```

### SQL Injection
```bash
# Direct string concat in queries
grep -rn "rawQuery.*+\|execSQL.*+\|compileStatement.*+" sources/
grep -rn "SELECT.*FROM.*\+\|INSERT.*INTO.*\+" sources/

# Content provider queries
grep -rn "contentResolver\.query\|getContentResolver\(\)\.query" sources/
```

### XSS & WebView
```bash
# JavaScript bridge
grep -rn "addJavascriptInterface\|@JavascriptInterface" sources/
grep -rn "setJavaScriptEnabled.*true" sources/

# File access
grep -rn "setAllowFileAccess.*true\|setAllowFileAccessFromFileURLs.*true" sources/
grep -rn "setAllowUniversalAccessFromFileURLs.*true" sources/

# HTTP in WebView
grep -rn "loadUrl.*http://\|loadData.*http://" sources/
grep -rn "evaluateJavascript" sources/
```

### Intent Abuse
```bash
# Intent without validation
grep -rn "getIntent()\.get\|getIntent()\.getData" sources/
grep -rn "intent\.getParcelableExtra\|intent\.getStringExtra" sources/

# Exported components
grep -rn "android:exported=\"true\"" AndroidManifest.xml

# Implicit intents
grep -rn "new Intent(.*\"\|Intent(.*setAction" sources/
grep -rn "sendBroadcast\|sendOrderedBroadcast" sources/
```

### Deserialization
```bash
# Java deserialization
grep -rn "ObjectInputStream\|readObject\(\)" sources/
grep -rn "Serializable\|Parcelable" sources/

# JSON deserialization
grep -rn "fromJson\|JsonObject\|JsonParser\|parseJson" sources/
grep -rn "kotlinx\.serialization\|@Serializable" sources/

# Proto/FlatBuffers
grep -rn "parseFrom\|protobuf\|FlatBuffer" sources/
```

### Debug & Logging
```bash
# Debug flags
grep -rn "debuggable\|isDebuggable\|Debug\.isDebugger" sources/
grep -rn "LogLevel\.ALL\|LogLevel\.BODY\|LogLevel\.HEADERS" sources/

# Logging
grep -rn "Log\.d\|Log\.v\|Log\.i\|Log\.w\|Log\.e" sources/
grep -rn "System\.out\.print\|System\.err\.print" sources/
```

### Path Traversal
```bash
# File operations with user input
grep -rn "openFileInput\|openFileOutput\|FileInputStream\|FileOutputStream" sources/
grep -rn "getAbsolutePath\|getCanonicalPath" sources/
grep -rn "\.\./\|\.\.\\\\" sources/
```

### Deep Link & URI
```bash
# Deep link handling
grep -rn "intent\.getData\|intent\.getAction\|ACTION_VIEW" sources/
grep -rn "onNewIntent\|setIntent" sources/
grep -rn "android:scheme\|android:host\|android:pathPrefix" AndroidManifest.xml
```

## Semgrep Equivalent Patterns
```yaml
# Example semgrep rules
rules:
  - id: hardcoded-api-key
    pattern: "api_key = $X"
    severity: ERROR
    
  - id: weak-crypto
    pattern: "Cipher.getInstance(\"$X\")"
    severity: WARNING
    
  - id: sql-injection
    pattern: "rawQuery($X + $Y)"
    severity: ERROR
```
