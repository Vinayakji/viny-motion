# Android Attack Patterns Reference
> Version: 1.0 | Last Updated: 2026-09-01

## OWASP MASTG (Mobile Application Security Testing Guide)

### M1: Improper Platform Usage
| Test ID | Pattern | Detection | Impact |
|---------|---------|-----------|--------|
| MASTG-TEST-0032 | `android:debuggable="true"` | Manifest audit | Code execution, data theft |
| MASTG-TEST-0033 | `android:allowBackup="true"` | Manifest audit | Backup extraction |
| MASTG-TEST-0035 | `android:exported="true"` | Manifest audit | Unauthorized component access |
| MASTG-TEST-0043 | `DexClassLoader`, `PathClassLoader` | Code search | Code injection |
| MASTG-TEST-0044 | `Runtime.getRuntime().exec` | Code search | Command injection |
| MASTG-TEST-0073 | `PreferenceActivity` without `isValidFragment` | Code search | Fragment injection |
| MASTG-TEST-0051 | `rawQuery`, `execSQL` with `+` | Code search | SQL injection |
| MASTG-TEST-0052 | `getIntent().get*Extra` without validation | Code search | Intent injection |

### M2: Insecure Data Storage
| Test ID | Pattern | Detection | Impact |
|---------|---------|-----------|--------|
| MASTG-TEST-0018 | `getExternalFilesDir`, `getExternalStorageDirectory` | Code search | Data leakage |
| MASTG-TEST-0030 | `MODE_WORLD_READABLE/WRITABLE` | Code search | Data leakage |
| MASTG-TEST-0041 | `ClipboardManager` with sensitive data | Code search | Data leakage |
| MASTG-TEST-0056 | `SharedPreferences` with sensitive data | Code search | Data leakage |
| MASTG-TEST-0088 | `EncryptedSharedPreferences` | Code search | Crypto key mgmt |
| MASTG-TEST-0090 | `SQLCipher` | Code search | Crypto key mgmt |

### M3: Insecure Communication
| Test ID | Pattern | Detection | Impact |
|---------|---------|-----------|--------|
| MASTG-TEST-0011 | `http://` URLs | Code search | MITM |
| MASTG-TEST-0026 | `TLSv1.0`, `SSLv3` | Code search | Protocol downgrade |
| MASTG-TEST-0072 | `HostnameVerifier`, `TrustAllCerts` | Code search | Certificate bypass |
| MASTG-TEST-0084 | `OkHttpClient` config | Code search | TLS misconfig |
| MASTG-TEST-0085 | `HttpClient` (Ktor) config | Code search | TLS misconfig |

### M4: Insecure Authentication
| Test ID | Pattern | Detection | Impact |
|---------|---------|-----------|--------|
| MASTG-TEST-0066 | `BiometricPrompt`, `FingerprintManager` | Code search | Auth bypass |
| MASTG-TEST-0058 | `ACCESS_FINE_LOCATION` | Manifest audit | Location tracking |
| MASTG-TEST-0059 | `CAMERA` permission | Manifest audit | Camera abuse |
| MASTG-TEST-0060 | `RECORD_AUDIO` permission | Manifest audit | Audio recording |
| MASTG-TEST-0062 | `SmsManager`, `SEND_SMS` | Manifest audit | SMS fraud |

### M5: Insufficient Cryptography
| Test ID | Pattern | Detection | Impact |
|---------|---------|-----------|--------|
| MASTG-TEST-0014 | `DES`, `MD5`, `SHA1`, `RC4`, `ECB` | Code search | Crypto weakness |
| MASTG-TEST-0015 | `SecretKeySpec` with hardcoded key | Code search | Key exposure |
| MASTG-TEST-0017 | `Math.random()`, `java.util.Random` | Code search | Predictable output |

### M7: Client Code Quality
| Test ID | Pattern | Detection | Impact |
|---------|---------|-----------|--------|
| MASTG-TEST-0023 | `addJavascriptInterface` | Code search | JS bridge abuse |
| MASTG-TEST-0024 | `setAllowFileAccess(true)` | Code search | File access |
| MASTG-TEST-0025 | `loadUrl("http://")` | Code search | HTTP in WebView |

### M9: Reverse Engineering
| Test ID | Pattern | Detection | Impact |
|---------|---------|-----------|--------|
| MASTG-TEST-0020 | `Log.d/v/i/w/e()` | Code search | Info disclosure |
| MASTG-TEST-0021 | Logs with sensitive data | Code search | PII leakage |
| MASTG-TEST-0076 | `isRooted`, `RootBeer` | Code search | Root detection |

## Common Exploitation Chains

### 1. ATO Chain
```
Weak auth → IDOR → Session hijack → Account takeover
```
**Detection:** Sequential IDs in API, no authz checks, session token predictability.

### 2. SSRF → RCE Chain
```
URL parameter → SSRF to internal service → RCE via internal API
```
**Detection:** `URL()` with user input, `HttpURLConnection`, no allowlist.

### 3. XSS → Cookie Theft → ATO
```
Reflected XSS → document.cookie → Session token exfil
```
**Detection:** User input in HTML/JS without encoding.

### 4. SQLi → Data Exfil
```
User input → rawQuery/execSQL → database dump
```
**Detection:** String concatenation in SQL queries.

### 5. Path Traversal → Config Leak
```
File path parameter → ../ traversal → /data/data/... config access
```
**Detection:** `openFileInput`/`openFileOutput` with user-controlled paths.

### 6. Deep Link → Intent Injection
```
Malicious deep link → intent data → component hijack
```
**Detection:** `intent.getData()` without validation.

## Detection Cheatsheet

| What to grep | Pattern |
|--------------|---------|
| Hardcoded secrets | `api_key`, `secret`, `token`, `password`, `firebase`, `aws` |
| Weak crypto | `DES`, `MD5`, `SHA1`, `RC4`, `ECB` |
| Insecure storage | `getExternal`, `MODE_WORLD`, `SharedPreferences` |
| Debug flags | `debuggable`, `allowBackup`, `LogLevel.ALL` |
| Network issues | `http://`, `TrustAllCerts`, `ALLOW_ALL_HOSTNAME` |
| Command exec | `Runtime.exec`, `ProcessBuilder`, `exec(` |
| SQL injection | `rawQuery`, `execSQL`, `+.*sql` |
| XSS | `loadUrl`, `evaluateJavascript`, `innerHTML` |
| Intent abuse | `getIntent`, `startActivity`, `sendBroadcast` |
| Crypto ops | `Cipher`, `SecretKeySpec`, `KeyGenerator`, `KeyStore` |
