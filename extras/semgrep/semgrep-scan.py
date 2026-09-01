#!/usr/bin/env python3
"""
semgrep-scan.py — Semgrep SAST integration for Android APK analysis
Reads decompiled Java/Smali code and runs semgrep with MASTG-aligned rules.
Usage: python3 semgrep-scan.py <jadx_output_dir> <output_dir>
"""
import os, sys, json, subprocess, tempfile
from pathlib import Path
from datetime import datetime

MASTRG_RULES = {
    "MASTG-TEST-0011": {
        "id": "mastg-cleartext-traffic",
        "severity": "WARNING",
        "message": "Cleartext HTTP traffic detected",
        "pattern": "http://",
        "paths": {"include": ["*.java", "*.xml"]},
        "metadata": {"owasp": "M3", "cwe": "CWE-319"}
    },
    "MASTG-TEST-0014": {
        "id": "mastg-weak-crypto",
        "severity": "WARNING",
        "message": "Weak cryptographic algorithm usage",
        "pattern": "DES|MD5|SHA1\\.|RC4|ECB",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M5", "cwe": "CWE-327"}
    },
    "MASTG-TEST-0015": {
        "id": "mastg-hardcoded-key",
        "severity": "ERROR",
        "message": "Hardcoded cryptographic key",
        "pattern": "SecretKeySpec\\(|new SecretKeySpec\\(|\"AES\"|\"DES\"",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M5", "cwe": "CWE-798"}
    },
    "MASTG-TEST-0017": {
        "id": "mastg-insecure-random",
        "severity": "WARNING",
        "message": "Insecure random number generator",
        "pattern": "Math\\.random\\(\\)|java\\.util\\.Random",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M5", "cwe": "CWE-330"}
    },
    "MASTG-TEST-0018": {
        "id": "mastg-external-storage",
        "severity": "WARNING",
        "message": "External storage usage for sensitive data",
        "pattern": "getExternalFilesDir|getExternalStorageDirectory|Environment\\.getExternalStorage",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M2", "cwe": "CWE-922"}
    },
    "MASTG-TEST-0020": {
        "id": "mastg-logging",
        "severity": "INFO",
        "message": "Sensitive data in logs",
        "pattern": "Log\\.(d|v|i|w|e)\\(",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M9", "cwe": "CWE-532"}
    },
    "MASTG-TEST-0021": {
        "id": "mastg-userdata-leak",
        "severity": "WARNING",
        "message": "Potential sensitive data in log output",
        "pattern": "Log\\.(d|v|i|w|e)\\(.*(?:password|token|secret|key|credential)",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M9", "cwe": "CWE-532"}
    },
    "MASTG-TEST-0023": {
        "id": "mastg-webview-javascript",
        "severity": "WARNING",
        "message": "WebView JavaScript interface enabled",
        "pattern": "addJavascriptInterface|setJavaScriptEnabled\\(true\\)",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M7", "cwe": "CWE-610"}
    },
    "MASTG-TEST-0024": {
        "id": "mastg-webview-file-access",
        "severity": "WARNING",
        "message": "WebView file access enabled",
        "pattern": "setAllowFileAccess\\(true\\)|setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M7", "cwe": "CWE-610"}
    },
    "MASTG-TEST-0025": {
        "id": "mastg-webview-https",
        "severity": "WARNING",
        "message": "WebView loads HTTP URL",
        "pattern": "loadUrl\\(\"http://|loadData.*http://",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M7", "cwe": "CWE-319"}
    },
    "MASTG-TEST-0026": {
        "id": "mastg-tls-version",
        "severity": "WARNING",
        "message": "Deprecated TLS version",
        "pattern": "TLSv1\\.0|TLSv1\\.1|SSLv3|SSLContext\\.getInstance\\(\"TLS\"\\)",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M3", "cwe": "CWE-326"}
    },
    "MASTG-TEST-0030": {
        "id": "mastg-insecure-shared-prefs",
        "severity": "WARNING",
        "message": "SharedPreferences stored in MODE_WORLD_READABLE/WRITABLE",
        "pattern": "MODE_WORLD_READABLE|MODE_WORLD_WRITABLE",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M2", "cwe": "CWE-922"}
    },
    "MASTG-TEST-0032": {
        "id": "mastg-debuggable",
        "severity": "INFO",
        "message": "App is debuggable",
        "pattern": "android:debuggable=\"true\"",
        "paths": {"include": ["AndroidManifest.xml"]},
        "metadata": {"owasp": "M1", "cwe": "CWE-489"}
    },
    "MASTG-TEST-0033": {
        "id": "mastg-allow-backup",
        "severity": "INFO",
        "message": "App allows backup",
        "pattern": "android:allowBackup=\"true\"",
        "paths": {"include": ["AndroidManifest.xml"]},
        "metadata": {"owasp": "M2", "cwe": "CWE-312"}
    },
    "MASTG-TEST-0034": {
        "id": "mastg-network-security",
        "severity": "INFO",
        "message": "Network security config missing or default",
        "pattern": "android:networkSecurityConfig",
        "paths": {"include": ["AndroidManifest.xml"]},
        "metadata": {"owasp": "M3", "cwe": "CWE-295"}
    },
    "MASTG-TEST-0035": {
        "id": "mastg-exported-component",
        "severity": "WARNING",
        "message": "Exported component without permission",
        "pattern": "android:exported=\"true\"",
        "paths": {"include": ["AndroidManifest.xml"]},
        "metadata": {"owasp": "M1", "cwe": "CWE-927"}
    },
    "MASTG-TEST-0041": {
        "id": "mastg-clipboard-sensitive",
        "severity": "WARNING",
        "message": "Clipboard usage for sensitive data",
        "pattern": "ClipboardManager|setPrimaryClip|getPrimaryClip",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M2", "cwe": "CWE-316"}
    },
    "MASTG-TEST-0042": {
        "id": "mastg-keychain-usage",
        "severity": "INFO",
        "message": "Android Keystore usage detected",
        "pattern": "KeyStore\\.getInstance|KeyGenerator\\.getInstance|KeyPairGenerator",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M5", "cwe": "CWE-320"}
    },
    "MASTG-TEST-0043": {
        "id": "mastg-dynamic-loading",
        "severity": "WARNING",
        "message": "Dynamic code loading detected",
        "pattern": "DexClassLoader|PathClassLoader|InMemoryDexClassLoader|DexFile\\.loadDex",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M1", "cwe": "CWE-94"}
    },
    "MASTG-TEST-0044": {
        "id": "mastg-exec-command",
        "severity": "ERROR",
        "message": "Runtime command execution",
        "pattern": "Runtime\\.getRuntime\\(\\)\\.exec|ProcessBuilder",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M1", "cwe": "CWE-78"}
    },
    "MASTG-TEST-0051": {
        "id": "mastg-sql-injection",
        "severity": "ERROR",
        "message": "Potential SQL injection",
        "pattern": "rawQuery\\(|execSQL\\(.*\\+|compileStatement\\(.*\\+",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M1", "cwe": "CWE-89"}
    },
    "MASTG-TEST-0052": {
        "id": "mastg-intent-injection",
        "severity": "WARNING",
        "message": "Intent data used without validation",
        "pattern": "getIntent\\(\\)\\.get.*Extra|getIntent\\(\\)\\.getData|intent\\.getParcelableExtra",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M1", "cwe": "CWE-927"}
    },
    "MASTG-TEST-0053": {
        "id": "mastg-broadcast-receiver",
        "severity": "INFO",
        "message": "Broadcast receiver registered dynamically",
        "pattern": "registerReceiver\\(|sendBroadcast\\(|sendOrderedBroadcast\\(",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M1", "cwe": "CWE-927"}
    },
    "MASTG-TEST-0054": {
        "id": "mastg-deep-link",
        "severity": "INFO",
        "message": "Deep link / URI scheme handling",
        "pattern": "intent\\.getData|intent\\.getAction|ACTION_VIEW|onNewIntent",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M1", "cwe": "CWE-610"}
    },
    "MASTG-TEST-0055": {
        "id": "mastg-implicit-intent",
        "severity": "INFO",
        "message": "Implicit intent usage",
        "pattern": "new Intent\\(\"|Intent\\(.*\\)\\.setAction|setPackage\\(",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M1", "cwe": "CWE-927"}
    },
    "MASTG-TEST-0056": {
        "id": "mastg-data-storage",
        "severity": "INFO",
        "message": "SharedPreferences access",
        "pattern": "SharedPreferences|getSharedPreferences|edit\\(\\)\\.put",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M2", "cwe": "CWE-922"}
    },
    "MASTG-TEST-0058": {
        "id": "mastg-location-tracking",
        "severity": "WARNING",
        "message": "Location access",
        "pattern": "requestLocationUpdates|getLastKnownLocation|ACCESS_FINE_LOCATION|ACCESS_COARSE_LOCATION",
        "paths": {"include": ["*.java", "*.xml"]},
        "metadata": {"owasp": "M4", "cwe": "CWE-200"}
    },
    "MASTG-TEST-0059": {
        "id": "mastg-camera-access",
        "severity": "INFO",
        "message": "Camera access",
        "pattern": "CameraManager|Camera\\.|CAMERA|takePicture|captureImage",
        "paths": {"include": ["*.java", "*.xml"]},
        "metadata": {"owasp": "M4", "cwe": "CWE-200"}
    },
    "MASTG-TEST-0060": {
        "id": "mastg-microphone-access",
        "severity": "INFO",
        "message": "Microphone/Recording access",
        "pattern": "MediaRecorder|AudioRecord|RECORD_AUDIO|startRecording|setAudioSource",
        "paths": {"include": ["*.java", "*.xml"]},
        "metadata": {"owasp": "M4", "cwe": "CWE-200"}
    },
    "MASTG-TEST-0062": {
        "id": "mastg-sms-sending",
        "severity": "WARNING",
        "message": "SMS sending capability",
        "pattern": "SmsManager|sendTextMessage|SEND_SMS",
        "paths": {"include": ["*.java", "*.xml"]},
        "metadata": {"owasp": "M4", "cwe": "CWE-927"}
    },
    "MASTG-TEST-0063": {
        "id": "mastg-phone-calls",
        "severity": "INFO",
        "message": "Phone call initiation",
        "pattern": "ACTION_CALL|ACTION_DIAL|call\\(\"tel:|CALL_PHONE",
        "paths": {"include": ["*.java", "*.xml"]},
        "metadata": {"owasp": "M4", "cwe": "CWE-927"}
    },
    "MASTG-TEST-0064": {
        "id": "mastg-nfc-access",
        "severity": "INFO",
        "message": "NFC capability",
        "pattern": "NfcAdapter|NDEF|NFC|IsoDep|Tag",
        "paths": {"include": ["*.java", "*.xml"]},
        "metadata": {"owasp": "M4", "cwe": "CWE-200"}
    },
    "MASTG-TEST-0066": {
        "id": "mastg-biometric-auth",
        "severity": "INFO",
        "message": "Biometric authentication usage",
        "pattern": "BiometricPrompt|FingerprintManager|authenticate\\(",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M4", "cwe": "CWE-287"}
    },
    "MASTG-TEST-0067": {
        "id": "mastg-keystore-ops",
        "severity": "INFO",
        "message": "Keystore operations",
        "pattern": "KeyStore|KeyGenParameterSpec|KeyPairGeneratorSpec|AndroidKeyStore",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M5", "cwe": "CWE-320"}
    },
    "MASTG-TEST-0068": {
        "id": "mastg-ssrf",
        "severity": "ERROR",
        "message": "Potential SSRF via URL construction",
        "pattern": "URL\\(.*\\+|new URL\\(.*request|openConnection|HttpURLConnection",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M1", "cwe": "CWE-918"}
    },
    "MASTG-TEST-0069": {
        "id": "mastg-path-traversal",
        "severity": "ERROR",
        "message": "Potential path traversal",
        "pattern": "\\.\\.\\/|\\.\\\\\\.\\.|getAbsolutePath|openFileInput|openFileOutput",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M1", "cwe": "CWE-22"}
    },
    "MASTG-TEST-0070": {
        "id": "mastg-xxe",
        "severity": "ERROR",
        "message": "Potential XML External Entity",
        "pattern": "DocumentBuilderFactory|SAXParser|XMLReader|FEATURE.*EXTERNAL",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M1", "cwe": "CWE-611"}
    },
    "MASTG-TEST-0071": {
        "id": "mastg-deserialization",
        "severity": "ERROR",
        "message": "Insecure deserialization",
        "pattern": "ObjectInputStream|readObject\\(|Serializable|Parcelable",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M1", "cwe": "CWE-502"}
    },
    "MASTG-TEST-0072": {
        "id": "mastg-insecure-net",
        "severity": "WARNING",
        "message": "Insecure network configuration",
        "pattern": "HostnameVerifier|ALLOW_ALL_HOSTNAME|TrustAllCerts|X509TrustManager.*checkClientTrusted.*\\{\\s*\\}",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M3", "cwe": "CWE-295"}
    },
    "MASTG-TEST-0073": {
        "id": "mastg-fragment-injection",
        "severity": "WARNING",
        "message": "Fragment injection via PreferenceActivity",
        "pattern": "PreferenceActivity|PreferenceActivityCompat|isValidFragment",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M1", "cwe": "CWE-560"}
    },
    "MASTG-TEST-0075": {
        "id": "mastg-jni-reg",
        "severity": "INFO",
        "message": "JNI method registration",
        "pattern": "System\\.loadLibrary|System\\.load|registerNatives|nativeMethod",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M1", "cwe": "CWE-676"}
    },
    "MASTG-TEST-0076": {
        "id": "mastg-rooted-device",
        "severity": "INFO",
        "message": "Root detection implementation",
        "pattern": "isRooted|RootBeer|checkRoot|/system/bin/su",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M1", "cwe": "CWE-284"}
    },
    "MASTG-TEST-0078": {
        "id": "mastg-crypto-usage",
        "severity": "INFO",
        "message": "Cryptographic operation",
        "pattern": "Cipher\\.getInstance|MessageDigest\\.getInstance|Mac\\.getInstance|SecretKey|KeyGenerator",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M5", "cwe": "CWE-327"}
    },
    "MASTG-TEST-0079": {
        "id": "mastg-obfuscation",
        "severity": "INFO",
        "message": "Potential code obfuscation",
        "pattern": "[a-z]{1,2}\\.[a-z]{1,2}\\.[a-z]{1,2}\\.[A-Z][a-z]+",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M1", "cwe": "CWE-95"}
    },
    "MASTG-TEST-0082": {
        "id": "mastg-kotlin-crypto",
        "severity": "INFO",
        "message": "Kotlin coroutine + crypto",
        "pattern": "suspend.*Cipher|suspend.*encrypt|suspend.*decrypt",
        "paths": {"include": ["*.kt"]},
        "metadata": {"owasp": "M5", "cwe": "CWE-327"}
    },
    "MASTG-TEST-0084": {
        "id": "mastg-okhttp-config",
        "severity": "INFO",
        "message": "OkHttp client configuration",
        "pattern": "OkHttpClient|Interceptor|addInterceptor|sslSocketFactory",
        "paths": {"include": ["*.java", "*.kt"]},
        "metadata": {"owasp": "M3", "cwe": "CWE-295"}
    },
    "MASTG-TEST-0085": {
        "id": "mastg-ktor-client",
        "severity": "INFO",
        "message": "Ktor HTTP client usage",
        "pattern": "HttpClient|install\\(|expectSuccess|HttpTimeout",
        "paths": {"include": ["*.kt"]},
        "metadata": {"owasp": "M3", "cwe": "CWE-295"}
    },
    "MASTG-TEST-0086": {
        "id": "mastg-retrofit-api",
        "severity": "INFO",
        "message": "Retrofit API client",
        "pattern": "@GET|@POST|@PUT|@DELETE|@PATCH|@Headers|@Body",
        "paths": {"include": ["*.java", "*.kt"]},
        "metadata": {"owasp": "M3", "cwe": "CWE-295"}
    },
    "MASTG-TEST-0088": {
        "id": "mastg-storage-encrypted",
        "severity": "INFO",
        "message": "EncryptedSharedPreferences usage",
        "pattern": "EncryptedSharedPreferences|MasterKey|EncryptedFile",
        "paths": {"include": ["*.java", "*.kt"]},
        "metadata": {"owasp": "M2", "cwe": "CWE-312"}
    },
    "MASTG-TEST-0090": {
        "id": "mastg-sqlcipher",
        "severity": "INFO",
        "message": "SQLCipher encrypted database",
        "pattern": "SQLCipher|net\\.zetetic|Passphrase",
        "paths": {"include": ["*.java"]},
        "metadata": {"owasp": "M2", "cwe": "CWE-312"}
    }
}

def write_semgrep_rules(output_dir):
    """Write MASTG-aligned semgrep rules as a single YAML file."""
    rules_path = os.path.join(output_dir, "mastg_rules.yaml")
    with open(rules_path, "w") as f:
        f.write("rules:\n")
        for rule_id, rule in MASTG_RULES.items():
            f.write(f"  - id: {rule['id']}\n")
            f.write(f"    severity: {rule['severity']}\n")
            f.write(f"    message: \"{rule['message']}\"\n")
            f.write(f"    metadata:\n")
            for k, v in rule.get("metadata", {}).items():
                f.write(f"      {k}: \"{v}\"\n")
            f.write(f"    pattern: \"{rule['pattern']}\"\n")
            f.write(f"    paths:\n")
            for k, v in rule.get("paths", {}).items():
                f.write(f"      {k}:\n")
                for p in v:
                    f.write(f"        - \"{p}\"\n")
            f.write("\n")
    return rules_path

def run_semgrep(jadx_dir, output_dir):
    """Run semgrep against decompiled code."""
    results_path = os.path.join(output_dir, "semgrep_results.json")
    rules_path = write_semgrep_rules(output_dir)
    
    # Check if semgrep is available
    semgrep_available = False
    try:
        result = subprocess.run(["semgrep", "--version"], capture_output=True, timeout=10)
        semgrep_available = result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        semgrep_available = False
    
    if not semgrep_available:
        print("[!] Semgrep not installed — falling back to grep-based scan")
        return grep_fallback(jadx_dir, output_dir, results_path)
    
    try:
        result = subprocess.run(
            ["semgrep", "--config", rules_path, "--json", "--quiet", jadx_dir],
            capture_output=True, text=True, timeout=300
        )
        with open(results_path, "w") as f:
            json.dump(json.loads(result.stdout) if result.stdout else {"results": []}, f, indent=2)
        return results_path
    except Exception as e:
        print(f"[!] Semgrep failed: {e}")
        return grep_fallback(jadx_dir, output_dir, results_path)

def grep_fallback(jadx_dir, output_dir, results_path):
    """Grep-based fallback when semgrep is unavailable."""
    findings = []
    for rule_id, rule in MASTG_RULES.items():
        pattern = rule["pattern"]
        includes = rule.get("paths", {}).get("include", ["*.java"])
        for include in includes:
            ext = include.lstrip("*")
            cmd = f"grep -rn --include='*{ext}' -E '{pattern}' '{jadx_dir}' 2>/dev/null | head -50"
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                for line in result.stdout.strip().split("\n"):
                    if line and ":" in line:
                        parts = line.split(":", 2)
                        if len(parts) >= 3:
                            findings.append({
                                "check_id": rule["id"],
                                "path": parts[0],
                                "start": {"line": int(parts[1]) if parts[1].isdigit() else 0},
                                "extra": {"message": rule["message"], "severity": rule["severity"], "metadata": rule.get("metadata", {})},
                                "extra_lines": parts[2][:200]
                            })
            except Exception:
                pass
    
    with open(results_path, "w") as f:
        json.dump({"results": findings, "total": len(findings)}, f, indent=2)
    return results_path

def summarize(results_path, output_dir):
    """Summarize semgrep results."""
    with open(results_path) as f:
        data = json.load(f)
    
    results = data.get("results", [])
    summary = {"total": len(results), "by_severity": {}, "by_owasp": {}, "by_cwe": {}}
    
    for r in results:
        sev = r.get("extra", {}).get("severity", "UNKNOWN")
        summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1
        meta = r.get("extra", {}).get("metadata", {})
        owasp = meta.get("owasp", "unknown")
        summary["by_owasp"][owasp] = summary["by_owasp"].get(owasp, 0) + 1
        cwe = meta.get("cwe", "unknown")
        summary["by_cwe"][cwe] = summary["by_cwe"].get(cwe, 0) + 1
    
    summary_path = os.path.join(output_dir, "semgrep_summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    return summary

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: semgrep-scan.py <jadx_output_dir> <output_dir>")
        sys.exit(1)
    
    jadx_dir = sys.argv[1]
    output_dir = sys.argv[2]
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"[*] Semgrep SAST scan: {jadx_dir}")
    results_path = run_semgrep(jadx_dir, output_dir)
    summary = summarize(results_path, output_dir)
    
    print(f"[+] Total findings: {summary['total']}")
    print(f"[+] By severity: {json.dumps(summary['by_severity'])}")
    print(f"[+] By OWASP: {json.dumps(summary['by_owasp'])}")
    print(f"[+] Results: {results_path}")
    print(f"[+] Summary: {output_dir}/semgrep_summary.json")
