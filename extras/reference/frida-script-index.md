# Frida Script Index
> Version: 1.0 | Last Updated: 2026-09-01
> Total scripts: 61

## By Category

### 1. Root/Jailbreak Detection & Bypass
| Script | Purpose | Applicable When |
|--------|---------|-----------------|
| `root-bypass.js` | Bypass root detection (su, RootBeer, SuperSU) | Root detection present |
| `rootkit-detector.js` | Detect rootkit and persistence mechanisms | Post-root enumeration |
| `emulator-detection-bypass.js` | Spoof build properties, file checks | Running on emulator |

### 2. Anti-Debug & Anti-Analysis
| Script | Purpose | Applicable When |
|--------|---------|-----------------|
| `anti-debug.js` | Bypass isDebuggerConnected, TracerPid, timing | Anti-debug present |
| `android-anti-frida-countermeasures.js` | Counter Frida detection attempts | Frida detection present |
| `rasp-bypass.js` | Generic RASP bypass framework | RASP active |

### 3. SSL/TLS & Network
| Script | Purpose | Applicable When |
|--------|---------|-----------------|
| `ssl-bypass.js` | Bypass SSL pinning (TrustManager, CertificatePinner) | SSL pinning active |
| `tls-interceptor.js` | Intercept TLS traffic | Network analysis |
| `network-interceptor.js` | Monitor all network connections | Traffic capture |
| `network-interceptor-enhanced.js` | Enhanced network monitoring with logging | Detailed traffic analysis |
| `network-security-bypass.js` | Bypass network security config | Security config active |
| `okhttp-interceptor.js` | Intercept OkHttp requests/responses | OkHttp-based app |

### 4. Cryptography & Key Management
| Script | Purpose | Applicable When |
|--------|---------|-----------------|
| `crypto-monitor.js` | Monitor all crypto operations | Crypto analysis |
| `keystore-dumper.js` | Dump Android Keystore contents | Key management audit |
| `encryption-at-rest-checker.js` | Check encryption of stored data | Data protection audit |

### 5. Data Storage
| Script | Purpose | Applicable When |
|--------|---------|-----------------|
| `sqlite-dumper.js` | Dump SQLite database contents | Database analysis |
| `sqlite-hook.js` | Hook SQLite operations | SQL injection testing |
| `shared-prefs-dumper.js` | Dump SharedPreferences | Storage audit |
| `sharedprefs-hook.js` | Hook SharedPreferences read/write | Storage monitoring |
| `insecure-storage-dumper.js` | Find and dump insecure storage | Storage audit |
| `clipboard-hook.js` | Hook clipboard operations | Clipboard monitoring |
| `clipboard-monitor.js` | Monitor clipboard content changes | Clipboard audit |

### 6. IPC & Component Abuse
| Script | Purpose | Applicable When |
|--------|---------|-----------------|
| `intent-hook.js` | Hook Intent creation and dispatch | Intent analysis |
| `intent-redirect.js` | Test for intent redirect vulnerabilities | Component testing |
| `intent-filter-analyzer.js` | Analyze intent filter configurations | Manifest audit |
| `content-provider-hook.js` | Hook ContentProvider operations | Provider testing |
| `ipc-abuse-helper.js` | Test IPC abuse vectors | IPC security audit |

### 7. Biometrics & Authentication
| Script | Purpose | Applicable When |
|--------|---------|-----------------|
| `biometric-bypass.js` | Bypass BiometricPrompt authentication | Biometric auth present |
| `device-lock-bypass.js` | Bypass KeyguardManager/device lock | Lock screen checks |
| `gesture-lock-tester.js` | Test gesture/pattern lock | Pattern lock testing |

### 8. Dynamic Code Loading & Class Analysis
| Script | Purpose | Applicable When |
|--------|---------|-----------------|
| `class-loader-analyzer.js` | Analyze ClassLoader usage | Dynamic loading |
| `dynamic-loading-analyzer.js` | Monitor DEX loading at runtime | DEX loading |
| `dexdump.js` | Dump DEX files from memory | DEX extraction |
| `method-tracer.js` | Trace method calls | Method analysis |
| `comprehensive-tracer.js` | Comprehensive method tracing | Deep analysis |
| `android-constructors-hook.js` | Hook object constructors | Object lifecycle |

### 9. WebView & JavaScript
| Script | Purpose | Applicable When |
|--------|---------|-----------------|
| `webview-debug.js` | Enable WebView debugging | WebView testing |
| `webview-hook.js` | Hook WebView operations | WebView audit |
| `android-argument-manipulation.js` | Manipulate WebView arguments | WebView injection |

### 10. Native/JNI
| Script | Purpose | Applicable When |
|--------|---------|-----------------|
| `jni-tracer.js` | Trace JNI native calls | Native code analysis |
| `native-heap-tracer.js` | Monitor native heap allocations | Memory analysis |
| `android-native-wrapper.js` | Wrap native function calls | Native interaction |
| `native-wrapper.js` | Generic native function wrapper | Native code audit |
| `packer-unpacker.js` | Unpack packed APKs | Packer detection |
| `rop-gadget-finder.js` | Find ROP gadgets in memory | Exploit dev |

### 11. Memory & Process
| Script | Purpose | Applicable When |
|--------|---------|-----------------|
| `memory-scanner.js` | Scan memory for sensitive patterns | Secrets in memory |
| `mem-layout-viewer.js` | View memory layout | Memory analysis |
| `uaf-detector.js` | Detect use-after-free | Vuln analysis |
| `android-early-instrumentation.js` | Early process instrumentation | Early analysis |

### 12. Runtime Behavior
| Script | Purpose | Applicable When |
|--------|---------|-----------------|
| `android-early-instrumentation.js` | Early instrumentation hooks | Process startup |
| `dynamic-code-analysis.js` | Monitor dynamic code execution | Runtime analysis |
| `test-universal-script.js` | Universal hooking script | General testing |
| `android-argument-manipulation.js` | Manipulate function arguments | Argument fuzzing |

### 13. Location & Sensors
| Script | Purpose | Applicable When |
|--------|---------|-----------------|
| `location-leak-detector.js` | Detect location data leakage | Location audit |
| `mediaprojection-bypass.js` | Bypass MediaProjection restrictions | Screen capture testing |

### 14. Permission & Runtime
| Script | Purpose | Applicable When |
|--------|---------|-----------------|
| `permission-tracker.js` | Track permission requests | Permission audit |
| `runtime-permission-bypass.js` | Bypass runtime permission requests | Permission bypass |
| `foreground-service-check.js` | Check foreground service usage | Service audit |

### 15. Debugging & Logging
| Script | Purpose | Applicable When |
|--------|---------|-----------------|
| `logging-interceptor.js` | Intercept all logging calls | Log analysis |
| `logging-hook.js` | Hook logging functions | Log audit |
| `android-early-instrumentation.js` | Early process hooks | Process analysis |
| `haptic-feedback-interceptor.js` | Intercept haptic feedback | UI analysis |
| `keyboard-cache-checker.js` | Check keyboard cache | Input audit |

### 16. Cross-Platform (Flutter/React Native)
| Script | Purpose | Applicable When |
|--------|---------|-----------------|
| `flutter-channel-hook.js` | Hook Flutter MethodChannel calls | Flutter app |
| `react-native-bridge.js` | Hook React Native bridge | RN app |
