# Required Skills Map — Android Testing

Maps the skill catalog to each pipeline phase so a tester loads the right methodology.
Skills live in `~/.config/opencode/skills/` (load via the `skill` tool) — they are the
knowledge layer; the phase scripts are the automation.

## Core (every Android engagement)

| Skill | When |
|-------|------|
| `android-pentesting-tricks` | general Android testing, SSL pinning, WebView, root bypass |
| `apk-redteam-pipeline` | APK acquisition → decompile → secrets → Frida → endpoints |
| `mobile-dynamic-analysis` | rooted emulator/device setup, Frida/Objection, proxy chains |
| `mobile-ssl-pinning-bypass` | bypass cert pinning on Android/iOS |
| `android-new-android-attacks` | Android 14/15/16 (API 34/35/36) specific surface |
| `bb-hunt-mobile-testing` | bug-bounty mobile methodology |

## By pipeline phase

| Phase | Required skills |
|-------|-----------------|
| **00 acquire** | `apk-redteam-pipeline` |
| **01 static / SAST** | `android-attack-surface-classification`, `android-app-bundle-analysis`, `mobile-binary-protection`, `android-exploit-mitigations` |
| **02 emulator setup** | `android-emulator-detection-bypass`, `android-kernel-rooting-strategies`, `mobile-dynamic-analysis`, `android-automated-security-testing` |
| **03 drozer** | `android-intent-ipc-security`, `android-content-provider-deep` |
| **03b drozer MCP** | `android-intent-ipc-security`, `android-content-provider-deep` |
| **04 objection** | `mobile-dynamic-analysis`, `android-pentesting-tricks`, `mobile-ssl-pinning-bypass` |
| **05 frida hooks** | `android-pentesting-tricks`, `mobile-ssl-pinning-bypass`, `android-rasp-anti-tamper-bypass`, `android-zygote-process-security` |
| **06 traffic / Burp** | `android-network-security-deep`, `mobile-api-security` |
| **07 deep links** | `android-deep-link-attacks`, `android-intent-ipc-security` |
| **07 storage dump** | `android-storage-crypto-security`, `android-forensics-artifacts`, `android-fbe-encryption-forensics` |
| **09 mobsf / DAST** | `android-automated-security-testing` |
| **10 backup extract** | `android-forensics-artifacts`, `android-storage-crypto-security` |
| **11 webview** | `android-webview-deep-security`, `android-pentesting-tricks` |
| **12 pending intent** | `android-intent-ipc-security`, `android-zygote-process-security` |
| **13 resilience** | `android-rasp-anti-tamper-bypass`, `android-emulator-detection-bypass`, `android-play-integrity-attestation` |
| **14 crypto audit** | `android-storage-crypto-security`, `android-fbe-encryption-forensics` |
| **16 code analysis** | `android-systems-deep`, `mobile-binary-protection`, `android-zygote-process-security` |
| **17 input validation** | `injection-checking`, `api-sec`, `android-firebase-mobile` |
| **18 dastforge (API)** | `sqli-sql-injection`, `xss-cross-site-scripting`, `ssrf-server-side-request-forgery`, `cmdi-command-injection`, `ssti-server-side-template-injection`, `idor-broken-object-authorization`, `api-authorization-and-bola`, `api-auth-and-jwt-abuse`, `nosql-injection`, `path-traversal-lfi`, `open-redirect`, `graphql-and-hidden-parameters` |
| **19 rasp bypass** | `android-rasp-anti-tamper-bypass`, `android-play-integrity-attestation`, `android-emulator-detection-bypass` |

## Cross-platform apps (React Native / Flutter)

| Framework | Skill |
|-----------|-------|
| React Native | `react-native-security` |
| Flutter | `flutter-security` |

## App-type focused

| Target type | Skill |
|-------------|-------|
| Firebase backend | `android-firebase-mobile` |
| Payments / UPI | `android-payment-sdk-security`, `android-nfc-hce-attacks` |
| NFC / Fastag | `android-nfc-hce-attacks` |
| Device fingerprinting / anti-fraud | `android-device-fingerprinting-fraud` |
| Enterprise / MDM | `android-enterprise-mdm-security` |
| On-device AI/ML | `android-ondevice-ai-ml-security` |

## Deep / advanced (as needed)

| Area | Skill |
|------|-------|
| ADB abuse | `android-adb-attacks` |
| USB / physical | `android-usb-physical-attacks` |
| Accessibility overlay | `android-accessibility-overlay-attacks` |
| Radio/baseband | `android-radio-interface-attacks` |
| ROP on ARM | `android-rop-arm` |
| Tombstone analysis | `android-tombstone-forensics` |
| Root history / legacy | `android-root-history` |
| Firmware extraction | `android-firmware-extraction` |