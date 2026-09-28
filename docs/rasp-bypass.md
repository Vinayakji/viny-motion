# RASP Bypass — Comprehensive Methodology

Runtime Application Self-Protection (RASP) defends a running app against tampering,
instrumentation, root and repackaging. This guide covers the full bypass process used by
phase `19_rasp_bypass`. **Validating a confirmed bypass requires a real rooted device** —
the emulator can only exercise the emulator-viable vectors (see caveats below).

## 1. Fingerprint the RASP solution

Identify which protection is embedded (from decompiled source + assets):

| SDK | Grep markers |
|-----|--------------|
| Promon SHIELD | `promon`, `shield`, `com.promon` |
| Guardsquare DexGuard / RASP | `dexguard`, `guardsquare`, `com.guardsquare` |
| CrowdStrike Falcon | `falcon`, `crowdstrike`, `SspSdk` |
| Zimperium zShield | `zimperium`, `zshield`, `zDefender` |
| ThreatMetrix | `threatmetrix`, `threatmatrix`, `tmsdk` |
| SafetyNet / Play Integrity | `safetynet`, `play.integrity`, `MEETS_DEVICE` |
| Custom | grep for detection APIs below |

## 2. Detection vectors RASP uses (and where to hook)

| Vector | Detection API / technique |
|--------|---------------------------|
| **Root** | `su` binary existence, `which su`, `RootBeer`, `Magisk`, `/system/xbin/su`, mount check, `TestForRoot`, `SELinux`, `getPackageInfo` of root apps |
| **Emulator** | `Build.FINGERPRINT/MODEL/DEVICE/HARDWARE/PRODUCT`, `ro.kernel.qemu`, `goldfish`, `ranchu`, `generic`, sensors, telephony (no IMEI), CPU ABI |
| **Debugger** | `Debug.isDebuggerConnected()`, `waitingForDebugger`, `TracerPid` in `/proc/self/status`, `ptrace(PTRACE_TRACEME)`, timing gaps, `android:debuggable` |
| **Frida** | `/proc/self/maps` → `frida`, `gum-js-loop`, `gadget`, `linjector`; ports `27042`/`27043`; `/data/local/tmp/frida-server`; thread names; `D-Bus` auth handshake |
| **Tamper / integrity** | signature check (`GET_SIGNATURES`/`GET_SIGNING_CERTIFICATES`), DEX/so checksum, asset hash, self-signature match, `apkSignature` |
| **Repackage** | install-source check, version pinning, update channel verification |
| **Certificate** | pinning via `TrustManager`/`NetworkSecurityConfig`, key hash compare |

## 3. Bypass approaches (by vector)

### Root detection
- **Magisk DenyList / Zygisk** — hide root from the target app (per-app hide), enable `zygisk + denyList`, use Shamiko for stronger hiding
- **Frida** (`root-bypass.js`, `rasp-bypass.js`) — override `File.exists()` for `su`, `which`, `Runtime.exec`, `RootBeer` internals, hide mount evidence
- Return **false** from all root predicates; return a clean `Build`/path set

### Emulator detection
- **Frida** (`emulator-detection-bypass.js`) — override `Build` fields to real-device values, `System.getProperty("ro.kernel.qemu")`, hide `goldfish/ranchu`, spoof telephony (`getDeviceId`), sensors, camera
- **Custom ROM / fingerprint spoof** on the emulator for closer-to-real behaviour

### Anti-debug
- **Frida** (`anti-debug.js`) — hook `Debug.isDebuggerConnected`/`waitingForDebugger` → false, neutralise `ptrace(TRACEME)` and `TracerPid` reads, close timing-gap checks
- Patch `android:debuggable` handling if the app refuses to run debuggable

### Frida detection (anti-instrumentation)
- **`android-anti-frida-countermeasures.js`** — hook the detectors: `Process.findModuleByName("frida-agent")`, `maps` scans, thread-name scans, port checks, D-Bus probes
- **Operational**: rename `frida-server`, use `frida-gadget` embedded with a custom config, disable `default` D-Bus; avoid obvious `/data/local/tmp` files; use `--runtime=v8` quirks sparingly

### Tamper / integrity
- **Frida** (`rasp-bypass.js`) — hook `PackageManager.getPackageInfo` signature calls, `MessageDigest` comparisons, `ApplicationInfo`, return the ORIGINAL signature / expected hashes
- **Static patch** (fallback): locate the integrity check in smali/DEX, NOP the branch, recompile + re-sign; must match signature logic the app verifies

### SSL pinning / MITM (feeds API testing)
- **objection**: `android sslpinning disable`
- **Frida**: override `TrustManager`, `HostnameVerifier`, `checkServerTrusted` → trust-all, `NetworkSecurityConfig` trust user certs

## 4. Bypass execution (phase 19)

```bash
# 1. Fingerprint + inventory (writes rasp-detector-report)
# 2. Deploy each bypass script against the app with frida
./extras/frida-scripts/rasp-bypass.js
./extras/frida-scripts/root-bypass.js
./extras/frida-scripts/emulator-detection-bypass.js
./extras/frida-scripts/anti-debug.js
./extras/frida-scripts/android-anti-frida-countermeasures.js
# 3. Magisk DenyList (if Magisk present)
# 4. Verify: app progresses past the protection gate (focused activity / logcat)
```

## 5. Validation & evidence

- **Success = the app reaches its normal UI/flow** that a protection gate previously blocked (compare focused activity before vs after bypass)
- Capture: frida logs, before/after screenshots, the script used, and the blocked-vs-passing activity
- **Severity:** a *confirmed* bypass = HIGH/CRITICAL. On the emulator only, mark the finding `SUSPECTED` and **confirm on a real rooted device** before reporting as confirmed (RASP's hardware/attestation checks only fail on-device).

## 6. Caveats

- RASP includes **emulator detection** — on an emulator, the app may flag the environment before app-level checks, so you're partly testing emulator-detection bypass
- **Play Integrity / hardware attestation** fails on emulators by design (no real TEE/StrongBox) — cannot be fully bypassed in emulation
- Real-device validation is mandatory for a confirmed RASP bypass finding