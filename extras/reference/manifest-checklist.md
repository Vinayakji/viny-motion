# AndroidManifest.xml Security Checklist
> Version: 1.0 | Last Updated: 2026-09-01

## Quick Reference

| Field | Secure | Risk |
|-------|--------|------|
| `android:debuggable` | `false` | Code execution, data theft |
| `android:allowBackup` | `false` | Backup extraction |
| `android:exported` | `false` (default) | Unauthorized component access |
| `android:networkSecurityConfig` | Custom config | Cleartext traffic |
| `android:usesCleartextTraffic` | `false` | MITM attacks |
| `android:largeHeap` | `false` (default) | Memory analysis ease |
| `android:allowTaskReparenting` | `false` | Task hijacking |
| `android:launchMode` | `standard` | Intent redirect |

## Permissions Risk Matrix

| Permission | Risk | Abuse Vector |
|------------|------|-------------|
| `INTERNET` | LOW | Network exfil |
| `CAMERA` | HIGH | Spyware |
| `RECORD_AUDIO` | HIGH | Eavesdropping |
| `READ_CONTACTS` | HIGH | Contact theft |
| `READ_SMS` | HIGH | 2FA bypass |
| `SEND_SMS` | HIGH | Premium SMS fraud |
| `READ_PHONE_STATE` | MEDIUM | Device fingerprinting |
| `READ_CALL_LOG` | HIGH | Call history theft |
| `ACCESS_FINE_LOCATION` | HIGH | Tracking |
| `ACCESS_COARSE_LOCATION` | MEDIUM | Approximate location |
| `CALL_PHONE` | MEDIUM | Toll fraud |
| `RECEIVE_BOOT_COMPLETED` | MEDIUM | Persistence |
| `SYSTEM_ALERT_WINDOW` | HIGH | Overlay attack |
| `REQUEST_INSTALL_PACKAGES` | HIGH | Sideloading |
| `WRITE_EXTERNAL_STORAGE` | MEDIUM | Data manipulation |
| `READ_EXTERNAL_STORAGE` | MEDIUM | Data theft |
| `POST_NOTIFICATIONS` | LOW | Notification phishing |
| `AD_ID` | LOW | Advertising tracking |
| `WAKE_LOCK` | LOW | Battery drain |

## Deep Link Security

| Check | What | Risk |
|-------|------|------|
| `android:scheme` | Custom scheme (e.g., `lmtl://`) | Intent hijack |
| `android:host` | Wildcard host | Open redirect |
| `android:pathPrefix` | `/*` | Overly broad |
| `android:autoVerify` | `false` or missing | No verification |

### Deep Link Validation Checklist
- [ ] No wildcard hosts (`*`)
- [ ] `android:autoVerify="true"` set
- [ ] `intent-filter` on exported activities only
- [ ] Input validation on deep link data
- [ ] No sensitive data in deep link parameters

## Exported Component Checklist

| Component | Should Be Exported? | Notes |
|-----------|---------------------|-------|
| `MainActivity` | Usually yes | Check intent-filter |
| `LoginActivity` | Usually yes | Check deep links |
| `SettingsActivity` | Usually no | Should be private |
| `BroadcastReceiver` | Depends | Check `permission` attr |
| `Service` | Depends | Check `permission` attr |
| `ContentProvider` | Depends | Check `grantUriPermissions` |

### Exported Component Audit
- [ ] All exported activities have `android:permission` if sensitive
- [ ] No activities exported without intent-filters
- [ ] All `intent-filter` declarations reviewed
- [ ] `android:exported` explicitly set (not relying on defaults)

## Content Provider Security

| Check | Pattern | Risk |
|-------|---------|------|
| `android:authorities` | Dynamic/unique | Authority conflict |
| `android:grantUriPermissions` | `true` | URI permission leak |
| `android:permission` | Missing | Unauthorized access |
| `android:readPermission` | Missing | Data read |
| `android:writePermission` | Missing | Data write |

## Network Security Config

```xml
<!-- Recommended config structure -->
<network-security-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">example.com</domain>
        <pin-set>
            <pin digest="SHA-256">base64==</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

### Network Config Checklist
- [ ] `cleartextTrafficPermitted="false"` for all domains
- [ ] Pin-set configured for sensitive endpoints
- [ ] No `trust-anchors` with user certificates in production
- [ ] Debug overrides removed from production builds

## Permission Group Risk Summary

| Group | Risk | Mitigation |
|-------|------|-----------|
| `STORAGE` | MEDIUM | Encrypt stored data |
| `LOCATION` | HIGH | Minimize retention |
| `PHONE` | MEDIUM | Justify necessity |
| `CONTACTS` | HIGH | Encrypt at rest |
| `CALENDAR` | MEDIUM | Access controls |
| `CAMERA` | HIGH | User consent |
| `MICROPHONE` | HIGH | User consent |
| `SENSORS` | LOW | Minimize usage |
| `SMS` | HIGH | Avoid if possible |
| `PHONE_CALLS` | MEDIUM | Justify necessity |
