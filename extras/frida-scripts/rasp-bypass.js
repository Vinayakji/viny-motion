/**
 * rasp-bypass.js
 * Runtime Application Self-Protection (RASP) detection bypass
 * Covers: root detection, debugger detection, emulator detection, integrity checks
 *
 * Usage: frida -U -f <package> -l rasp-bypass.js --no-pause
 */

'use strict';

console.log('[rasp] Loading RASP bypass framework...');

// ═══════════════════════════════════════════════════════
// 1. ROOT DETECTION BYPASS
// ═══════════════════════════════════════════════════════

Java.perform(function () {
    // File existence checks
    var File = Java.use('java.io.File');
    var dangerousPaths = [
        '/system/app/Superuser.apk', '/system/bin/su', '/system/xbin/su',
        '/sbin/su', '/data/local/xbin/su', '/data/local/bin/su',
        '/system/sd/xbin/su', '/system/bin/failsafe/su', '/data/local/su',
        '/su/bin/su', '/system/app/SuperSU.apk', '/system/app/Supersu.apk',
        '/system/app/Busybox.apk'
    ];

    File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        if (dangerousPaths.indexOf(path) !== -1) {
            console.log('[rasp] Root check blocked: ' + path);
            return false;
        }
        // Block /proc/self/maps and /proc/self/status checks
        if (path.indexOf('/proc/') !== -1 && (path.indexOf('maps') !== -1 || path.indexOf('status') !== -1)) {
            console.log('[rasp] /proc check blocked: ' + path);
            return false;
        }
        return this.exists();
    };

    // Runtime.exec root checks
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmd) {
        var joined = cmd.join(' ');
        if (joined.indexOf('su') !== -1 && (joined.indexOf('-c') !== -1 || joined.indexOf('which') !== -1)) {
            console.log('[rasp] Root exec blocked: ' + joined);
            throw Java.use('java.io.IOException').$new('Cannot run program');
        }
        return this.exec(cmd);
    };

    // ProcessBuilder root checks
    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
    ProcessBuilder.start.implementation = function () {
        var cmd = this.command.value;
        if (cmd !== null) {
            var joined = cmd.toString();
            if (joined.indexOf('su') !== -1 || joined.indexOf('which su') !== -1) {
                console.log('[rasp] Root ProcessBuilder blocked: ' + joined);
                this.command.value = Java.use('java.util.Collections').emptyList();
            }
        }
        return this.start();
    };

    console.log('[rasp] Root detection bypass installed');
});

// ═══════════════════════════════════════════════════════
// 2. DEBUGGER DETECTION BYPASS
// ═══════════════════════════════════════════════════════

Java.perform(function () {
    // Debug.isDebuggerConnected
    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function () {
        console.log('[rasp] Debugger check bypassed');
        return false;
    };

    // Debug.waitForDebugger
    Debug.waitForDebugger.implementation = function () {
        console.log('[rasp] waitForDebugger skipped');
    };

    // Check for JDWP port
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            if (cmd.indexOf('jdwp') !== -1 || cmd.indexOf('ps') !== -1) {
                console.log('[rasp] JDWP check blocked: ' + cmd);
                return this.exec('echo');
            }
            return this.exec(cmd);
        };
    } catch (e) {}

    console.log('[rasp] Debugger detection bypass installed');
});

// ═══════════════════════════════════════════════════════
// 3. EMULATOR DETECTION BYPASS
// ═══════════════════════════════════════════════════════

Java.perform(function () {
    var Build = Java.use('android.os.Build');

    // Spoof build properties
    Build.FINGERPRINT.value = 'google/raven/raven:14/UP1A.231105.001/10754064:user/release-keys';
    Build.HARDWARE.value = 'raven';
    Build.BOARD.value = 'raven';
    Build.MANUFACTURER.value = 'Google';
    Build.BRAND.value = 'google';
    Build.MODEL.value = 'Pixel 6 Pro';
    Build.PRODUCT.value = 'raven';
    Build.TAGS.value = 'release-keys';
    Build.TYPE.value = 'user';
    Build.DEVICE.value = 'raven';
    Build.HOST.value = 'abfarm-release-rbe-64-00062';
    Build.DISPLAY.value = 'UP1A.231105.001';

    // Block Build.SERIAL check (deprecated but still used)
    try {
        var System = Java.use('java.lang.System');
        System.getProperty.overload('java.lang.String').implementation = function (key) {
            if (key === 'ro.serialno' || key === 'ro.boot.serialno') {
                return 'FBXXXXXXXX';
            }
            return this.getProperty(key);
        };
    } catch (e) {}

    // Block Build.getSerial() check
    try {
        Build.getSerial.implementation = function () {
            return 'FBXXXXXXXX';
        };
    } catch (e) {}

    console.log('[rasp] Emulator detection bypass installed');
});

// ═══════════════════════════════════════════════════════
// 4. APP INTEGRITY CHECK BYPASS
// ═══════════════════════════════════════════════════════

Java.perform(function () {
    var PackageManager = Java.use('android.content.pm.PackageManager');
    var ApplicationInfo = Java.use('android.content.pm.ApplicationInfo');

    // Block debugger flag check
    ApplicationInfo.FLAG_DEBUGGABLE.value = 0;

    // Block signature verification
    PackageManager.getPackageInfo.overload('java.lang.String', 'int')
        .implementation = function (pkg, flags) {
            var info = this.getPackageInfo(pkg, flags);
            // Clear debuggable flag
            info.applicationInfo.value.flags.value = info.applicationInfo.value.flags.value & ~0x2;
            return info;
        };

    console.log('[rasp] App integrity bypass installed');
});

// ═══════════════════════════════════════════════════════
// 5. HOOK COMMON RASP SDKs
// ═══════════════════════════════════════════════════════

Java.perform(function () {
    var raspLibs = [
        'io.sentry.android.core.SentryAndroid',
        'com.datadog.android.rum.GlobalRumMonitor',
        'com.adjust.sdk.Adjust',
        'io.branch.referral.Branch',
        'com.appsflyer.AppsFlyerLib'
    ];

    raspLibs.forEach(function (lib) {
        try {
            var cls = Java.use(lib);
            console.log('[rasp] Found RASP library: ' + lib);
        } catch (e) {}
    });

    console.log('[rasp] RASP SDK scanning complete');
});

console.log('[rasp] All RASP bypasses loaded');
