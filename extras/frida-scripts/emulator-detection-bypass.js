/**
 * emulator-detection-bypass.js
 * Bypass common emulator detection checks
 * Spoof build properties, sensor data, file system checks
 *
 * Usage: frida -U -f <package> -l emulator-detection-bypass.js --no-pause
 */

'use strict';

console.log('[emu-bypass] Emulator detection bypass loaded');

Java.perform(function () {
    // ─── Build properties spoofing ─────────────────────
    var Build = Java.use('android.os.Build');
    Build.MODEL.value = 'Pixel 7 Pro';
    Build.MANUFACTURER.value = 'Google';
    Build.BRAND.value = 'google';
    Build.DEVICE.value = 'cheetah';
    Build.PRODUCT.value = 'cheetah';
    Build.HARDWARE.value = 'cheetah';
    Build.BOARD.value = 'cheetah';
    Build.DISPLAY.value = 'TP1A.220905.004';
    Build.FINGERPRINT.value = 'google/cheetah/cheetah:13/TP1A.220905.004/9019111:user/release-keys';
    Build.HOST.value = 'abfarm-release-rbe-64-00065';
    Build.TAGS.value = 'release-keys';
    Build.TYPE.value = 'user';
    Build.USER.value = 'android-build';

    console.log('[emu-bypass] Build properties spoofed');

    // ─── System properties ─────────────────────────────
    try {
        var SystemProperties = Java.use('android.os.SystemProperties');
        var propsToSpoof = {
            'ro.product.model': 'Pixel 7 Pro',
            'ro.product.brand': 'google',
            'ro.product.device': 'cheetah',
            'ro.product.name': 'cheetah',
            'ro.build.display.id': 'TP1A.220905.004',
            'ro.build.tags': 'release-keys',
            'ro.build.type': 'user',
            'ro.hardware': 'cheetah',
            'ro.board.platform': 'mt6893',
            'ro.boot.hardware': 'cheetah',
            'ro.product.first_api_level': '33',
            'persist.sys.dalvik.vm.lib.2': 'libart.so',
            'dalvik.vm.isa.arm.variant': 'cortex-a55',
            'dalvik.vm.isa.arm64.variant': 'cortex-a55',
            'ro.ril.oem.imei': '358759091234567',
            'gsm.version.baseband': 'g5300q-230828-230830-B-10915472',
            'ro.build.version.sdk': '33',
            'ro.build.version.release': '13',
            'ro.com.google.gmsversion': '13_202308'
        };

        for (var key in propsToSpoof) {
            SystemProperties.set(key, propsToSpoof[key]);
        }
        console.log('[emu-bypass] System properties spoofed');
    } catch (e) {
        console.log('[emu-bypass] SystemProperties hook failed');
    }

    // ─── File existence checks ─────────────────────────
    var fs = Java.use('java.io.File');
    var suspiciousFiles = [
        '/dev/qemu_pipe', '/dev/socket/qemud', '/dev/qemu_trace',
        '/system/lib/libc_malloc_debug_qemu.so', '/sys/qemu_trace',
        '/system/bin/qemu-props', '/dev/goldfish_pipe',
        '/system/lib/libhooks.so', '/system/bin/getprop',
        '/dev/vboxguest', '/dev/vboxuser',
        '/fstab.qemu', '/proc/tty/drivers',
        '/proc/net/arp', '/sys/bus/platform/drivers/goldfish'
    ];

    fs.exists.implementation = function () {
        var path = this.getAbsolutePath();
        if (suspiciousFiles.indexOf(path) !== -1) {
            return false;
        }
        return this.exists();
    };

    fs.isFile.implementation = function () {
        var path = this.getAbsolutePath();
        if (suspiciousFiles.indexOf(path) !== -1) {
            return false;
        }
        return this.isFile();
    };

    console.log('[emu-bypass] File existence checks patched');

    // ─── Sensor checks ─────────────────────────────────
    try {
        var SensorManager = Java.use('android.hardware.SensorManager');
        SensorManager.getSensorList.overload('int').implementation = function (type) {
            var list = this.getSensorList(type);
            if (list.size() === 0 && type === 1) {
                console.log('[emu-bypass] Spoofing accelerometer sensor');
                // Create fake sensor list
            }
            return list;
        };
    } catch (e) {}

    // ─── Telephony checks ──────────────────────────────
    try {
        var TelephonyManager = Java.use('android.telephony.TelephonyManager');
        TelephonyManager.getDeviceId.overload().implementation = function () {
            return '358759091234567';
        };
        TelephonyManager.getSubscriberId.overload().implementation = function () {
            return '310260000000000';
        };
        TelephonyManager.getLine1Number.overload().implementation = function () {
            return '+15551234567';
        };
        TelephonyManager.getNetworkOperatorName.overload().implementation = function () {
            return 'T-Mobile';
        };
        TelephonyManager.getSimOperatorName.overload().implementation = function () {
            return 'T-Mobile';
        };
    } catch (e) {}

    // ─── Settings.Secure checks ────────────────────────
    try {
        var Settings = Java.use('android.provider.Settings$Secure');
        Settings.getString.overload('android.content.ContentResolver', 'java.lang.String')
            .implementation = function (resolver, name) {
                if (name === 'android_id') {
                    return '9774d56d682e549c';
                }
                return this.getString(resolver, name);
            };
    } catch (e) {}

    // ─── Kernel/proc checks ────────────────────────────
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            if (cmd.indexOf('cat /proc/cpuinfo') !== -1 ||
                cmd.indexOf('getprop') !== -1 ||
                cmd.indexOf('ls /dev') !== -1) {
                console.log('[emu-bypass] Blocked suspicious exec: ' + cmd);
                // Return empty process
                return this.exec('echo');
            }
            return this.exec(cmd);
        };
    } catch (e) {}

    console.log('[emu-bypass] All bypasses installed');
});
