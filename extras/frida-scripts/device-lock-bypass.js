/**
 * device-lock-bypass.js
 * Bypass screen lock, keyguard, and device admin restrictions
 *
 * Usage: frida -U -f <package> -l device-lock-bypass.js --no-pause
 */

'use strict';

console.log('[lock-bypass] Device lock bypass loaded');

Java.perform(function () {
    // ─── KeyguardManager bypass ────────────────────────
    try {
        var KeyguardManager = Java.use('android.app.KeyguardManager');
        KeyguardManager.isKeyguardLocked.implementation = function () {
            console.log('[lock-bypass] isKeyguardLocked -> false');
            return false;
        };
        KeyguardManager.isDeviceLocked.implementation = function () {
            console.log('[lock-bypass] isDeviceLocked -> false');
            return false;
        };
        KeyguardManager.isDeviceSecure.implementation = function () {
            console.log('[lock-bypass] isDeviceSecure -> false');
            return false;
        };
        KeyguardManager.getInstalledProviders.overload().implementation = function () {
            console.log('[lock-bypass] getInstalledProviders -> empty');
            var ArrayList = Java.use('java.util.ArrayList');
            return ArrayList.$new();
        };
    } catch (e) {}

    // ─── DevicePolicyManager bypass ────────────────────
    try {
        var DPM = Java.use('android.app.admin.DevicePolicyManager');
        DPM.isAdminActive.implementation = function (who) {
            console.log('[lock-bypass] isAdminActive -> false');
            return false;
        };
        DPM.isDeviceOwnerApp.implementation = function (packageName) {
            console.log('[lock-bypass] isDeviceOwnerApp(' + packageName + ') -> false');
            return false;
        };
        DPM.isProfileOwnerApp.implementation = function (packageName) {
            console.log('[lock-bypass] isProfileOwnerApp(' + packageName + ') -> false');
            return false;
        };
        DPM.getCameraDisabled.implementation = function (who) {
            return false;
        };
        DPM.getScreenCaptureDisabled.implementation = function (who) {
            return false;
        };
        DPM.getKeyguardDisabledFeatures.implementation = function (who) {
            return 0;
        };
    } catch (e) {}

    // ─── Window flag bypass ────────────────────────────
    try {
        var Window = Java.use('android.view.Window');
        Window.setFlags.overload('int', 'int').implementation = function (flags, mask) {
            // Remove FLAG_DISMISS_KEYGUARD, FLAG_SHOW_WHEN_LOCKED, FLAG_TURN_SCREEN_ON
            var cleanFlags = flags & ~(0x00400000 | 0x00800000 | 0x20000000);
            return this.setFlags(cleanFlags, mask);
        };
    } catch (e) {}

    // ─── Activity lock bypass ──────────────────────────
    try {
        var Activity = Java.use('android.app.Activity');
        Activity.setShowWhenLocked.implementation = function (showWhenLocked) {
            console.log('[lock-bypass] setShowWhenLocked -> true');
            return this.setShowWhenLocked(true);
        };
        Activity.setTurnScreenOn.implementation = function (turnScreenOn) {
            console.log('[lock-bypass] setTurnScreenOn -> true');
            return this.setTurnScreenOn(true);
        };
    } catch (e) {}

    console.log('[lock-bypass] All bypasses installed');
});
