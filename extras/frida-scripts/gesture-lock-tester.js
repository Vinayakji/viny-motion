/**
 * gesture-lock-tester.js
 * Test gesture/pattern lock implementations
 * Monitor pattern input and verify pattern storage
 *
 * Usage: frida -U -f <package> -l gesture-lock-tester.js --no-pause
 */

'use strict';

console.log('[gl] Gesture lock tester loaded');

var gestureOps = [];

Java.perform(function () {
    // ─── LockPatternView ───────────────────────────────
    try {
        var LockPatternView = Java.use('com.android.internal.widget.LockPatternView');
        LockPatternView.setPattern.overload('int', 'java.util.List').implementation = function (displayMode, pattern) {
            console.log('[gl] Pattern set: ' + pattern.size() + ' dots');
            gestureOps.push({ type: 'setPattern', size: pattern.size(), timestamp: Date.now() });
            return this.setPattern(displayMode, pattern);
        };

        LockPatternView.checkPattern.overload('java.util.List').implementation = function (pattern) {
            console.log('[gl] Pattern check: ' + pattern.size() + ' dots');
            gestureOps.push({ type: 'checkPattern', size: pattern.size(), timestamp: Date.now() });
            return this.checkPattern(pattern);
        };
    } catch (e) {}

    // ─── LockPatternUtils ──────────────────────────────
    try {
        var LockPatternUtils = Java.use('com.android.internal.widget.LockPatternUtils');
        LockPatternUtils.checkPattern.overload('[B').implementation = function (pattern) {
            console.log('[gl] LockPatternUtils.checkPattern called');
            return this.checkPattern(pattern);
        };

        LockPatternUtils.saveLockPattern.overload('java.util.List').implementation = function (pattern) {
            console.log('[gl] Pattern saved: ' + pattern.size() + ' dots');
            gestureOps.push({ type: 'savePattern', size: pattern.size(), timestamp: Date.now() });
            return this.saveLockPattern(pattern);
        };
    } catch (e) {}

    // ─── BiometricPrompt (fallback) ────────────────────
    try {
        var BiometricPrompt = Java.use('androidx.biometric.BiometricPrompt');
        BiometricPrompt.authenticate.implementation = function (cryptoObject) {
            console.log('[gl] BiometricPrompt.authenticate (fallback to gesture)');
            gestureOps.push({ type: 'biometricFallback', timestamp: Date.now() });
        };
    } catch (e) {}

    // ─── PIN/Password input ────────────────────────────
    try {
        var PasswordTextView = Java.use('com.android.internal.widget.PasswordTextView');
        PasswordTextView.append.overload('java.lang.CharSequence').implementation = function (text) {
            console.log('[gl] PIN input: ' + text.length() + ' chars');
            gestureOps.push({ type: 'pinInput', length: text.length(), timestamp: Date.now() });
            return this.append(text);
        };
    } catch (e) {}

    console.log('[gl] All hooks installed');
});

function gestureReport() {
    console.log('\n[gl] === Gesture Lock Report ===');
    console.log('[gl] Total operations: ' + gestureOps.length);
    gestureOps.forEach(function (op) {
        console.log('[gl]   ' + op.type + ': ' + (op.size || op.length || ''));
    });
    console.log('[gl] === End ===\n');
}

console.log('[gl] Functions: gestureReport()');
console.log('[gl] Loaded');
