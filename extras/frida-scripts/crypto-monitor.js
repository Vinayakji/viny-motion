// crypto-monitor.js — Hook javax.crypto.Cipher, KeyGenerator, SecretKeySpec, IvParameterSpec, Mac
// Detects: ECB mode, weak algorithms (DES/RC4/Blowfish), hardcoded keys, IV reuse

Java.perform(function() {
    var Tag = "CRYPTO_MONITOR";

    // Track cipher usage
    var Cipher = Java.use("javax.crypto.Cipher");
    var seenIVs = {};
    var weakAlgos = ["DES", "DESede", "Blowfish", "RC4", "RC4_40", "ARCFOUR", "HmacMD5", "HmacSHA1"];

    Cipher.getInstance.overload("java.lang.String").implementation = function(transformation) {
        var algo = transformation.toUpperCase();
        send({type: "crypto", action: "Cipher.getInstance", transformation: transformation});

        // Check for ECB mode
        if (algo.includes("/ECB/") || (!algo.includes("/") && !algo.includes("ECB") === false)) {
            send({type: "crypto_vuln", vuln: "ECB_MODE", transformation: transformation});
            console.log("[!] ECB mode detected: " + transformation);
        }

        // Check for weak algorithms
        for (var i = 0; i < weakAlgos.length; i++) {
            if (algo.includes(weakAlgos[i])) {
                send({type: "crypto_vuln", vuln: "WEAK_ALGO", algorithm: weakAlgos[i], transformation: transformation});
                console.log("[!] Weak algorithm: " + weakAlgos[i] + " in " + transformation);
            }
        }

        return this.getInstance(transformation);
    };

    Cipher.getInstance.overload("java.lang.String", "java.lang.String").implementation = function(transformation, provider) {
        send({type: "crypto", action: "Cipher.getInstance", transformation: transformation, provider: provider});
        return this.getInstance(transformation, provider);
    };

    Cipher.init.overload("int", "java.security.Key").implementation = function(mode, key) {
        var keyBytes = key.getEncoded();
        var keyHex = bytesToHex(keyBytes);
        send({type: "crypto", action: "Cipher.init", mode: mode, keyHex: keyHex, keySize: keyBytes.length * 8});

        // Check for hardcoded/short keys
        if (keyBytes.length <= 8) {
            send({type: "crypto_vuln", vuln: "SHORT_KEY", keySize: keyBytes.length * 8, keyHex: keyHex});
            console.log("[!] Short key detected: " + (keyBytes.length * 8) + " bits");
        }

        return this.init(mode, key);
    };

    // Track IVs
    var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
    IvParameterSpec.$init.overload("[B").implementation = function(iv) {
        var ivHex = bytesToHex(iv);
        send({type: "crypto", action: "IvParameterSpec", ivHex: ivHex, ivSize: iv.length});

        // Check IV reuse
        if (seenIVs[ivHex]) {
            send({type: "crypto_vuln", vuln: "IV_REUSE", ivHex: ivHex});
            console.log("[!] IV reuse detected: " + ivHex);
        }
        seenIVs[ivHex] = true;

        // Check for null/zero IV
        if (iv.length === 0 || iv.every(function(b) { return b === 0; })) {
            send({type: "crypto_vuln", vuln: "NULL_IV", ivHex: ivHex});
            console.log("[!] Null/zero IV detected");
        }

        return this.$init(iv);
    };

    // Hook Mac for HMAC analysis
    var Mac = Java.use("javax.crypto.Mac");
    Mac.getInstance.overload("java.lang.String").implementation = function(algorithm) {
        send({type: "crypto", action: "Mac.getInstance", algorithm: algorithm});
        return this.getInstance(algorithm);
    };

    // SecretKeySpec — detect hardcoded keys
    var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function(key, algorithm) {
        var keyHex = bytesToHex(key);
        send({type: "crypto", action: "SecretKeySpec", algorithm: algorithm, keyHex: keyHex, keySize: key.length * 8});
        return this.$init(key, algorithm);
    };

    // Helper
    function bytesToHex(bytes) {
        if (!bytes) return "null";
        var hex = "";
        for (var i = 0; i < Math.min(bytes.length, 64); i++) {
            var b = (bytes[i] & 0xFF).toString(16);
            hex += (b.length < 2 ? "0" : "") + b;
        }
        if (bytes.length > 64) hex += "...(" + bytes.length + " bytes)";
        return hex;
    }

    console.log("[*] Crypto monitor loaded");
});
