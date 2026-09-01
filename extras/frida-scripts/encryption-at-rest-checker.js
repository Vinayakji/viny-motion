/**
 * encryption-at-rest-checker.js
 * Check encryption at rest for app data, databases, and shared preferences
 * Detect weak encryption, hardcoded keys, and insecure storage
 *
 * Usage: frida -U -f <package> -l encryption-at-rest-checker.js --no-pause
 */

'use strict';

console.log('[ear] Encryption at rest checker loaded');

var cryptoOps = [];
var storageAccess = [];

Java.perform(function () {
    // ─── SharedPreferences ─────────────────────────────
    var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');
    SharedPreferencesImpl.getString.implementation = function (key, defValue) {
        var val = this.getString(key, defValue);
        storageAccess.push({ type: 'SharedPrefs.get', key: key, value: val ? val.substring(0, 50) : null });
        return val;
    };

    SharedPreferencesImpl.putString.implementation = function (key, value) {
        console.log('[ear] SharedPrefs.put: ' + key + ' = ' + (value ? value.substring(0, 50) : 'null'));
        storageAccess.push({ type: 'SharedPrefs.put', key: key, value: value ? value.substring(0, 50) : null });
        return this.putString(key, value);
    };

    // ─── EncryptedSharedPreferences ────────────────────
    try {
        var EncryptedSharedPrefs = Java.use('androidx.security.crypto.EncryptedSharedPreferences');
        console.log('[ear] EncryptedSharedPreferences found (good)');
    } catch (e) {
        console.log('[ear] EncryptedSharedPreferences NOT found');
    }

    // ─── SQLite databases ──────────────────────────────
    var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
    SQLiteDatabase.openOrCreateDatabase.overload('java.lang.String', 'android.database.sqlite.SQLiteDatabase$CursorFactory')
        .implementation = function (path, factory) {
            console.log('[ear] DB opened (unencrypted): ' + path);
            storageAccess.push({ type: 'DB.open', path: path, encrypted: false });
            return this.openOrCreateDatabase(path, factory);
        };

    // ─── SQLCipher detection ───────────────────────────
    try {
        var SQLCipher = Java.use('net.zetetic.android.database.SQLiteDatabaseHook');
        console.log('[ear] SQLCipher found (good)');
    } catch (e) {
        console.log('[ear] SQLCipher NOT found');
    }

    // ─── KeyStore usage ────────────────────────────────
    try {
        var KeyStore = Java.use('java.security.KeyStore');
        KeyStore.getInstance.overload('java.lang.String').implementation = function (type) {
            console.log('[ear] KeyStore type: ' + type);
            cryptoOps.push({ type: 'KeyStore', algorithm: type });
            return this.getInstance(type);
        };
    } catch (e) {}

    // ─── Cipher usage ──────────────────────────────────
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.getInstance.overload('java.lang.String').implementation = function (transformation) {
            console.log('[ear] Cipher: ' + transformation);
            cryptoOps.push({ type: 'Cipher', transformation: transformation });
            return this.getInstance(transformation);
        };

        Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
            var modeStr = mode === 1 ? 'ENCRYPT' : mode === 2 ? 'DECRYPT' : 'UNKNOWN';
            console.log('[ear] Cipher.init: ' + modeStr + ' with ' + key.getClass().getName());
            return this.init(mode, key);
        };
    } catch (e) {}

    // ─── Weak key detection ────────────────────────────
    try {
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (key, algorithm) {
            console.log('[ear] SecretKeySpec: ' + algorithm + ' (' + key.length + ' bytes)');
            if (key.length < 16) {
                console.log('[ear] ⚠️  WEAK KEY: ' + key.length + ' bytes for ' + algorithm);
            }
            cryptoOps.push({ type: 'SecretKeySpec', algorithm: algorithm, keyLength: key.length });
            return this.$init(key, algorithm);
        };
    } catch (e) {}

    // ─── File encryption checks ────────────────────────
    try {
        var FileInputStream = Java.use('java.io.FileInputStream');
        FileInputStream.$init.overload('java.lang.String').implementation = function (path) {
            if (path.indexOf('database') !== -1 || path.indexOf('.db') !== -1 ||
                path.indexOf('shared_prefs') !== -1 || path.indexOf('.xml') !== -1) {
                console.log('[ear] Reading sensitive file: ' + path);
                storageAccess.push({ type: 'File.read', path: path });
            }
            return this.$init(path);
        };
    } catch (e) {}

    console.log('[ear] All hooks installed');
});

function storageReport() {
    console.log('\n[ear] === Storage Access Report ===');
    console.log('[ear] Total accesses: ' + storageAccess.length);

    var byType = {};
    storageAccess.forEach(function (a) {
        if (!byType[a.type]) byType[a.type] = 0;
        byType[a.type]++;
    });

    console.log('[ear] By type:');
    for (var t in byType) {
        console.log('[ear]   ' + t + ': ' + byType[t]);
    }

    console.log('\n[ear] Crypto operations: ' + cryptoOps.length);
    cryptoOps.forEach(function (op) {
        console.log('[ear]   ' + op.type + ': ' + (op.transformation || op.algorithm || ''));
    });
    console.log('[ear] === End ===\n');
}

console.log('[ear] Functions: storageReport()');
console.log('[ear] Loaded');
