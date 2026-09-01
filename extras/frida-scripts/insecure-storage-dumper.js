/**
 * insecure-storage-dumper.js
 * Dump insecure storage locations (SharedPrefs, files, databases)
 * Detect cleartext sensitive data in storage
 *
 * Usage: frida -U -f <package> -l insecure-storage-dumper.js --no-pause
 */

'use strict';

console.log('[isd] Insecure storage dumper loaded');

var storageOps = [];

Java.perform(function () {
    // ─── SharedPreferences ─────────────────────────────
    var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');

    SharedPreferencesImpl.getString.implementation = function (key, defValue) {
        var val = this.getString(key, defValue);
        if (val !== null && isSensitive(key)) {
            console.log('[isd] ⚠️  SharedPreferences.get(' + key + ') = ' + val.substring(0, 50));
        }
        storageOps.push({ type: 'SharedPrefs.get', key: key, encrypted: false });
        return val;
    };

    SharedPreferencesImpl.putString.implementation = function (key, value) {
        if (isSensitive(key)) {
            console.log('[isd] ⚠️  SharedPreferences.put(' + key + ') = ' + (value ? value.substring(0, 50) : 'null'));
        }
        storageOps.push({ type: 'SharedPrefs.put', key: key, encrypted: false });
        return this.putString(key, value);
    };

    SharedPreferencesImpl.putInt.implementation = function (key, value) {
        storageOps.push({ type: 'SharedPrefs.putInt', key: key, encrypted: false });
        return this.putInt(key, value);
    };

    SharedPreferencesImpl.putBoolean.implementation = function (key, value) {
        storageOps.push({ type: 'SharedPrefs.putBool', key: key, encrypted: false });
        return this.putBoolean(key, value);
    };

    // ─── File operations ───────────────────────────────
    var FileWriter = Java.use('java.io.FileWriter');
    FileWriter.$init.overload('java.lang.String').implementation = function (path) {
        console.log('[isd] FileWriter: ' + path);
        storageOps.push({ type: 'FileWriter', path: path });
        return this.$init(path);
    };

    var FileWriterAppend = Java.use('java.io.FileWriter');
    FileWriterAppend.$init.overload('java.lang.String', 'boolean').implementation = function (path, append) {
        console.log('[isd] FileWriter: ' + path + ' (append=' + append + ')');
        storageOps.push({ type: 'FileWriter', path: path });
        return this.$init(path, append);
    };

    // ─── SQLite (unencrypted) ──────────────────────────
    var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
    SQLiteDatabase.openOrCreateDatabase.overload('java.lang.String', 'android.database.sqlite.SQLiteDatabase$CursorFactory')
        .implementation = function (path, factory) {
            console.log('[isd] ⚠️  Unencrypted DB: ' + path);
            storageOps.push({ type: 'DB.open', path: path });
            return this.openOrCreateDatabase(path, factory);
        };

    SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function (sql) {
        if (sql.toLowerCase().indexOf('insert') !== -1 || sql.toLowerCase().indexOf('update') !== -1) {
            console.log('[isd] DB write: ' + sql.substring(0, 100));
        }
        return this.execSQL(sql);
    };

    console.log('[isd] All hooks installed');
});

function isSensitive(key) {
    var sensitive = ['password', 'token', 'secret', 'key', 'otp', 'auth', 'session', 'cookie', 'jwt', 'credential'];
    var lower = key.toLowerCase();
    return sensitive.some(function (s) { return lower.indexOf(s) !== -1; });
}

function storageDumpReport() {
    console.log('\n[isd] === Insecure Storage Report ===');
    console.log('[isd] Total operations: ' + storageOps.length);

    var insecure = storageOps.filter(function (op) {
        return !op.encrypted || op.type.indexOf('DB') !== -1;
    });

    console.log('[isd] Insecure operations: ' + insecure.length);
    insecure.forEach(function (op) {
        console.log('[isd]   ' + op.type + ': ' + (op.key || op.path || ''));
    });
    console.log('[isd] === End ===\n');
}

console.log('[isd] Functions: storageDumpReport()');
console.log('[isd] Loaded');
