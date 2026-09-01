/**
 * test-universal-script.js
 * Universal Frida testing script — one-stop hook everything
 * Usage: frida -U -f <package> -l test-universal-script.js --no-pause
 */

'use strict';
console.log('[universal] Universal testing script loaded');

var findings = [];

function logFind(category, severity, detail) {
    findings.push({ category: category, severity: severity, detail: detail });
    console.log('[FINDING] [' + severity + '] ' + category + ': ' + detail);
}

Java.perform(function () {
    // ─── CLASS ENUMERATOR ──────────────────────────────
    Java.enumerateLoadedClasses({
        onMatch: function (cls) {
            if (cls.indexOf('$') === -1) return; // Skip inner classes for now
            // Log classes with interesting names
            var interesting = ['Secret', 'Key', 'Token', 'Auth', 'Login', 'Admin',
                'Debug', 'Test', 'Dev', 'Internal', 'Private', 'Hidden',
                'WebView', 'Intent', 'Provider', 'Service', 'Broadcast'];
            interesting.forEach(function (word) {
                if (cls.indexOf(word) !== -1) {
                    logFind('INTERESTING_CLASS', 'INFO', cls);
                }
            });
        },
        onComplete: function () {
            console.log('[universal] Class enumeration complete');
        }
    });

    // ─── FILE ACCESS MONITOR ───────────────────────────
    var File = Java.use('java.io.File');
    File.$init.overload('java.lang.String').implementation = function (path) {
        if (path.indexOf('/data/data') !== -1 || path.indexOf('/sdcard') !== -1) {
            logFind('FILE_ACCESS', 'INFO', 'Access: ' + path);
        }
        return this.$init(path);
    };

    // ─── CRYPTO MONITOR ────────────────────────────────
    try {
        var SecretKeyFactory = Java.use('javax.crypto.SecretKeyFactory');
        SecretKeyFactory.getInstance.implementation = function (algorithm) {
            logFind('CRYPTO', 'INFO', 'KeyFactory: ' + algorithm);
            return this.getInstance(algorithm);
        };
    } catch (e) {}

    try {
        var KeyGenerator = Java.use('javax.crypto.KeyGenerator');
        KeyGenerator.getInstance.overload('java.lang.String').implementation = function (algo) {
            logFind('CRYPTO', 'INFO', 'KeyGen: ' + algo);
            return this.getInstance(algo);
        };
    } catch (e) {}

    // ─── SQL MONITOR ───────────────────────────────────
    try {
        var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
        SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function (sql) {
            logFind('SQL', 'MEDIUM', 'SQL: ' + sql.substring(0, 200));
            return this.execSQL(sql);
        };
        SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function (sql, args) {
            logFind('SQL', 'MEDIUM', 'Query: ' + sql.substring(0, 200));
            return this.rawQuery(sql, args);
        };
    } catch (e) {}

    // ─── NETWORK MONITOR ───────────────────────────────
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function () {
            logFind('NETWORK', 'INFO', 'URL: ' + this.toString());
            return this.openConnection();
        };
    } catch (e) {}

    // ─── INTENT MONITOR ────────────────────────────────
    var Intent = Java.use('android.content.Intent');
    Intent.getStringExtra.implementation = function (key) {
        var val = this.getStringExtra(key);
        if (val !== null) logFind('INTENT', 'INFO', key + '=' + val);
        return val;
    };

    // ─── BASE64 MONITOR ────────────────────────────────
    try {
        var Base64 = Java.use('android.util.Base64');
        Base64.encodeToString.overload('[B', 'int').implementation = function (input, flags) {
            logFind('BASE64', 'INFO', 'Encode: ' + input.length + ' bytes');
            return this.encodeToString(input, flags);
        };
        Base64.decode.overload('java.lang.String', 'int').implementation = function (str, flags) {
            logFind('BASE64', 'INFO', 'Decode: ' + str.substring(0, 50));
            return this.decode(str, flags);
        };
    } catch (e) {}

    console.log('[universal] All hooks installed');
});

function dumpFindings() {
    console.log('\n[universal] === FINDINGS (' + findings.length + ') ===');
    findings.forEach(function (f, i) {
        console.log('[universal] [' + (i + 1) + '] [' + f.severity + '] ' + f.category + ': ' + f.detail);
    });
    console.log('[universal] === END FINDINGS ===\n');
}

console.log('[universal] Call dumpFindings() to see all captured findings');
console.log('[universal] Loaded');
