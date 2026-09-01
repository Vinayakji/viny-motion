/**
 * logging-interceptor.js
 * Intercept and capture all logging operations (Log.d/i/w/e/v)
 * Monitor for sensitive data in logs
 *
 * Usage: frida -U -f <package> -l logging-interceptor.js --no-pause
 */

'use strict';

console.log('[log] Logging interceptor loaded');

var logEntries = [];
var sensitivePatterns = ['password', 'token', 'secret', 'key', 'otp', 'auth', 'session', 'cookie', 'credential', 'bearer'];

Java.perform(function () {
    // ─── android.util.Log ──────────────────────────────
    var Log = Java.use('android.util.Log');

    Log.d.overload('java.lang.String', 'java.lang.String').implementation = function (tag, msg) {
        logEntries.push({ level: 'D', tag: tag, msg: msg, timestamp: Date.now() });
        checkSensitive(tag, msg, 'D');
        return this.d(tag, msg);
    };

    Log.i.overload('java.lang.String', 'java.lang.String').implementation = function (tag, msg) {
        logEntries.push({ level: 'I', tag: tag, msg: msg, timestamp: Date.now() });
        checkSensitive(tag, msg, 'I');
        return this.i(tag, msg);
    };

    Log.w.overload('java.lang.String', 'java.lang.String').implementation = function (tag, msg) {
        logEntries.push({ level: 'W', tag: tag, msg: msg, timestamp: Date.now() });
        checkSensitive(tag, msg, 'W');
        return this.w(tag, msg);
    };

    Log.e.overload('java.lang.String', 'java.lang.String').implementation = function (tag, msg) {
        logEntries.push({ level: 'E', tag: tag, msg: msg, timestamp: Date.now() });
        checkSensitive(tag, msg, 'E');
        return this.e(tag, msg);
    };

    Log.v.overload('java.lang.String', 'java.lang.String').implementation = function (tag, msg) {
        logEntries.push({ level: 'V', tag: tag, msg: msg, timestamp: Date.now() });
        return this.v(tag, msg);
    };

    // Hook with exception
    Log.e.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable')
        .implementation = function (tag, msg, tr) {
            logEntries.push({ level: 'E', tag: tag, msg: msg + '\n' + tr.getStackTrace().toString(), timestamp: Date.now() });
            return this.e(tag, msg, tr);
        };

    Log.w.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable')
        .implementation = function (tag, msg, tr) {
            logEntries.push({ level: 'W', tag: tag, msg: msg, timestamp: Date.now() });
            return this.w(tag, msg, tr);
        };

    console.log('[log] android.util.Log hooks installed');
});

function checkSensitive(tag, msg, level) {
    var lower = (tag + ' ' + msg).toLowerCase();
    sensitivePatterns.forEach(function (p) {
        if (lower.indexOf(p) !== -1) {
            console.log('[log] ⚠️  SENSITIVE [' + level + '] ' + tag + ': ' + msg.substring(0, 100));
        }
    });
}

function dumpLogs() {
    console.log('\n[log] === Log Entries (' + logEntries.length + ') ===');
    logEntries.slice(-50).forEach(function (entry) {
        console.log('[log] [' + entry.level + '] ' + entry.tag + ': ' + entry.msg.substring(0, 150));
    });
    console.log('[log] === End ===\n');
}

function logStats() {
    console.log('[log] === Log Stats ===');
    console.log('[log] Total entries: ' + logEntries.length);
    var levels = { D: 0, I: 0, W: 0, E: 0, V: 0 };
    var tags = {};
    logEntries.forEach(function (e) {
        levels[e.level]++;
        if (!tags[e.tag]) tags[e.tag] = 0;
        tags[e.tag]++;
    });
    console.log('[log] By level: ' + JSON.stringify(levels));
    console.log('\n[log] Top tags:');
    var sorted = Object.entries(tags).sort(function (a, b) { return b[1] - a[1]; });
    sorted.slice(0, 10).forEach(function (t) {
        console.log('[log]   ' + t[0] + ': ' + t[1]);
    });
}

console.log('[log] Functions: dumpLogs(), logStats()');
console.log('[log] Loaded');
