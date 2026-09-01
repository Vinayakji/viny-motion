/**
 * file-permission-audit.js
 * Audit file permissions for app data, world-readable/writable files
 * Detect insecure file operations and path traversal risks
 *
 * Usage: frida -U -f <package> -l file-permission-audit.js --no-pause
 */

'use strict';

console.log('[fpa] File permission audit loaded');

var fileOps = [];

Java.perform(function () {
    // ─── File creation monitoring ───────────────────────
    var File = Java.use('java.io.File');
    File.$init.overload('java.lang.String').implementation = function (path) {
        if (path.indexOf('/data') !== -1 || path.indexOf('/sdcard') !== -1 ||
            path.indexOf('/storage') !== -1 || path.indexOf('/cache') !== -1) {
            fileOps.push({ type: 'create', path: path, timestamp: Date.now() });
        }
        return this.$init(path);
    };

    File.mkdirs.implementation = function () {
        var path = this.getAbsolutePath();
        console.log('[fpa] mkdirs: ' + path);
        fileOps.push({ type: 'mkdirs', path: path, timestamp: Date.now() });
        return this.mkdirs();
    };

    File.createNewFile.implementation = function () {
        var path = this.getAbsolutePath();
        console.log('[fpa] createNewFile: ' + path);
        fileOps.push({ type: 'create', path: path, timestamp: Date.now() });
        return this.createNewFile();
    };

    File.setWritable.overload('boolean').implementation = function (writable) {
        var path = this.getAbsolutePath();
        if (writable) {
            console.log('[fpa] ⚠️  setWritable(true): ' + path);
        }
        return this.setWritable(writable);
    };

    File.setReadable.overload('boolean').implementation = function (readable) {
        return this.setReadable(readable);
    };

    File.setExecutable.overload('boolean').implementation = function (executable) {
        var path = this.getAbsolutePath();
        if (executable) {
            console.log('[fpa] setExecutable: ' + path);
        }
        return this.setExecutable(executable);
    };

    // ─── World-readable/writable mode ──────────────────
    try {
        var Context = Java.use('android.content.Context');
        Context.openFileOutput.overload('java.lang.String', 'int').implementation = function (name, mode) {
            // MODE_WORLD_READABLE = 1, MODE_WORLD_WRITABLE = 2
            if (mode & 1) console.log('[fpa] ⚠️  MODE_WORLD_READABLE: ' + name);
            if (mode & 2) console.log('[fpa] ⚠️  MODE_WORLD_WRITABLE: ' + name);
            fileOps.push({ type: 'openFileOutput', name: name, mode: mode, timestamp: Date.now() });
            return this.openFileOutput(name, mode);
        };
    } catch (e) {}

    // ─── Content Provider file access ──────────────────
    try {
        var ContentResolver = Java.use('android.content.ContentResolver');
        ContentResolver.openInputStream.overload('android.net.Uri').implementation = function (uri) {
            console.log('[fpa] openInputStream: ' + uri.toString());
            fileOps.push({ type: 'openInputStream', uri: uri.toString(), timestamp: Date.now() });
            return this.openInputStream(uri);
        };

        ContentResolver.openOutputStream.overload('android.net.Uri').implementation = function (uri) {
            console.log('[fpa] openOutputStream: ' + uri.toString());
            fileOps.push({ type: 'openOutputStream', uri: uri.toString(), timestamp: Date.now() });
            return this.openOutputStream(uri);
        };
    } catch (e) {}

    // ─── chmod/chown monitoring ─────────────────────────
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            if (cmd.indexOf('chmod') !== -1 || cmd.indexOf('chown') !== -1) {
                console.log('[fpa] ⚠️  Shell command: ' + cmd);
            }
            return this.exec(cmd);
        };
    } catch (e) {}

    console.log('[fpa] All hooks installed');
});

function filePermReport() {
    console.log('\n[fn] === File Permission Audit ===');
    console.log('[fpa] Total file operations: ' + fileOps.length);

    var suspicious = fileOps.filter(function (op) {
        return (op.mode && (op.mode & 3)) || // WORLD_READABLE or WORLD_WRITABLE
               op.uri && op.uri.indexOf('content://') === 0; // Content provider access
    });

    console.log('[fpa] Suspicious operations: ' + suspicious.length);
    suspicious.forEach(function (op) {
        console.log('[fpa]   ' + op.type + ': ' + (op.name || op.uri || op.path || ''));
    });

    console.log('\n[fpa] === All Operations ===');
    fileOps.slice(-30).forEach(function (op) {
        console.log('[fpa]   ' + op.type + ': ' + (op.name || op.uri || op.path || ''));
    });
    console.log('[fpa] === End ===\n');
}

console.log('[fpa] Functions: filePermReport()');
console.log('[fpa] Loaded');
