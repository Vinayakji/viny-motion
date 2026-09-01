/**
 * clipboard-monitor.js
 * Monitor clipboard access for sensitive data leakage
 * Track all clipboard read/write operations
 *
 * Usage: frida -U -f <package> -l clipboard-monitor.js --no-pause
 */

'use strict';

console.log('[clip] Clipboard monitor loaded');

var clipOps = [];

Java.perform(function () {
    // ─── ClipboardManager ──────────────────────────────
    try {
        var ClipboardManager = Java.use('android.content.ClipboardManager');

        // Hook setPrimaryClip (write)
        ClipboardManager.setPrimaryClip.implementation = function (clip) {
            var text = clip.getItemAt(0).getText();
            var label = clip.getDescription().getLabel();
            console.log('[clip] WRITE to clipboard:');
            console.log('[clip]   Label: ' + label);
            console.log('[clip]   Text: ' + (text !== null ? text.toString().substring(0, 200) : 'null'));

            clipOps.push({
                action: 'write',
                text: text !== null ? text.toString() : null,
                label: label,
                timestamp: Date.now()
            });

            // Check for sensitive patterns
            if (text !== null) {
                var t = text.toString().toLowerCase();
                var sensitive = ['password', 'token', 'key', 'secret', 'otp', 'pin', 'auth', 'session'];
                sensitive.forEach(function (s) {
                    if (t.indexOf(s) !== -1) {
                        console.log('[clip]   ⚠️  SENSITIVE DATA: contains "' + s + '"');
                    }
                });

                // Check for potential URLs
                if (t.indexOf('http') === 0 || t.indexOf('otpauth') === 0) {
                    console.log('[clip]   ⚠️  URL/URI detected');
                }
            }

            return this.setPrimaryClip(clip);
        };

        // Hook getPrimaryClip (read)
        ClipboardManager.getPrimaryClip.implementation = function () {
            var clip = this.getPrimaryClip();
            if (clip !== null && clip.getItemCount() > 0) {
                var text = clip.getItemAt(0).getText();
                console.log('[clip] READ from clipboard:');
                console.log('[clip]   Text: ' + (text !== null ? text.toString().substring(0, 200) : 'null'));

                clipOps.push({
                    action: 'read',
                    text: text !== null ? text.toString() : null,
                    timestamp: Date.now()
                });
            }
            return clip;
        };

        // Hook hasPrimaryClip
        ClipboardManager.hasPrimaryClip.implementation = function () {
            var has = this.hasPrimaryClip();
            return has;
        };

        // Hook addPrimaryClipChangedListener
        ClipboardManager.addPrimaryClipChangedListener.implementation = function (listener) {
            console.log('[clip] addPrimaryClipChangedListener: ' + listener.getClass().getName());
            return this.addPrimaryClipChangedListener(listener);
        };

        console.log('[clip] ClipboardManager hooks installed');
    } catch (e) {
        console.log('[clip] ClipboardManager hook failed: ' + e);
    }

    // ─── ContentProvider clipboard access ───────────────
    try {
        var ContentResolver = Java.use('android.content.ContentResolver');
        ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String')
            .implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
                if (uri.toString().indexOf('clipboard') !== -1) {
                    console.log('[clip] ContentProvider clipboard access');
                }
                return this.query(uri, projection, selection, selectionArgs, sortOrder);
            };
    } catch (e) {}

    console.log('[clip] All hooks installed');
});

function dumpClipboardOps() {
    console.log('\n[clip] === Clipboard Operations (' + clipOps.length + ') ===');
    clipOps.forEach(function (op, i) {
        console.log('[clip] [' + i + '] ' + op.action + ': ' + (op.text || '').substring(0, 100));
    });
    console.log('[clip] === End ===\n');
}

function clipboardStats() {
    console.log('[clip] === Clipboard Stats ===');
    var reads = 0, writes = 0;
    clipOps.forEach(function (op) {
        if (op.action === 'read') reads++;
        else writes++;
    });
    console.log('[clip] Reads: ' + reads);
    console.log('[clip] Writes: ' + writes);

    // Check for sensitive data
    var sensitive = clipOps.filter(function (op) {
        if (!op.text) return false;
        var t = op.text.toLowerCase();
        return ['password', 'token', 'key', 'secret', 'otp'].some(function (s) {
            return t.indexOf(s) !== -1;
        });
    });
    console.log('[clip] Sensitive data operations: ' + sensitive.length);
    sensitive.forEach(function (op) {
        console.log('[clip]   ' + op.action + ': ' + op.text.substring(0, 50));
    });
}

console.log('[clip] Functions: dumpClipboardOps(), clipboardStats()');
console.log('[clip] Loaded');
