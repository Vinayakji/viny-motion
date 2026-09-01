/**
 * flag-secure-bypass.js
 * Bypass FLAG_SECURE to allow screenshots/screen recording of protected activities
 *
 * Usage: frida -U -f <package> -l flag-secure-bypass.js --no-pause
 */

'use strict';

console.log('[flag-secure] Loading FLAG_SECURE bypass...');

Java.perform(function () {
    // 1. Hook Window.setFlags to remove FLAG_SECURE (0x2000 = 8192)
    var Window = Java.use('android.view.Window');
    Window.setFlags.implementation = function (flags, mask) {
        var FLAG_SECURE = 0x2000;
        if ((flags & FLAG_SECURE) !== 0) {
            console.log('[flag-secure] Removing FLAG_SECURE from ' + this.getClass().getName());
            flags = flags & ~FLAG_SECURE;
        }
        return this.setFlags(flags, mask);
    };

    // 2. Hook addFlags
    Window.addFlags.implementation = function (flags) {
        var FLAG_SECURE = 0x2000;
        if ((flags & FLAG_SECURE) !== 0) {
            console.log('[flag-secure] Blocking addFlags(FLAG_SECURE)');
            flags = flags & ~FLAG_SECURE;
        }
        return this.addFlags(flags);
    };

    // 3. Hook clearFlags (ensure FLAG_SECURE is always cleared)
    Window.clearFlags.implementation = function (flags) {
        var FLAG_SECURE = 0x2000;
        // Always clear FLAG_SECURE regardless
        var result = this.clearFlags(flags);
        // Also force clear it
        try {
            var lp = this.getAttributes();
            if (lp !== null) {
                this.clearFlags(FLAG_SECURE);
            }
        } catch (e) {}
        return result;
    };

    // 4. Hook DecorView to bypass surface-level protection
    try {
        var DecorView = Java.use('android.view.DecorView');
        DecorView.onDraw.implementation = function (canvas) {
            // Allow drawing even with FLAG_SECURE
            return this.onDraw(canvas);
        };
    } catch (e) {}

    // 5. Hook SurfaceView/Surface to bypass capture protection
    try {
        var SurfaceView = Java.use('android.view.SurfaceView');
        SurfaceView.setSecure.implementation = function (secure) {
            console.log('[flag-secure] Bypassing SurfaceView.setSecure(' + secure + ')');
            return this.setSecure(false);
        };
    } catch (e) {}

    console.log('[flag-secure] All bypasses installed');
});
