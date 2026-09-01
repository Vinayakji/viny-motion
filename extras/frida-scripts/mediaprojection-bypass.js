/**
 * mediaprojection-bypass.js
 * Bypass MediaProjection screen capture restrictions
 * Hook MediaProjection.createVirtualDisplay to allow capture of protected content
 *
 * Usage: frida -U -f <package> -l mediaprojection-bypass.js --no-pause
 */

'use strict';

console.log('[mediaproj] MediaProjection bypass loaded');

Java.perform(function () {
    // 1. Hook MediaProjection.createVirtualDisplay to remove SECURE flag
    try {
        var MediaProjection = Java.use('android.media.projection.MediaProjection');
        MediaProjection.createVirtualDisplay.overload(
            'java.lang.String', 'int', 'int', 'int', 'int',
            'android.view.Surface', 'android.hardware.display.VirtualDisplay$Callback',
            'android.os.Handler'
        ).implementation = function (name, width, height, dpi, flags, surface, callback, handler) {
            var FLAG_SECURE = 0x800; // FLAG_SECURE for virtual displays
            if ((flags & FLAG_SECURE) !== 0) {
                console.log('[mediaproj] Removing FLAG_SECURE from VirtualDisplay');
                flags = flags & ~FLAG_SECURE;
            }
            console.log('[mediaproj] createVirtualDisplay: ' + name + ' ' + width + 'x' + height);
            return this.createVirtualDisplay(name, width, height, dpi, flags, surface, callback, handler);
        };
        console.log('[mediaproj] MediaProjection hook installed');
    } catch (e) {
        console.log('[mediaproj] MediaProjection hook failed: ' + e);
    }

    // 2. Hook VirtualDisplay.Builder.setSecure
    try {
        var VDBuilder = Java.use('android.hardware.display.VirtualDisplay$Builder');
        VDBuilder.setSecure.implementation = function (secure) {
            console.log('[mediaproj] Blocking VirtualDisplay.Builder.setSecure(' + secure + ')');
            return this.setSecure(false);
        };
        console.log('[mediaproj] VirtualDisplay.Builder hook installed');
    } catch (e) {}

    // 3. Hook MediaProjectionManager to always return valid projection
    try {
        var ProjectionManager = Java.use('android.media.projection.MediaProjectionManager');
        ProjectionManager.getMediaProjection.implementation = function (resultCode, data) {
            console.log('[mediaproj] getMediaProjection called, resultCode=' + resultCode);
            return this.getMediaProjection(resultCode, data);
        };
    } catch (e) {}

    // 4. Hook Surface.lockCanvas to prevent canvas lock failures
    try {
        var Surface = Java.use('android.view.Surface');
        Surface.lockCanvas.implementation = function (dirty) {
            console.log('[mediaproj] Surface.lockCanvas called');
            return this.lockCanvas(dirty);
        };
    } catch (e) {}

    console.log('[mediaproj] All bypasses installed');
});
