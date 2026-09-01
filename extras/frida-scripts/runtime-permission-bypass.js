/**
 * runtime-permission-bypass.js
 * Auto-grant runtime permissions for testing
 * Bypass permission dialogs and restrictions
 *
 * Usage: frida -U -f <package> -l runtime-permission-bypass.js --no-pause
 */

'use strict';

console.log('[perm-bypass] Runtime permission bypass loaded');

Java.perform(function () {
    // ─── Auto-grant via PermissionController ───────────
    try {
        // Hook the permission grant dialog
        var GrantPermissionsActivity = Java.use('com.android.packageinstaller.permission.ui.GrantPermissionsActivity');
        GrantPermissionsActivity.onPermissionGranted.implementation = function (permission) {
            console.log('[perm-bypass] Auto-granting: ' + permission);
            return this.onPermissionGranted(permission);
        };
    } catch (e) {
        console.log('[perm-bypass] GrantPermissionsActivity not available');
    }

    // ─── Auto-grant via checkSelfPermission ────────────
    var Context = Java.use('android.content.Context');
    Context.checkSelfPermission.overload('java.lang.String').implementation = function (permission) {
        console.log('[perm-bypass] checkSelfPermission(' + permission + ') -> GRANTED');
        return 0; // PERMISSION_GRANTED
    };

    // ─── Auto-grant via checkPermission ────────────────
    Context.checkPermission.implementation = function (permission, pid, uid) {
        console.log('[perm-bypass] checkPermission(' + permission + ') -> GRANTED');
        return 0; // PERMISSION_GRANTED
    };

    // ─── Auto-grant via checkCallingPermission ─────────
    Context.checkCallingPermission.implementation = function (permission) {
        console.log('[perm-bypass] checkCallingPermission(' + permission + ') -> GRANTED');
        return 0;
    };

    // ─── Auto-grant via checkCallingOrSelfPermission ────
    Context.checkCallingOrSelfPermission.implementation = function (permission) {
        console.log('[perm-bypass] checkCallingOrSelfPermission(' + permission + ') -> GRANTED');
        return 0;
    };

    // ─── Auto-grant via checkUriPermission ─────────────
    Context.checkUriPermission.implementation = function (uri, pid, uid, modeFlags) {
        console.log('[perm-bypass] checkUriPermission(' + uri + ') -> GRANTED');
        return 0;
    };

    // ─── Request Permissions (always grant) ────────────
    try {
        var ActivityCompat = Java.use('androidx.core.app.ActivityCompat');
        ActivityCompat.requestPermissions.overload('android.app.Activity', '[Ljava.lang.String;', 'int')
            .implementation = function (activity, permissions, requestCode) {
                console.log('[perm-bypass] Requesting permissions (auto-granting):');
                permissions.forEach(function (p) {
                    console.log('[perm-bypass]   ' + p);
                });

                // Simulate immediate grant
                var grantResults = Java.array('int', permissions.map(function () { return 0; }));
                try {
                    activity.onRequestPermissionsResult(requestCode, permissions, grantResults);
                } catch (e) {}

                return null;
            };
    } catch (e) {}

    // ─── Signature-level permissions bypass ─────────────
    try {
        var PackageManager = Java.use('android.content.pm.PackageManager');
        PackageManager.checkPermission.overload('java.lang.String', 'java.lang.String').implementation = function (permName, pkgName) {
            console.log('[perm-bypass] checkPermission(' + permName + ', ' + pkgName + ') -> GRANTED');
            return 0;
        };
    } catch (e) {}

    // ─── Manifest permission bypass ────────────────────
    try {
        var ContextImpl = Java.use('android.app.ContextImpl');
        ContextImpl.checkPermission.overload('java.lang.String', 'int', 'int').implementation = function (permission, pid, uid) {
            console.log('[perm-bypass] ContextImpl.checkPermission(' + permission + ') -> GRANTED');
            return 0;
        };
    } catch (e) {}

    console.log('[perm-bypass] All bypasses installed');
    console.log('[perm-bypass] All runtime permissions will be auto-granted');
});
