/**
 * permission-tracker.js
 * Track runtime permission requests and responses
 * Monitor dangerous permissions usage patterns
 *
 * Usage: frida -U -f <package> -l permission-tracker.js --no-pause
 */

'use strict';

console.log('[perm] Permission tracker loaded');

var permissionLog = [];
var deniedPerms = [];
var grantedPerms = [];

Java.perform(function () {
    // ─── Permission Request Tracking ────────────────────
    var ActivityCompat = Java.use('androidx.core.app.ActivityCompat');
    ActivityCompat.requestPermissions.overload('android.app.Activity', '[Ljava.lang.String;', 'int')
        .implementation = function (activity, permissions, requestCode) {
            console.log('[perm] requestPermissions called:');
            permissions.forEach(function (p) {
                console.log('[perm]   -> ' + p);
                permissionLog.push({
                    permission: p,
                    action: 'request',
                    timestamp: Date.now(),
                    activity: activity.getClass().getName()
                });
            });
            return this.requestPermissions(activity, permissions, requestCode);
        };

    // ─── Check Permission ──────────────────────────────
    var Context = Java.use('android.content.Context');
    Context.checkPermission.implementation = function (permission, pid, uid) {
        var result = this.checkPermission(permission, pid, uid);
        console.log('[perm] checkPermission: ' + permission + ' -> ' +
            (result === 0 ? 'GRANTED' : result === -1 ? 'DENIED' : 'UNKNOWN'));
        return result;
    };

    Context.checkSelfPermission.overload('java.lang.String').implementation = function (permission) {
        var result = this.checkSelfPermission(permission);
        console.log('[perm] checkSelfPermission: ' + permission + ' -> ' +
            (result === 0 ? 'GRANTED' : 'DENIED'));
        return result;
    };

    // ─── Permission Result Callback ────────────────────
    try {
        var OnRequestPermissionResult = Java.use('androidx.core.app.ActivityCompat$OnRequestPermissionsResultCallback');
    } catch (e) {}

    // ─── Dangerous Permissions List ────────────────────
    var dangerousPerms = [
        'android.permission.CAMERA',
        'android.permission.READ_CONTACTS',
        'android.permission.WRITE_CONTACTS',
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.ACCESS_COARSE_LOCATION',
        'android.permission.ACCESS_BACKGROUND_LOCATION',
        'android.permission.READ_EXTERNAL_STORAGE',
        'android.permission.WRITE_EXTERNAL_STORAGE',
        'android.permission.READ_MEDIA_IMAGES',
        'android.permission.READ_MEDIA_VIDEO',
        'android.permission.READ_MEDIA_AUDIO',
        'android.permission.RECORD_AUDIO',
        'android.permission.READ_PHONE_STATE',
        'android.permission.READ_PHONE_NUMBERS',
        'android.permission.CALL_PHONE',
        'android.permission.ANSWER_PHONE_CALLS',
        'android.permission.READ_CALENDAR',
        'android.permission.WRITE_CALENDAR',
        'android.permission.READ_SMS',
        'android.permission.SEND_SMS',
        'android.permission.RECEIVE_SMS',
        'android.permission.BODY_SENSORS',
        'android.permission.ACTIVITY_RECOGNITION',
        'android.permission.POST_NOTIFICATIONS',
        'android.permission.READ_MEDIA_VISUAL_USER_SELECTED',
        'android.permission.NEARBY_WIFI_DEVICES',
        'android.permission.UWB_RANGING'
    ];

    // ─── Grant All Permissions (for testing) ───────────
    window.grantAllPermissions = function () {
        var PermissionController = Java.use('com.android.packageinstaller.permission.ui.GrantPermissionsActivity');
        Java.choose('com.android.packageinstaller.permission.ui.GrantPermissionsActivity', {
            onMatch: function (activity) {
                console.log('[perm] Granting all permissions...');
                // This is a simplified approach - actual implementation varies
                dangerousPerms.forEach(function (perm) {
                    activity.onPermissionGranted(perm);
                });
            },
            onComplete: function () {}
        });
    };

    // ─── Check Currently Granted Permissions ───────────
    window.checkPermissions = function () {
        Java.choose('android.app.Activity', {
            onMatch: function (activity) {
                dangerousPerms.forEach(function (perm) {
                    var result = activity.checkSelfPermission(perm);
                    if (result === 0) {
                        console.log('[perm] GRANTED: ' + perm);
                        grantedPerms.push(perm);
                    }
                });
            },
            onComplete: function () {}
        });
    };

    console.log('[perm] All hooks installed');
});

function dumpPermissionLog() {
    console.log('\n[perm] === Permission Log (' + permissionLog.length + ' entries) ===');
    permissionLog.forEach(function (entry, i) {
        console.log('[perm] [' + i + '] ' + entry.permission + ' (' + entry.action + ')');
        console.log('[perm]   Activity: ' + entry.activity);
    });
    console.log('[perm] === End ===\n');
}

function permissionSummary() {
    console.log('\n[perm] === Permission Summary ===');
    console.log('[perm] Total requests: ' + permissionLog.length);
    console.log('[perm] Granted: ' + grantedPerms.length);
    console.log('[perm] Denied: ' + deniedPerms.length);

    var permCounts = {};
    permissionLog.forEach(function (entry) {
        if (!permCounts[entry.permission]) permCounts[entry.permission] = 0;
        permCounts[entry.permission]++;
    });

    console.log('\n[perm] Permission frequency:');
    for (var perm in permCounts) {
        console.log('[perm]   ' + perm + ': ' + permCounts[perm] + ' times');
    }
    console.log('[perm] === End ===\n');
}

console.log('[perm] Functions: dumpPermissionLog(), permissionSummary(), checkPermissions()');
console.log('[perm] Loaded');
