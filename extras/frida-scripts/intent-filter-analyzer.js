/**
 * intent-filter-analyzer.js
 * Analyze intent filters and exported components for abuse
 * Map attack surface from manifest-defined intents
 *
 * Usage: frida -U -f <package> -l intent-filter-analyzer.js --no-pause
 */

'use strict';

console.log('[ifa] Intent filter analyzer loaded');

var intentFilters = [];

Java.perform(function () {
    // ─── Intent resolution monitoring ──────────────────
    var Intent = Java.use('android.content.Intent');
    Intent.resolveActivity.overload('android.content.pm.PackageManager').implementation = function (pm) {
        var component = this.resolveActivity(pm);
        var action = this.getAction();
        var data = this.getData();
        console.log('[ifa] resolveActivity: action=' + action + ' data=' + (data ? data.toString() : 'null'));
        intentFilters.push({ type: 'resolve', action: action, data: data ? data.toString() : null });
        return component;
    };

    Intent.setFlags.implementation = function (flags) {
        // Check for dangerous flags
        if (flags & 0x10000000) console.log('[ifa] FLAG_ACTIVITY_NEW_TASK');
        if (flags & 0x04000000) console.log('[ifa] FLAG_ACTIVITY_CLEAR_TOP');
        if (flags & 0x10000000 | flags & 0x00000010) console.log('[ifa] ⚠️  FLAG_GRANT_READ_URI_PERMISSION');
        return this.setFlags(flags);
    };

    Intent.addFlags.implementation = function (flags) {
        if (flags & 0x00000010) console.log('[ifa] ⚠️  addFlags: GRANT_READ_URI_PERMISSION');
        if (flags & 0x00000020) console.log('[ifa] ⚠️  addFlags: GRANT_WRITE_URI_PERMISSION');
        return this.addFlags(flags);
    };

    // ─── Package Manager queries ───────────────────────
    try {
        var PackageManager = Java.use('android.app.ApplicationPackageManager');
        PackageManager.queryIntentActivities.overload('android.content.Intent', 'int')
            .implementation = function (intent, flags) {
                var activities = this.queryIntentActivities(intent, flags);
                console.log('[ifa] queryIntentActivities: ' + activities.size() + ' results');
                activities.forEach(function (info) {
                    console.log('[ifa]   ' + info.activityInfo.name);
                });
                return activities;
            };

        PackageManager.queryIntentServices.overload('android.content.Intent', 'int')
            .implementation = function (intent, flags) {
                var services = this.queryIntentServices(intent, flags);
                console.log('[ifa] queryIntentServices: ' + services.size() + ' results');
                return services;
            };

        PackageManager.queryBroadcastReceivers.overload('android.content.Intent', 'int')
            .implementation = function (intent, flags) {
                var receivers = this.queryBroadcastReceivers(intent, flags);
                console.log('[ifa] queryBroadcastReceivers: ' + receivers.size() + ' results');
                return receivers;
            };
    } catch (e) {}

    // ─── Content Provider URI resolution ───────────────
    try {
        var ContentResolver = Java.use('android.content.ContentResolver');
        ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String')
            .implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
                console.log('[ifa] ContentProvider query: ' + uri.toString());
                intentFilters.push({ type: 'contentQuery', uri: uri.toString() });
                return this.query(uri, projection, selection, selectionArgs, sortOrder);
            };
    } catch (e) {}

    console.log('[ifa] All hooks installed');
});

function intentFilterReport() {
    console.log('\n[intent] === Intent Filter Analysis ===');
    console.log('[ifa] Total interactions: ' + intentFilters.length);
    intentFilters.forEach(function (f) {
        console.log('[ifa]   ' + f.type + ': ' + (f.action || f.uri || ''));
    });
    console.log('[ifa] === End ===\n');
}

console.log('[ifa] Functions: intentFilterReport()');
console.log('[ifa] Loaded');
