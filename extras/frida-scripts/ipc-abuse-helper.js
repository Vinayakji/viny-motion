/**
 * ipc-abuse-helper.js
 * Enumerate and exploit IPC components (Activities, Services, Receivers, Providers)
 * List exported components, test intent injection, dump provider data
 *
 * Usage: frida -U -f <package> -l ipc-abuse-helper.js --no-pause
 */

'use strict';

console.log('[ipc] Loading IPC abuse helper...');

Java.perform(function () {
    var Context = Java.use('android.content.Context');
    var Intent = Java.use('android.content.Intent');
    var PackageManager = Java.use('android.content.pm.PackageManager');

    /**
     * List all exported components
     */
    Context.listExportedComponents = function () {
        var pm = this.getPackageManager();
        var pkg = this.getPackageName();
        var result = { activities: [], services: [], receivers: [], providers: [] };

        try {
            // Get all activities
            var activities = pm.getPackageInfo(pkg, PackageManager.GET_ACTIVITIES.value);
            if (activities.activities.value !== null) {
                activities.activities.value.forEach(function (act) {
                    if (act.exported.value) {
                        result.activities.push({
                            name: act.name.value,
                            permission: act.permission.value !== null ? act.permission.value : 'none'
                        });
                    }
                });
            }
        } catch (e) {}

        try {
            // Get all services
            var services = pm.getPackageInfo(pkg, PackageManager.GET_SERVICES.value);
            if (services.services.value !== null) {
                services.services.value.forEach(function (svc) {
                    if (svc.exported.value) {
                        result.services.push({
                            name: svc.name.value,
                            permission: svc.permission.value !== null ? svc.permission.value : 'none'
                        });
                    }
                });
            }
        } catch (e) {}

        try {
            // Get all receivers
            var receivers = pm.getPackageInfo(pkg, PackageManager.GET_RECEIVERS.value);
            if (receivers.receivers.value !== null) {
                receivers.receivers.value.forEach(function (rcv) {
                    if (rcv.exported.value) {
                        result.receivers.push({
                            name: rcv.name.value,
                            permission: rcv.permission.value !== null ? rcv.permission.value : 'none'
                        });
                    }
                });
            }
        } catch (e) {}

        try {
            // Get all providers
            var providers = pm.getPackageInfo(pkg, PackageManager.GET_PROVIDERS.value);
            if (providers.providers.value !== null) {
                providers.providers.value.forEach(function (prv) {
                    if (prv.exported.value) {
                        result.providers.push({
                            name: prv.name.value,
                            authority: prv.authority.value,
                            permission: prv.permission.value !== null ? prv.permission.value : 'none'
                        });
                    }
                });
            }
        } catch (e) {}

        return result;
    };

    /**
     * Start an exported activity with custom intent
     */
    Context.startExportedActivity = function (activityName, extras) {
        var intent = Intent.$new(this, Java.use('android.content.ComponentName')
            .$new(this.getPackageName(), activityName));
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK.value);
        if (extras) {
            for (var key in extras) {
                intent.putExtra(key, extras[key]);
            }
        }
        console.log('[ipc] Starting: ' + activityName);
        this.startActivity(intent);
    };

    /**
     * Query a content provider
     */
    Context.queryProvider = function (authority, path) {
        var uri = Java.use('android.net.Uri').parse('content://' + authority + '/' + (path || ''));
        var cursor = this.getContentResolver().query(uri, null, null, null, null);
        if (cursor === null) {
            console.log('[ipc] Provider query returned null: ' + authority);
            return [];
        }

        var results = [];
        var cols = cursor.getColumnNames();
        while (cursor.moveToNext()) {
            var row = {};
            cols.forEach(function (col, i) {
                row[col] = cursor.getString(i);
            });
            results.push(row);
        }
        cursor.close();
        console.log('[ipc] Provider ' + authority + ': ' + results.length + ' rows');
        return results;
    };

    console.log('[ipc] Functions ready: listExportedComponents(), startExportedActivity(), queryProvider()');
});

console.log('[ipc] Loaded');
