/**
 * foreground-service-check.js
 * Check for proper foreground service implementation
 * Monitor service lifecycle and notification requirements
 *
 * Usage: frida -U -f <package> -l foreground-service-check.js --no-pause
 */

'use strict';

console.log('[fsc] Foreground service checker loaded');

var serviceOps = [];

Java.perform(function () {
    // ─── Service start monitoring ──────────────────────
    var Context = Java.use('android.content.Context');
    Context.startService.overload('android.content.Intent').implementation = function (intent) {
        var component = intent.getComponent();
        console.log('[fsc] startService: ' + (component ? component.getClassName() : intent.getAction()));
        serviceOps.push({ type: 'start', component: component ? component.getClassName() : null, timestamp: Date.now() });
        return this.startService(intent);
    };

    Context.startForegroundService.overload('android.content.Intent').implementation = function (intent) {
        var component = intent.getComponent();
        console.log('[fsc] startForegroundService: ' + (component ? component.getClassName() : 'null'));
        serviceOps.push({ type: 'startForeground', component: component ? component.getClassName() : null, timestamp: Date.now() });
        return this.startForegroundService(intent);
    };

    // ─── Service foreground transition ──────────────────
    try {
        var Service = Java.use('android.app.Service');
        Service.startForeground.overload('int', 'android.app.Notification').implementation = function (id, notification) {
            console.log('[fsc] startForeground: id=' + id);
            console.log('[fsc]   Title: ' + notification.extras.getString('android.title'));
            console.log('[fsc]   Text: ' + notification.extras.getString('android.text'));
            serviceOps.push({ type: 'foreground', id: id, timestamp: Date.now() });
            return this.startForeground(id, notification);
        };

        Service.stopForeground.overload('boolean').implementation = function (remove) {
            console.log('[fsc] stopForeground: remove=' + remove);
            return this.stopForeground(remove);
        };

        Service.stopForeground.overload('int').implementation = function (flags) {
            console.log('[fsc] stopForeground: flags=' + flags);
            return this.stopForeground(flags);
        };
    } catch (e) {}

    // ─── Notification channel check ────────────────────
    try {
        var NotificationManager = Java.use('android.app.NotificationManager');
        NotificationManager.createNotificationChannel.overload('android.app.NotificationChannel')
            .implementation = function (channel) {
                console.log('[fsc] NotificationChannel: ' + channel.getId() +
                    ' (importance=' + channel.getImportance() + ')');
                return this.createNotificationChannel(channel);
            };
    } catch (e) {}

    // ─── Service connection monitoring ─────────────────
    try {
        Context.bindService.overload('android.content.Intent', 'android.content.ServiceConnection', 'int')
            .implementation = function (intent, conn, flags) {
                var component = intent.getComponent();
                console.log('[fsc] bindService: ' + (component ? component.getClassName() : 'null'));
                return this.bindService(intent, conn, flags);
            };
    } catch (e) {}

    console.log('[fsc] All hooks installed');
});

function serviceReport() {
    console.log('\n[fsc] === Service Operations ===');
    console.log('[fsc] Total: ' + serviceOps.length);

    var counts = { start: 0, startForeground: 0, foreground: 0 };
    serviceOps.forEach(function (op) {
        if (counts[op.type] !== undefined) counts[op.type]++;
    });
    console.log('[fsc] Starts: ' + counts.start);
    console.log('[fsc] StartForeground calls: ' + counts.startForeground);
    console.log('[fsc] Foreground transitions: ' + counts.foreground);

    if (counts.startForeground > 0 && counts.foreground === 0) {
        console.log('[fsc] ⚠️  startForegroundService called but startForeground not called');
    }

    serviceOps.forEach(function (op) {
        console.log('[fsc]   ' + op.type + ': ' + (op.component || op.id || ''));
    });
    console.log('[fsc] === End ===\n');
}

console.log('[fsc] Functions: serviceReport()');
console.log('[fsc] Loaded');
