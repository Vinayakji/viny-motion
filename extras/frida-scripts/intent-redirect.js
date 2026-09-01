/**
 * intent-redirect.js
 * Detect and exploit intent redirection vulnerabilities
 * Log all intent launches, parameter sources, and redirect chains
 *
 * Usage: frida -U -f <package> -l intent-redirect.js --no-pause
 */

'use strict';

console.log('[intent] Intent redirect analyzer loaded');

var intentChain = [];
var redirectCount = 0;

Java.perform(function () {
    // ─── startActivity Monitoring ──────────────────────
    var ContextWrapper = Java.use('android.content.ContextWrapper');
    ContextWrapper.startActivity.overload('android.content.Intent').implementation = function (intent) {
        redirectCount++;
        var action = intent.getAction();
        var component = intent.getComponent();
        var extras = intent.getExtras();
        var flags = intent.getFlags();

        var entry = {
            id: redirectCount,
            action: action,
            component: component ? component.getClassName() : null,
            extras: {},
            flags: flags,
            timestamp: Date.now(),
            backtrace: Java.use('android.util.Log').getStackTraceString(
                Java.use('java.lang.Exception').$new()).substring(0, 500)
        };

        // Extract extras safely
        if (extras) {
            try {
                var keySet = extras.keySet().iterator();
                while (keySet.hasNext()) {
                    var key = keySet.next();
                    try {
                        entry.extras[key] = extras.get(key) !== null ? extras.get(key).toString() : 'null';
                    } catch (e) {
                        entry.extras[key] = '[unextractable]';
                    }
                }
            } catch (e) {}
        }

        console.log('[intent] #' + redirectCount + ' startActivity:');
        console.log('[intent]   action: ' + action);
        console.log('[intent]   component: ' + entry.component);
        console.log('[intent]   flags: 0x' + flags.toString(16));
        if (Object.keys(entry.extras).length > 0) {
            console.log('[intent]   extras: ' + JSON.stringify(entry.extras));
        }

        // Check for redirect patterns
        if (flags & 0x10000000) { // FLAG_ACTIVITY_NEW_TASK
            console.log('[intent]   FLAG_ACTIVITY_NEW_TASK set');
        }
        if (flags & 0x04000000) { // FLAG_ACTIVITY_CLEAR_TOP
            console.log('[intent]   FLAG_ACTIVITY_CLEAR_TOP set');
        }

        intentChain.push(entry);
        return this.startActivity(intent);
    };

    ContextWrapper.startActivity.overload('android.content.Intent', 'android.os.Bundle')
        .implementation = function (intent, options) {
            redirectCount++;
            console.log('[intent] #' + redirectCount + ' startActivity (with options)');
            intentChain.push({
                id: redirectCount,
                action: intent.getAction(),
                component: intent.getComponent() ? intent.getComponent().getClassName() : null,
                timestamp: Date.now()
            });
            return this.startActivity(intent, options);
        };

    // ─── startActivityForResult Monitoring ─────────────
    var Activity = Java.use('android.app.Activity');
    Activity.startActivityForResult.overload('android.content.Intent', 'int')
        .implementation = function (intent, requestCode) {
            console.log('[intent] startActivityForResult: ' + intent.getAction() + ' (code=' + requestCode + ')');
            return this.startActivityForResult(intent, requestCode);
        };

    // ─── Intent.getParcelableExtra Monitoring ──────────
    var Intent = Java.use('android.content.Intent');
    Intent.getParcelableExtra.overload('java.lang.String').implementation = function (name) {
        var extra = this.getParcelableExtra(name);
        if (extra !== null) {
            console.log('[intent] getParcelableExtra: ' + name + ' -> ' + extra.getClass().getName());
        }
        return extra;
    };

    // ─── PendingIntent Creation Monitoring ─────────────
    try {
        var PendingIntent = Java.use('android.app.PendingIntent');
        PendingIntent.getActivity.overload('android.content.Context', 'int', 'android.content.Intent', 'int')
            .implementation = function (context, requestCode, intent, flags) {
                console.log('[intent] PendingIntent.getActivity:');
                console.log('[intent]   target: ' + (intent.getComponent() ? intent.getComponent().getClassName() : 'null'));
                console.log('[intent]   flags: 0x' + flags.toString(16));
                return this.getActivity(context, requestCode, intent, flags);
            };

        PendingIntent.getBroadcast.overload('android.content.Context', 'int', 'android.content.Intent', 'int')
            .implementation = function (context, requestCode, intent, flags) {
                console.log('[intent] PendingIntent.getBroadcast:');
                console.log('[intent]   action: ' + intent.getAction());
                return this.getBroadcast(context, requestCode, intent, flags);
            };

        PendingIntent.getService.overload('android.content.Context', 'int', 'android.content.Intent', 'int')
            .implementation = function (context, requestCode, intent, flags) {
                console.log('[intent] PendingIntent.getService:');
                console.log('[intent]   component: ' + (intent.getComponent() ? intent.getComponent().getClassName() : 'null'));
                return this.getService(context, requestCode, intent, flags);
            };
    } catch (e) {}

    console.log('[intent] All hooks installed');
});

function dumpIntentChain() {
    console.log('\n[intent] === Intent Chain (' + intentChain.length + ' entries) ===');
    intentChain.forEach(function (entry) {
        console.log('[intent] [' + entry.id + '] ' + (entry.action || entry.component || 'unknown'));
        if (entry.extras && Object.keys(entry.extras).length > 0) {
            console.log('[intent]   extras: ' + JSON.stringify(entry.extras));
        }
    });
    console.log('[intent] === End ===\n');
}

function intentStats() {
    console.log('[intent] === Stats ===');
    console.log('[intent] Total intents: ' + redirectCount);

    var actions = {};
    var components = {};
    intentChain.forEach(function (e) {
        if (e.action) {
            if (!actions[e.action]) actions[e.action] = 0;
            actions[e.action]++;
        }
        if (e.component) {
            if (!components[e.component]) components[e.component] = 0;
            components[e.component]++;
        }
    });

    console.log('\n[intent] Top actions:');
    for (var a in actions) console.log('[intent]   ' + a + ': ' + actions[a]);
    console.log('\n[intent] Top components:');
    for (var c in components) console.log('[intent]   ' + c + ': ' + components[c]);
}

console.log('[intent] Functions: dumpIntentChain(), intentStats()');
console.log('[intent] Loaded');
