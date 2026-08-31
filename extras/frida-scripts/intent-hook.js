// intent-hook.js — Hook startActivity, startService, sendBroadcast to log all intents
Java.perform(function() {
    var Tag = "INTENT_HOOK";

    var Context = Java.use("android.content.Context");

    // Hook startActivity(Intent)
    Context.startActivity.overload("android.content.Intent").implementation = function(intent) {
        var extras = extractExtras(intent);
        send({type: "intent", action: "startActivity", component: intent.getComponent() ? intent.getComponent().flattenToString() : "null", intentAction: intent.getAction(), data: intent.getDataString(), extras: extras, flags: intent.getFlags()});
        console.log("[INTENT] startActivity: " + (intent.getComponent() ? intent.getComponent().flattenToString() : "null"));
        if (intent.getAction()) console.log("  action: " + intent.getAction());
        if (intent.getDataString()) console.log("  data: " + intent.getDataString());
        return this.startActivity(intent);
    };

    // Hook startActivity(Intent, Bundle)
    Context.startActivity.overload("android.content.Intent", "android.os.Bundle").implementation = function(intent, options) {
        var extras = extractExtras(intent);
        send({type: "intent", action: "startActivity_options", component: intent.getComponent() ? intent.getComponent().flattenToString() : "null", extras: extras});
        console.log("[INTENT] startActivity (with options): " + (intent.getComponent() ? intent.getComponent().flattenToString() : "null"));
        return this.startActivity(intent, options);
    };

    // Hook startService
    Context.startService.implementation = function(intent) {
        var extras = extractExtras(intent);
        send({type: "intent", action: "startService", component: intent.getComponent() ? intent.getComponent().flattenToString() : "null", extras: extras});
        console.log("[INTENT] startService: " + (intent.getComponent() ? intent.getComponent().flattenToString() : "null"));
        return this.startService(intent);
    };

    // Hook startForegroundService (Android 8+)
    try {
        Context.startForegroundService.implementation = function(intent) {
            var extras = extractExtras(intent);
            send({type: "intent", action: "startForegroundService", component: intent.getComponent() ? intent.getComponent().flattenToString() : "null", extras: extras});
            console.log("[INTENT] startForegroundService: " + (intent.getComponent() ? intent.getComponent().flattenToString() : "null"));
            return this.startForegroundService(intent);
        };
    } catch(e) {}

    // Hook sendBroadcast
    Context.sendBroadcast.overload("android.content.Intent").implementation = function(intent) {
        var extras = extractExtras(intent);
        send({type: "intent", action: "sendBroadcast", receiver: intent.getComponent() ? intent.getComponent().flattenToString() : "action:" + intent.getAction(), extras: extras});
        console.log("[INTENT] sendBroadcast: " + (intent.getComponent() ? intent.getComponent().flattenToString() : intent.getAction()));
        return this.sendBroadcast(intent);
    };

    // Hook sendOrderedBroadcast
    try {
        Context.sendOrderedBroadcast.overload("android.content.Intent", "java.lang.String").implementation = function(intent, receiverPermission) {
            var extras = extractExtras(intent);
            send({type: "intent", action: "sendOrderedBroadcast", receiver: intent.getAction(), permission: receiverPermission, extras: extras});
            console.log("[INTENT] sendOrderedBroadcast: " + intent.getAction());
            return this.sendOrderedBroadcast(intent, receiverPermission);
        };
    } catch(e) {}

    // Hook sendBroadcast with receiverPermission
    Context.sendBroadcast.overload("android.content.Intent", "java.lang.String").implementation = function(intent, receiverPermission) {
        var extras = extractExtras(intent);
        send({type: "intent", action: "sendBroadcast_perm", receiver: intent.getAction(), permission: receiverPermission, extras: extras});
        console.log("[INTENT] sendBroadcast (perm): " + intent.getAction());
        return this.sendBroadcast(intent, receiverPermission);
    };

    // Hook Intent.parseUri
    var Intent = Java.use("android.content.Intent");
    Intent.parseUri.implementation = function(uri, flags) {
        send({type: "intent", action: "parseUri", uri: uri, flags: flags});
        console.log("[INTENT] parseUri: " + uri);
        return this.parseUri(uri, flags);
    };

    // Helper: extract extras from Intent
    function extractExtras(intent) {
        try {
            var extras = intent.getExtras();
            if (!extras) return null;
            var result = {};
            var keys = extras.keySet().iterator();
            while (keys.hasNext()) {
                var key = keys.next();
                var val = extras.get(key);
                result[key] = val ? val.toString() : "null";
            }
            return result;
        } catch(e) {
            return {error: e.toString()};
        }
    }

    console.log("[*] Intent hooks loaded");
});
