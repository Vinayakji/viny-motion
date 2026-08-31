// sharedprefs-hook.js — Hook SharedPreferences to capture all key-value writes
Java.perform(function() {
    var Tag = "SHARED_PREFS_HOOK";

    // Hook SharedPreferencesImpl$EditorImpl.commit/apply to capture writes
    try {
        var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");

        SharedPreferencesImpl.getString.implementation = function(key, defValue) {
            var val = this.getString(key, defValue);
            send({type: "sharedprefs", action: "getString", key: key, value: val ? val.toString() : defValue});
            console.log("[SP] getString(" + key + ") = " + val);
            return val;
        };

        SharedPreferencesImpl.getInt.implementation = function(key, defValue) {
            var val = this.getInt(key, defValue);
            send({type: "sharedprefs", action: "getInt", key: key, value: val});
            console.log("[SP] getInt(" + key + ") = " + val);
            return val;
        };

        SharedPreferencesImpl.getBoolean.implementation = function(key, defValue) {
            var val = this.getBoolean(key, defValue);
            send({type: "sharedprefs", action: "getBoolean", key: key, value: val});
            console.log("[SP] getBoolean(" + key + ") = " + val);
            return val;
        };

        SharedPreferencesImpl.getLong.implementation = function(key, defValue) {
            var val = this.getLong(key, defValue);
            send({type: "sharedprefs", action: "getLong", key: key, value: val});
            return val;
        };

        SharedPreferencesImpl.getFloat.implementation = function(key, defValue) {
            var val = this.getFloat(key, defValue);
            send({type: "sharedprefs", action: "getFloat", key: key, value: val});
            return val;
        };

        SharedPreferencesImpl.getStringSet.implementation = function(key, defValue) {
            var val = this.getStringSet(key, defValue);
            send({type: "sharedprefs", action: "getStringSet", key: key, value: val ? val.toString() : "null"});
            return val;
        };
    } catch(e) {
        console.log("[*] SharedPreferencesImpl hooks failed: " + e);
    }

    // Hook EditorImpl for writes
    try {
        var EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");

        EditorImpl.putString.implementation = function(key, value) {
            send({type: "sharedprefs", action: "putString", key: key, value: value ? value.toString() : "null"});
            console.log("[SP] putString(" + key + ", " + value + ")");
            return this.putString(key, value);
        };

        EditorImpl.putInt.implementation = function(key, value) {
            send({type: "sharedprefs", action: "putInt", key: key, value: value});
            console.log("[SP] putInt(" + key + ", " + value + ")");
            return this.putInt(key, value);
        };

        EditorImpl.putBoolean.implementation = function(key, value) {
            send({type: "sharedprefs", action: "putBoolean", key: key, value: value});
            console.log("[SP] putBoolean(" + key + ", " + value + ")");
            return this.putBoolean(key, value);
        };

        EditorImpl.putLong.implementation = function(key, value) {
            send({type: "sharedprefs", action: "putLong", key: key, value: value});
            return this.putLong(key, value);
        };

        EditorImpl.putFloat.implementation = function(key, value) {
            send({type: "sharedprefs", action: "putFloat", key: key, value: value});
            return this.putFloat(key, value);
        };

        EditorImpl.commit.implementation = function() {
            send({type: "sharedprefs", action: "commit"});
            console.log("[SP] Editor.commit()");
            return this.commit();
        };

        EditorImpl.apply.implementation = function() {
            send({type: "sharedprefs", action: "apply"});
            console.log("[SP] Editor.apply()");
            return this.apply();
        };
    } catch(e) {
        console.log("[*] EditorImpl hooks failed: " + e);
    }

    console.log("[*] SharedPreferences hooks loaded");
});
