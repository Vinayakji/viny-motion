/**
 * shared-prefs-dumper.js
 * Dump all SharedPreferences to console and to file
 * Useful for finding stored tokens, session data, user PII
 *
 * Usage: frida -U -f <package> -l shared-prefs-dumper.js --no-pause
 */

'use strict';

console.log('[spdump] SharedPreferences dumper loaded');

Java.perform(function () {
    var Context = Java.use('android.content.Context');
    var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');

    // Track all SharedPreferences files
    var spFiles = {};

    // Hook getSharedPreferences to track all SP instances
    Context.getSharedPreferences.implementation = function (name, mode) {
        var sp = this.getSharedPreferences(name, mode);
        spFiles[name] = sp;
        console.log('[spdump] SharedPreferences opened: ' + name);
        return sp;
    };

    // Hook SharedPreferencesImpl.loadFromDisk to capture when data is ready
    SharedPreferencesImpl.loadFromDisk.implementation = function () {
        this.loadFromDisk();
        var name = this.mFile.value.getAbsolutePath();
        console.log('[spdump] SP loaded: ' + name);
    };

    /**
     * Dump all tracked SharedPreferences
     */
    window.dumpAllSharedPrefs = function () {
        console.log('[spdump] === Dumping all SharedPreferences ===');

        Java.choose('android.app.SharedPreferencesImpl', {
            onMatch: function (instance) {
                try {
                    var file = instance.mFile.value.getAbsolutePath();
                    var map = instance.mMap.value;
                    var keys = map.keySet().iterator();

                    console.log('\n[spdump] File: ' + file);
                    while (keys.hasNext()) {
                        var key = keys.next();
                        var val = map.get(key);
                        console.log('[spdump]   ' + key + ' = ' + val);
                    }
                } catch (e) {
                    console.log('[spdump] Error: ' + e);
                }
            },
            onComplete: function () {
                console.log('[spdump] === Dump complete ===');
            }
        });
    };

    /**
     * Hook all put methods to capture writes
     */
    SharedPreferencesImpl.edit.implementation = function () {
        var editor = this.edit();
        var origCommit = editor.commit;
        var origApply = editor.apply;

        // Hook putString
        var EditorImpl = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
        EditorImpl.putString.implementation = function (key, value) {
            console.log('[spdump] PUT string: ' + key + ' = ' + value);
            return this.putString(key, value);
        };

        EditorImpl.putInt.implementation = function (key, value) {
            console.log('[spdump] PUT int: ' + key + ' = ' + value);
            return this.putInt(key, value);
        };

        EditorImpl.putBoolean.implementation = function (key, value) {
            console.log('[spdump] PUT boolean: ' + key + ' = ' + value);
            return this.putBoolean(key, value);
        };

        EditorImpl.putFloat.implementation = function (key, value) {
            console.log('[spdump] PUT float: ' + key + ' = ' + value);
            return this.putFloat(key, value);
        };

        EditorImpl.putLong.implementation = function (key, value) {
            console.log('[spdump] PUT long: ' + key + ' = ' + value);
            return this.putLong(key, value);
        };

        EditorImpl.putStringSet.implementation = function (key, values) {
            console.log('[spdump] PUT stringSet: ' + key + ' = ' + values);
            return this.putStringSet(key, values);
        };

        return editor;
    };

    console.log('[spdump] Call dumpAllSharedPrefs() to dump all SP files');
});

console.log('[spdump] Loaded');
