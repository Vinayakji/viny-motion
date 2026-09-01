/**
 * flutter-channel-hook.js
 * Intercept Flutter MethodChannel/EventChannel communication
 * Dump arguments from Dart-to-native and native-to-Dart calls
 *
 * Usage: frida -U -f <package> -l flutter-channel-hook.js --no-pause
 */

'use strict';

console.log('[flutter] Flutter channel hook loaded');

var channelLog = [];

Java.perform(function () {
    // 1. Hook FlutterView/FlutterEngine initialization
    try {
        var FlutterEngine = Java.use('io.flutter.embedding.engine.FlutterEngine');
        FlutterEngine.$init.overload('android.content.Context').implementation = function (ctx) {
            console.log('[flutter] FlutterEngine created');
            return this.$init(ctx);
        };
    } catch (e) {
        console.log('[flutter] FlutterEngine class not found');
    }

    // 2. Hook MethodChannel.MethodCallHandler
    try {
        var MethodChannel = Java.use('io.flutter.plugin.common.MethodChannel');
        MethodChannel.invokeMethod.overload('java.lang.String', 'java.lang.Object')
            .implementation = function (method, args) {
                console.log('[flutter] invokeMethod: ' + method + ' args=' + (args !== null ? args.toString() : 'null'));
                channelLog.push({ type: 'invoke', method: method, args: args });
                return this.invokeMethod(method, args);
            };

        MethodChannel.invokeMethod.overload('java.lang.String', 'java.lang.Object', 'io.flutter.plugin.common.MethodChannel$Result')
            .implementation = function (method, args, callback) {
                console.log('[flutter] invokeMethod (async): ' + method + ' args=' + (args !== null ? args.toString() : 'null'));
                channelLog.push({ type: 'invoke_async', method: method, args: args });
                return this.invokeMethod(method, args, callback);
            };
    } catch (e) {
        console.log('[flutter] MethodChannel class not found');
    }

    // 3. Hook MethodChannel.MethodCallHandler.invoke
    try {
        var MethodCallHandler = Java.use('io.flutter.plugin.common.MethodChannel$MethodCallHandler');
        // We can't hook interface methods directly, but we can hook implementations
    } catch (e) {}

    // 4. Hook EventChannel
    try {
        var EventChannel = Java.use('io.flutter.plugin.common.EventChannel');
        EventChannel.setStreamHandler.implementation = function (handler) {
            console.log('[flutter] EventChannel.setStreamHandler: ' + (handler !== null ? handler.getClass().getName() : 'null'));
            return this.setStreamHandler(handler);
        };
    } catch (e) {}

    // 5. Hook StandardMethodCodec to capture all encoded/decoded messages
    try {
        var StandardMethodCodec = Java.use('io.flutter.plugin.common.StandardMethodCodec');
        StandardMethodCodec.encodeMethodCall.implementation = function (methodCall) {
            var method = methodCall.getMethod().toString();
            var args = methodCall.getArguments();
            console.log('[flutter] Codec encode: ' + method + ' args=' + (args !== null ? args.toString() : 'null'));
            return this.encodeMethodCall(methodCall);
        };
    } catch (e) {}

    console.log('[flutter] MethodChannel hooks installed');
});

// Console function to dump channel log
function dumpFlutterChannels() {
    console.log('[flutter] === Channel Call Log (' + channelLog.length + ' entries) ===');
    channelLog.forEach(function (entry, i) {
        console.log('[flutter] [' + i + '] ' + entry.type + ': ' + entry.method);
        if (entry.args !== null) console.log('[flutter]   args: ' + entry.args.toString());
    });
}

console.log('[flutter] Call dumpFlutterChannels() to see channel calls');
console.log('[flutter] Loaded');
