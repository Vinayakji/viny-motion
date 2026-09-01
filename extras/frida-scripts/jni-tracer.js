/**
 * jni-tracer.js
 * Trace JNI calls between Java and native code
 * Logs all JNI function invocations with arguments
 *
 * Usage: frida -U -f <package> -l jni-tracer.js --no-pause
 */

'use strict';

console.log('[jni] JNI tracer loaded');

var jniCallCount = 0;
var jniEnabled = true;

// Key JNI functions to monitor (high-value for security testing)
var criticalJNI = [
    'FindClass', 'GetMethodID', 'GetStaticMethodID',
    'CallObjectMethod', 'CallBooleanMethod', 'CallIntMethod',
    'CallStaticObjectMethod', 'CallStaticBooleanMethod',
    'GetStringUTFChars', 'NewStringUTF',
    'GetByteArrayElements', 'ReleaseByteArrayElements',
    'RegisterNatives', 'UnregisterNatives',
    'GetFieldID', 'GetStaticFieldID',
    'GetObjectField', 'SetObjectField',
    'GetBooleanField', 'GetIntField', 'GetLongField',
    'SetBooleanField', 'SetIntField', 'SetLongField',
    'NewObject', 'NewByteArray', 'NewString',
    'Throw', 'ThrowNew', 'ExceptionCheck', 'ExceptionOccurred',
    'DefineClass', 'LoadClass', 'FindLibrary'
];

// Hook JNI functions in libart.so
var artModule = Process.findModuleByName('libart.so');
if (artModule) {
    artModule.enumerateSymbols().forEach(function (sym) {
        // Match JNI function names
        var match = sym.name.match(/JNI[^)]*?(\w+_\w+)/);
        if (!match) return;

        var funcName = match[1];
        var isCritical = criticalJNI.some(function (c) { return funcName.indexOf(c) !== -1; });

        Interceptor.attach(sym.address, {
            onEnter: function (args) {
                if (!jniEnabled) return;
                jniCallCount++;

                var prefix = isCritical ? '[JNI-CRIT]' : '[JNI]';

                // Log the call with first 3 args
                var a0 = args[0]; // JNIEnv*
                var a1 = args[1]; // varies
                var a2 = args[2]; // varies

                console.log(prefix + ' #' + jniCallCount + ' ' + funcName +
                    '(' + a1 + ', ' + a2 + ')');

                if (isCritical) {
                    // For critical functions, read string args
                    try {
                        if (funcName.indexOf('GetStringUTFChars') !== -1) {
                            var str = a1.readCString();
                            console.log('[JNI-CRIT]   string: "' + str + '"');
                        }
                        if (funcName.indexOf('FindClass') !== -1) {
                            var cls = a1.readCString();
                            console.log('[JNI-CRIT]   class: "' + cls + '"');
                        }
                        if (funcName.indexOf('FindLibrary') !== -1) {
                            var lib = a1.readCString();
                            console.log('[JNI-CRIT]   library: "' + lib + '"');
                        }
                    } catch (e) {}
                }
            }
        });
    });

    console.log('[jni] JNI tracer installed on libart.so');
}

// Console controls
function toggleJNI() {
    jniEnabled = !jniEnabled;
    console.log('[jni] JNI tracing ' + (jniEnabled ? 'ENABLED' : 'DISABLED'));
}

function jniStats() {
    console.log('[jni] Total JNI calls traced: ' + jniCallCount);
}

console.log('[jni] Call toggleJNI() to enable/disable, jniStats() for count');
console.log('[jni] Loaded');
