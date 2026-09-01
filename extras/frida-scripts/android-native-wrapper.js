/**
 * android-native-wrapper.js
 * Hook native method wrappers (JNI_OnLoad, RegisterNatives)
 * Trace native method registrations and calls
 *
 * Usage: frida -U -f <package> -l android-native-wrapper.js --no-pause
 */

'use strict';

console.log('[native] Loading native wrapper hooks...');

var registeredNatives = {};

// Hook RegisterNatives to trace all JNI registrations
var Module = Process.enumerateModules()[0];
var symbols = Module.enumerateSymbols();

// Find RegisterNatives in libart
var artModule = Process.findModuleByName('libart.so');
if (artModule) {
    var symbols = artModule.enumerateSymbols();
    symbols.forEach(function (sym) {
        if (sym.name.indexOf('RegisterNatives') !== -1 && sym.name.indexOf('CheckJNI') === -1) {
            Interceptor.attach(sym.address, {
                onEnter: function (args) {
                    var env = args[0];
                    var jclass = args[1];
                    var methodsPtr = args[2];
                    var nMethods = args[3].toInt32();

                    console.log('[native] RegisterNatives: ' + nMethods + ' methods');

                    for (var i = 0; i < nMethods; i++) {
                        var namePtr = methodsPtr.add(i * Process.pointerSize * 3).readPointer();
                        var sigPtr = methodsPtr.add(i * Process.pointerSize * 3 + Process.pointerSize).readPointer();
                        var fnPtr = methodsPtr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2).readPointer();

                        var name = namePtr.readCString();
                        var sig = sigPtr.readCString();

                        // Resolve class name
                        var className = '';
                        try {
                            var classLoader = Java.vm.tryGetEnv();
                            if (classLoader) {
                                className = Java.vm.tryGetEnv().getStringUtfChars(
                                    Java.vm.tryGetEnv().callObjectMethod(jclass,
                                        Java.vm.tryGetEnv().getMethodId(
                                            Java.vm.tryGetEnv().findClass('java/lang/Class'),
                                            'getName', '()Ljava/lang/String;'
                                        )
                                    )
                                );
                            }
                        } catch (e) {
                            className = 'unknown';
                        }

                        console.log('[native]   ' + name + sig + ' @ ' + fnPtr);
                        registeredNatives[name] = {
                            signature: sig,
                            address: fnPtr,
                            className: className
                        };
                    }
                }
            });
            console.log('[native] RegisterNatives hook installed at ' + sym.address);
        }
    });
}

// Hook JNI_OnLoad
var jniOnLoad = Module.findExportByName(null, 'JNI_OnLoad');
if (jniOnLoad) {
    Interceptor.attach(jniOnLoad, {
        onEnter: function (args) {
            console.log('[native] JNI_OnLoad called from ' + this.returnAddress);
        },
        onLeave: function (retval) {
            console.log('[native] JNI_OnLoad returned: ' + retval);
        }
    });
    console.log('[native] JNI_OnLoad hook installed');
}

// List native modules
Process.enumerateModules().forEach(function (mod) {
    if (mod.name.indexOf('.so') !== -1) {
        console.log('[native] Module: ' + mod.name + ' @ ' + mod.base + ' (' + mod.size + ' bytes)');
    }
});

console.log('[native] Loaded');
