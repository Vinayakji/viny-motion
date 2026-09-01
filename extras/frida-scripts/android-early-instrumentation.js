/**
 * android-early-instrumentation.js
 * Early instrumentation before app code runs
 * Hooks Application.onCreate, ContentProviders, and class loaders
 *
 * Usage: frida -U -f <package> -l android-early-instrumentation.js --no-pause
 */

'use strict';

console.log('[early-instr] Setting up early instrumentation...');

Java.perform(function () {
    // 1. Hook Application.onCreate
    var Application = Java.use('android.app.Application');
    Application.onCreate.implementation = function () {
        console.log('[early-instr] Application.onCreate() called');
        console.log('[early-instr] Package: ' + this.getPackageName());
        this.onCreate();
        console.log('[early-instr] Application.onCreate() completed');
    };

    // 2. Hook ContentProvider.onCreate for all providers
    var ContentProvider = Java.use('android.content.ContentProvider');
    ContentProvider.onCreate.implementation = function () {
        var name = this.getClass().getName();
        console.log('[early-instr] ContentProvider.onCreate(): ' + name);
        return this.onCreate();
    };

    // 3. Hook DexClassLoader for dynamic code loading
    var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
    DexClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader')
        .implementation = function (dexPath, optimizedDir, librarySearchPath, parent) {
            console.log('[early-instr] DexClassLoader: ' + dexPath);
            if (optimizedDir) console.log('[early-instr]   optimizedDir: ' + optimizedDir);
            if (librarySearchPath) console.log('[early-instr]   libPath: ' + librarySearchPath);
            return this.$init(dexPath, optimizedDir, librarySearchPath, parent);
        };

    // 4. Hook PathClassLoader
    var PathClassLoader = Java.use('dalvik.system.PathClassLoader');
    PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader')
        .implementation = function (dexPath, parent) {
            console.log('[early-instr] PathClassLoader: ' + dexPath);
            return this.$init(dexPath, parent);
        };

    // 5. Hook InMemoryDexClassLoader (API 26+)
    try {
        var InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');
        InMemoryDexClassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader')
            .implementation = function (buf, parent) {
                console.log('[early-instr] InMemoryDexClassLoader: ' + buf.remaining() + ' bytes');
                return this.$init(buf, parent);
            };
        console.log('[early-instr] InMemoryDexClassLoader hook installed');
    } catch (e) {
        console.log('[early-instr] InMemoryDexClassLoader not available (API < 26)');
    }

    // 6. Hook System.loadLibrary for native lib loading
    var System = Java.use('java.lang.System');
    System.loadLibrary.implementation = function (lib) {
        console.log('[early-instr] System.loadLibrary(' + lib + ')');
        return this.loadLibrary(lib);
    };

    // 7. Hook Runtime.exec for command execution
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmd) {
        console.log('[early-instr] Runtime.exec: ' + cmd.join(' '));
        return this.exec(cmd);
    };

    console.log('[early-instr] All hooks installed');
});
