/**
 * dynamic-loading-analyzer.js
 * Analyze dynamic code loading (DexClassLoader, PathClassLoader, InMemoryDexClassLoader)
 * Dump loaded DEX files and track class loading patterns
 *
 * Usage: frida -U -f <package> -l dynamic-loading-analyzer.js --no-pause
 */

'use strict';

console.log('[dla] Dynamic loading analyzer loaded');

var loadEvents = [];
var loadedClasses = {};

Java.perform(function () {
    // ─── DexClassLoader ────────────────────────────────
    try {
        var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
        DexClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader')
            .implementation = function (dexPath, optimizedDir, librarySearchPath, parent) {
                console.log('[dla] DexClassLoader created:');
                console.log('[dla]   dexPath: ' + dexPath);
                console.log('[dla]   optimizedDir: ' + optimizedDir);
                console.log('[dla]   librarySearchPath: ' + librarySearchPath);
                loadEvents.push({
                    type: 'DexClassLoader',
                    dexPath: dexPath,
                    optimizedDir: optimizedDir,
                    librarySearchPath: librarySearchPath,
                    timestamp: Date.now()
                });

                // Try to dump the DEX
                try {
                    var File = Java.use('java.io.File');
                    var f = File.$new(dexPath);
                    if (f.exists()) {
                        console.log('[dla]   DEX size: ' + f.length() + ' bytes');
                    }
                } catch (e) {}

                return this.$init(dexPath, optimizedDir, librarySearchPath, parent);
            };
    } catch (e) {}

    // ─── PathClassLoader ───────────────────────────────
    try {
        var PathClassLoader = Java.use('dalvik.system.PathClassLoader');
        PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader')
            .implementation = function (dexPath, parent) {
                console.log('[dla] PathClassLoader created: ' + dexPath);
                loadEvents.push({
                    type: 'PathClassLoader',
                    dexPath: dexPath,
                    timestamp: Date.now()
                });
                return this.$init(dexPath, parent);
            };

        PathClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.ClassLoader')
            .implementation = function (dexPath, librarySearchPath, parent) {
                console.log('[dla] PathClassLoader created: ' + dexPath + ' (lib: ' + librarySearchPath + ')');
                loadEvents.push({
                    type: 'PathClassLoader',
                    dexPath: dexPath,
                    librarySearchPath: librarySearchPath,
                    timestamp: Date.now()
                });
                return this.$init(dexPath, librarySearchPath, parent);
            };
    } catch (e) {}

    // ─── InMemoryDexClassLoader (Android 8+) ───────────
    try {
        var InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');
        InMemoryDexClassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader')
            .implementation = function (buf, parent) {
                console.log('[dla] InMemoryDexClassLoader created (buffer size: ' + buf.remaining() + ')');
                loadEvents.push({
                    type: 'InMemoryDexClassLoader',
                    bufferSize: buf.remaining(),
                    timestamp: Date.now()
                });

                // Try to dump buffer contents
                try {
                    var bytes = Java.array('byte', Java.use('java.lang.reflect.Array')
                        .newInstance(Java.use('java.lang.Byte').class, buf.remaining()));
                    buf.get(bytes);
                    buf.position(0); // Reset position

                    // Check for DEX magic
                    if (bytes.length > 4 && bytes[0] === 0x64 && bytes[1] === 0x65 && bytes[2] === 0x78 && bytes[3] === 0x0a) {
                        console.log('[dla]   DEX magic confirmed');
                    }
                } catch (e) {}

                return this.$init(buf, parent);
            };

        InMemoryDexClassLoader.$init.overload('[Ljava.nio.ByteBuffer;', 'java.lang.ClassLoader')
            .implementation = function (bufs, parent) {
                console.log('[dla] InMemoryDexClassLoader created (' + bufs.length + ' buffers)');
                loadEvents.push({
                    type: 'InMemoryDexClassLoader',
                    bufferCount: bufs.length,
                    timestamp: Date.now()
                });
                return this.$init(bufs, parent);
            };
    } catch (e) {}

    // ─── DexFile loading ───────────────────────────────
    try {
        var DexFile = Java.use('dalvik.system.DexFile');
        DexFile.loadDex.overload('java.lang.String', 'java.lang.String', 'int')
            .implementation = function (sourcePathName, outputPathName, flags) {
                console.log('[dla] DexFile.loadDex: ' + sourcePathName);
                loadEvents.push({
                    type: 'DexFile.loadDex',
                    sourcePath: sourcePathName,
                    outputPath: outputPathName,
                    timestamp: Date.now()
                });
                return this.loadDex(sourcePathName, outputPathName, flags);
            };
    } catch (e) {}

    // ─── ClassLoader.loadClass ─────────────────────────
    try {
        var ClassLoader = Java.use('java.lang.ClassLoader');
        ClassLoader.loadClass.overload('java.lang.String', 'boolean').implementation = function (name, resolve) {
            if (!loadedClasses[name]) {
                loadedClasses[name] = 0;
            }
            loadedClasses[name]++;
            return this.loadClass(name, resolve);
        };
    } catch (e) {}

    console.log('[dla] All hooks installed');
});

function dumpLoadingEvents() {
    console.log('\n[dla] === Dynamic Loading Events (' + loadEvents.length + ') ===');
    loadEvents.forEach(function (event, i) {
        console.log('[dla] [' + i + '] ' + event.type);
        if (event.dexPath) console.log('[dla]   path: ' + event.dexPath);
        if (event.bufferSize) console.log('[dla]   size: ' + event.bufferSize + ' bytes');
    });
    console.log('[dla] === End ===\n');
}

function loadedClassStats() {
    var names = Object.keys(loadedClasses);
    console.log('[dla] Loaded classes: ' + names.length);
    var suspicious = names.filter(function (n) {
        return n.indexOf('dalvik.system') !== -1 ||
               n.indexOf('reflect') !== -1 ||
               n.indexOf('ClassLoader') !== -1;
    });
    console.log('[dla] System classes loaded: ' + suspicious.length);
}

console.log('[dla] Functions: dumpLoadingEvents(), loadedClassStats()');
console.log('[dla] Loaded');
