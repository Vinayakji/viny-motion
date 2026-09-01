/**
 * dynamic-code-analysis.js
 * Analyze dynamic code loading: DexClassLoader, InMemoryDexClassLoader, PathClassLoader
 * Hook all class loading paths to detect dynamic code injection
 *
 * Usage: frida -U -f <package> -l dynamic-code-analysis.js --no-pause
 */

'use strict';

console.log('[dynload] Dynamic code loading analyzer loaded');

var classLoaders = [];
var dexFiles = [];
var nativeLoads = [];

Java.perform(function () {
    // ─── DexClassLoader ────────────────────────────────
    try {
        var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
        DexClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader')
            .implementation = function (dexPath, optDir, libPath, parent) {
                console.log('[dynload] DexClassLoader: ' + dexPath);
                console.log('[dynload]   optDir: ' + optDir);
                console.log('[dynload]   libPath: ' + libPath);

                // Read and dump DEX
                try {
                    var File = Java.use('java.io.File');
                    var f = File.$new(dexPath);
                    if (f.exists()) {
                        var size = f.length();
                        console.log('[dynload]   DEX size: ' + size + ' bytes');

                        // Copy to sdcard for analysis
                        var Runtime = Java.use('java.lang.Runtime');
                        var runtime = Runtime.getRuntime();
                        var outPath = '/sdcard/dyn_dex_' + Date.now() + '.dex';
                        runtime.exec(['cp', dexPath, outPath]);
                        console.log('[dynload]   Dumped -> ' + outPath);

                        dexFiles.push({ path: dexPath, size: size, dumpedTo: outPath });
                    }
                } catch (e) {
                    console.log('[dynload]   DEX dump failed: ' + e);
                }

                classLoaders.push({
                    type: 'DexClassLoader',
                    dexPath: dexPath,
                    optDir: optDir,
                    backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress)
                });

                return this.$init(dexPath, optDir, libPath, parent);
            };
    } catch (e) {
        console.log('[dynload] DexClassLoader hook failed: ' + e);
    }

    // ─── InMemoryDexClassLoader (API 26+) ──────────────
    try {
        var IMDCL = Java.use('dalvik.system.InMemoryDexClassLoader');

        // ByteBuffer overload
        IMDCL.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader')
            .implementation = function (buf, parent) {
                var size = buf.remaining();
                console.log('[dynload] InMemoryDexClassLoader (ByteBuffer): ' + size + ' bytes');

                // Dump buffer
                try {
                    var bytes = Java.array('byte', Java.use('java.lang.reflect.Array')
                        .newInstance(Java.use('java.lang.Byte').TYPE, size));
                    var pos = buf.position();
                    buf.get(bytes);
                    buf.position(pos);

                    var fos = Java.use('java.io.FileOutputStream').$new(
                        '/sdcard/dyn_memdex_' + Date.now() + '.dex');
                    fos.write(bytes);
                    fos.close();
                    console.log('[dynload]   Dumped -> /sdcard/dyn_memdex_' + Date.now() + '.dex');
                    dexFiles.push({ path: 'InMemory(ByteBuffer)', size: size });
                } catch (e) {
                    console.log('[dynload]   Dump failed: ' + e);
                }

                classLoaders.push({
                    type: 'InMemoryDexClassLoader',
                    size: size,
                    backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress)
                });

                return this.$init(buf, parent);
            };

        // InputStream overload
        IMDCL.$init.overload('java.io.InputStream', 'java.lang.ClassLoader')
            .implementation = function (stream, parent) {
                console.log('[dynload] InMemoryDexClassLoader (InputStream)');
                classLoaders.push({
                    type: 'InMemoryDexClassLoader InputStream',
                    backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress)
                });
                return this.$init(stream, parent);
            };
    } catch (e) {
        console.log('[dynload] InMemoryDexClassLoader hook failed');
    }

    // ─── PathClassLoader ───────────────────────────────
    try {
        var PathClassLoader = Java.use('dalvik.system.PathClassLoader');
        PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader')
            .implementation = function (dexPath, parent) {
                console.log('[dynload] PathClassLoader: ' + dexPath);
                classLoaders.push({ type: 'PathClassLoader', dexPath: dexPath });
                return this.$init(dexPath, parent);
            };
    } catch (e) {}

    // ─── DexFile ───────────────────────────────────────
    try {
        var DexFile = Java.use('dalvik.system.DexFile');
        DexFile.loadDex.overload('java.lang.String', 'java.lang.String', 'int')
            .implementation = function (sourcePathName, outputPathName, flags) {
                console.log('[dynload] DexFile.loadDex: ' + sourcePathName);
                return this.loadDex(sourcePathName, outputPathName, flags);
            };
    } catch (e) {}

    // ─── Runtime.exec for DEX loading ──────────────────
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmdArray) {
        var cmd = cmdArray.join(' ');
        if (cmd.indexOf('dex2oat') !== -1 || cmd.indexOf('.dex') !== -1 ||
            cmd.indexOf('dalvik') !== -1) {
            console.log('[dynload] DEX-related exec: ' + cmd);
        }
        return this.exec(cmdArray);
    };

    console.log('[dynload] All hooks installed');
});

function dumpClassLoaderInfo() {
    console.log('\n[dynload] === Class Loader Summary ===');
    console.log('[dynload] Total class loaders: ' + classLoaders.length);
    console.log('[dynload] DEX files found: ' + dexFiles.length);

    classLoaders.forEach(function (cl, i) {
        console.log('[dynload] [' + i + '] ' + cl.type + ' ' + (cl.dexPath || cl.size || ''));
        if (cl.backtrace) {
            cl.backtrace.slice(0, 3).forEach(function (frame) {
                console.log('[dynload]   ' + frame);
            });
        }
    });
    console.log('[dynload] === End ===\n');
}

console.log('[dynload] Call dumpClassLoaderInfo() for summary');
console.log('[dynload] Loaded');
