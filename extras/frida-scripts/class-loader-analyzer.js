/**
 * class-loader-analyzer.js
 * Analyze all ClassLoaders to understand class resolution paths
 * Detect class loading anomalies and hijacking opportunities
 *
 * Usage: frida -U -f <package> -l class-loader-analyzer.js --no-pause
 */

'use strict';

console.log('[clsload] ClassLoader analyzer loaded');

var loaders = [];
var classResolveLog = [];

Java.perform(function () {
    // ─── BaseDexClassLoader ────────────────────────────
    try {
        var BaseDexClassLoader = Java.use('dalvik.system.BaseDexClassLoader');
        BaseDexClassLoader.findClass.implementation = function (name) {
            try {
                var result = this.findClass(name);
                classResolveLog.push({
                    loader: this.getClass().getName(),
                    class: name,
                    resolved: true,
                    address: this.findResource(name)
                });
                return result;
            } catch (e) {
                classResolveLog.push({
                    loader: this.getClass().getName(),
                    class: name,
                    resolved: false,
                    error: e.toString()
                });
                throw e;
            }
        };

        BaseDexClassLoader.loadClass.overload('java.lang.String', 'boolean')
            .implementation = function (name, resolve) {
                classResolveLog.push({
                    loader: this.getClass().getName(),
                    class: name,
                    type: 'loadClass'
                });
                return this.loadClass(name, resolve);
            };
    } catch (e) {}

    // ─── PathList (for DexPathList) ────────────────────
    try {
        var DexPathList = Java.use('dalvik.system.DexPathList');
        DexPathList.findClass.implementation = function (name, loader) {
            try {
                var result = this.findClass(name, loader);
                classResolveLog.push({
                    loader: 'DexPathList',
                    class: name,
                    resolved: true
                });
                return result;
            } catch (e) {
                classResolveLog.push({
                    loader: 'DexPathList',
                    class: name,
                    resolved: false
                });
                throw e;
            }
        };
    } catch (e) {}

    // ─── URLClassLoader ────────────────────────────────
    try {
        var URLClassLoader = Java.use('java.net.URLClassLoader');
        URLClassLoader.loadClass.overload('java.lang.String', 'boolean')
            .implementation = function (name, resolve) {
                console.log('[clsload] URLClassLoader.loadClass: ' + name);
                return this.loadClass(name, resolve);
            };
    } catch (e) {}

    // ─── PathClassLoader ───────────────────────────────
    try {
        var PathClassLoader = Java.use('dalvik.system.PathClassLoader');
        PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader')
            .implementation = function (dexPath, parent) {
                console.log('[clsload] PathClassLoader: ' + dexPath);
                loaders.push({ type: 'PathClassLoader', path: dexPath });
                return this.$init(dexPath, parent);
            };

        PathClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.ClassLoader')
            .implementation = function (dexPath, librarySearchPath, parent) {
                console.log('[clsload] PathClassLoader: ' + dexPath + ' lib=' + librarySearchPath);
                loaders.push({ type: 'PathClassLoader', path: dexPath, libPath: librarySearchPath });
                return this.$init(dexPath, librarySearchPath, parent);
            };
    } catch (e) {}

    // ─── DexClassLoader ────────────────────────────────
    try {
        var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
        DexClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader')
            .implementation = function (dexPath, optDir, libPath, parent) {
                console.log('[clsload] DexClassLoader: ' + dexPath);
                loaders.push({ type: 'DexClassLoader', path: dexPath, optDir: optDir, libPath: libPath });
                return this.$init(dexPath, optDir, libPath, parent);
            };
    } catch (e) {}

    // ─── InMemoryDexClassLoader ────────────────────────
    try {
        var IMDCL = Java.use('dalvik.system.InMemoryDexClassLoader');
        IMDCL.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader')
            .implementation = function (buf, parent) {
                console.log('[clsload] InMemoryDexClassLoader: ' + buf.remaining() + ' bytes');
                loaders.push({ type: 'InMemoryDexClassLoader', size: buf.remaining() });
                return this.$init(buf, parent);
            };
    } catch (e) {}

    console.log('[clsload] All hooks installed');
});

function dumpClassLoaderInfo() {
    console.log('\n[clsload] === ClassLoader Summary ===');
    console.log('[clsload] Loaders found: ' + loaders.length);

    loaders.forEach(function (l, i) {
        console.log('[clsload] [' + i + '] ' + l.type);
        if (l.path) console.log('[clsload]   path: ' + l.path);
        if (l.libPath) console.log('[clsload]   lib: ' + l.libPath);
    });

    // Show resolved classes with unique loaders
    var uniqueLoaders = {};
    classResolveLog.forEach(function (entry) {
        if (!uniqueLoaders[entry.loader]) uniqueLoaders[entry.loader] = 0;
        uniqueLoaders[entry.loader]++;
    });

    console.log('\n[clsload] Class resolution by loader:');
    for (var loader in uniqueLoaders) {
        console.log('[clsload]   ' + loader + ': ' + uniqueLoaders[loader] + ' classes');
    }

    // Show failed resolutions
    var failures = classResolveLog.filter(function (e) { return e.resolved === false; });
    if (failures.length > 0) {
        console.log('\n[clsload] Failed resolutions:');
        failures.slice(0, 20).forEach(function (f) {
            console.log('[clsload]   ' + f.class + ' (' + f.loader + ')');
        });
    }

    console.log('[clsload] === End ===\n');
}

console.log('[clsload] Call dumpClassLoaderInfo() for summary');
console.log('[clsload] Loaded');
