/**
 * dexdump.js
 * Dump all loaded DEX files from memory
 * Useful for unpacking/packer detection — captures decrypted DEX at runtime
 *
 * Usage: frida -U -f <package> -l dexdump.js --no-pause
 */

'use strict';

console.log('[dexdump] DEX memory dump script loaded');

var dumped = {};

Java.perform(function () {
    // 1. Monitor DexFile opening
    var DexFile = Java.use('dalvik.system.DexFile');
    DexFile.loadDex.overload('java.lang.String', 'java.lang.String', 'int')
        .implementation = function (sourcePathName, outputPathName, flags) {
            console.log('[dexdump] DexFile.loadDex: ' + sourcePathName);
            var result = this.loadDex(sourcePathName, outputPathName, flags);
            // Dump the DEX file
            try {
                var File = Java.use('java.io.File');
                var f = File.$new(sourcePathName);
                if (f.exists()) {
                    var fis = Java.use('java.io.FileInputStream').$new(f);
                    var len = f.length();
                    var buf = Java.array('byte', Java.use('java.lang.reflect.Array')
                        .newInstance(Java.use('java.lang.Byte').TYPE, len));
                    fis.read(buf);
                    fis.close();

                    var outPath = '/sdcard/dumped_' + Date.now() + '.dex';
                    var fos = Java.use('java.io.FileOutputStream').$new(outPath);
                    fos.write(buf);
                    fos.close();
                    console.log('[dexdump] Dumped ' + len + ' bytes -> ' + outPath);
                    dumped[sourcePathName] = outPath;
                }
            } catch (e) {
                console.log('[dexdump] Error dumping: ' + e);
            }
            return result;
        };

    // 2. Monitor class loading to detect DEX sources
    var ClassLoader = Java.use('java.lang.ClassLoader');
    ClassLoader.loadClass.overload('java.lang.String', 'boolean')
        .implementation = function (name, resolve) {
            // Log interesting class loads
            if (name.indexOf('com.') !== -1 || name.indexOf('io.') !== -1) {
                // Uncomment for verbose: console.log('[dexdump] loadClass: ' + name);
            }
            return this.loadClass(name, resolve);
        };

    console.log('[dexdump] Hooks installed — DEX files will be dumped to /sdcard/');
});

// Console function to list dumped files
function listDumped() {
    console.log('[dexdump] Dumped files:');
    for (var src in dumped) {
        console.log('  ' + src + ' -> ' + dumped[src]);
    }
}

console.log('[dexdump] Call listDumped() to see results');
