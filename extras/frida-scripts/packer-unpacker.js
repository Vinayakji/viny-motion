/**
 * packer-unpacker.js
 * Detect and bypass common Android packers/protectors
 * Covers: DexProtector, Ijiami, Bangcle, Tencent, Baidu, Alibaba, Qihoo
 *
 * Usage: frida -U -f <package> -l packer-unpacker.js --no-pause
 */

'use strict';

console.log('[packer] Packer detection & bypass loaded');

// Known packer signatures
var packerSignatures = {
    'DexProtector': ['dexprotector', 'dex_protector', 'com.datadox'],
    'Ijiami': ['ijiami', 'com.secneo', 'com.shell.superapp'],
    'Bangcle': ['bangcle', 'com.secneo.apkmanager'],
    'Tencent': ['com.tencent.StubShell', 'com.tencent.appcompat', 'tencent应用宝加固'],
    'Baidu': ['com.baidu.protect', 'com.baidu.nm'],
    'Alibaba': ['com.alibaba.wireless.security', 'com.alibaba.sdk'],
    'Qihoo': ['com.qihoo.util', 'com.qihoo360.replugin'],
    'Banger': ['com.banger加固', 'com.hexin.plat.android'],
    'Naga': ['com.nagapt', 'libDexHelper.so'],
    'Dpt': ['libDexHelper-x86.so', 'libDexHelper.so'],
    'WOProtect': ['libWua.so', 'com.zwlsb.privacy'],
    'VMPProtect': ['libVmpProtect.so', 'com.vmprotect']
};

/**
 * Detect packer by scanning loaded classes
 */
function detectPacker() {
    Java.perform(function () {
        var detected = [];

        Java.enumerateLoadedClasses({
            onMatch: function (className) {
                for (var packer in packerSignatures) {
                    var sigs = packerSignatures[packer];
                    for (var i = 0; i < sigs.length; i++) {
                        if (className.indexOf(sigs[i]) !== -1) {
                            detected.push(packer);
                            break;
                        }
                    }
                }
            },
            onComplete: function () {
                if (detected.length > 0) {
                    console.log('[packer] DETECTED: ' + detected.join(', '));
                } else {
                    console.log('[packer] No known packer detected');
                }
            }
        });
    });
}

/**
 * Detect packer by scanning loaded native libraries
 */
function detectPackerNative() {
    var nativeLibs = [
        'libjiagu.so', 'libDexHelper.so', 'libDexHelper-x86.so',
        'libprotectClass.so', 'libtup.so', 'libBugly.so',
        'libexec.so', 'libexecmain.so', 'libsecexe.so',
        'libSecShell.so', 'libshella-*.so', 'libDex.so',
        'libx3g.so', 'libaoc.so', 'libwapua.so',
        'libVmpProtect.so', 'libnesec.so', 'libchaosvmp.so'
    ];

    Process.enumerateModules().forEach(function (mod) {
        nativeLibs.forEach(function (lib) {
            if (mod.name.indexOf(lib) !== -1) {
                console.log('[packer] Native lib found: ' + mod.name + ' @ ' + mod.base);
            }
        });
    });
}

/**
 * Attempt to dump unpacked DEX by hooking common unpacking functions
 */
function hookUnpacking() {
    Java.perform(function () {
        // Hook DexClassLoader to capture unpacked DEX
        var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
        DexClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader')
            .implementation = function (dexPath, optDir, libPath, parent) {
                console.log('[packer] DexClassLoader: ' + dexPath);
                // Attempt to dump
                try {
                    var File = Java.use('java.io.File');
                    var f = File.$new(dexPath);
                    if (f.exists()) {
                        var outPath = '/sdcard/unpacked_' + Date.now() + '.dex';
                        var Runtime = Java.use('java.lang.Runtime');
                        var runtime = Runtime.getRuntime();
                        runtime.exec(['cp', dexPath, outPath]);
                        console.log('[packer] Dumped -> ' + outPath);
                    }
                } catch (e) {}
                return this.$init(dexPath, optDir, libPath, parent);
            };

        // Hook InMemoryDexClassLoader (API 26+)
        try {
            var IMDCL = Java.use('dalvik.system.InMemoryDexClassLoader');
            IMDCL.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader')
                .implementation = function (buf, parent) {
                    var size = buf.remaining();
                    console.log('[packer] InMemoryDexClassLoader: ' + size + ' bytes');
                    // Dump the buffer
                    try {
                        var bytes = Java.array('byte', Java.use('java.lang.reflect.Array')
                            .newInstance(Java.use('java.lang.Byte').TYPE, size));
                        var pos = buf.position();
                        buf.get(bytes);
                        buf.position(pos); // reset

                        var fos = Java.use('java.io.FileOutputStream').$new(
                            '/sdcard/unpacked_mem_' + Date.now() + '.dex');
                        fos.write(bytes);
                        fos.close();
                        console.log('[packer] In-memory DEX dumped');
                    } catch (e) {}
                    return this.$init(buf, parent);
                };
        } catch (e) {}

        console.log('[packer] Unpacking hooks installed');
    });
}

detectPacker();
detectPackerNative();
hookUnpacking();

console.log('[packer] Functions: detectPacker(), detectPackerNative(), hookUnpacking()');
console.log('[packer] Loaded');
