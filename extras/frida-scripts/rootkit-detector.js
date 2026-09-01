/**
 * rootkit-detector.js
 * Detect rootkits, hooks, and tampering in the running process
 * Scan for inline hooks, modified functions, and suspicious memory regions
 *
 * Usage: frida -U -f <package> -l rootkit-detector.js --no-pause
 */

'use strict';

console.log('[rootkit] Rootkit detector loaded');

var scanResults = [];

/**
 * Scan module for inline hooks (check first bytes of each function)
 */
function scanForHooks(moduleName) {
    var mod = Process.findModuleByName(moduleName);
    if (!mod) {
        console.log('[rootkit] Module not found: ' + moduleName);
        return;
    }

    console.log('[rootkit] Scanning ' + moduleName + ' for hooks...');

    var exports = mod.enumerateExports();
    var hooksFound = 0;

    exports.forEach(function (exp) {
        try {
            var firstBytes = exp.address.readByteArray(4);
            var bytes = new Uint8Array(firstBytes);

            // Check for common hook patterns
            // Thumb mode: BX PC (0x4770) or B (0xE0xx)
            // ARM mode: BX LR (0xE12FFF1E) or B (0xEA000000)
            var isHooked = false;
            var hookType = '';

            // Check for JMP/BX patterns at function start
            if (bytes[0] === 0x04 && bytes[1] === 0xF0 && bytes[2] === 0x9F && bytes[3] === 0xE5) {
                isHooked = true;
                hookType = 'ARM jump';
            } else if (bytes[0] === 0x14 && bytes[1] === 0x00 && bytes[2] === 0x00 && bytes[3] === 0xEA) {
                isHooked = true;
                hookType = 'ARM branch';
            } else if (bytes[0] === 0x70 && bytes[1] === 0x47) {
                isHooked = true;
                hookType = 'Thumb BX LR';
            } else if (bytes[0] === 0x01 && bytes[1] === 0x46) {
                isHooked = true;
                hookType = 'Thumb MOV R0, R0 (nop)';
            }

            if (isHooked) {
                hooksFound++;
                scanResults.push({
                    module: moduleName,
                    function: exp.name,
                    address: exp.address,
                    hookType: hookType,
                    bytes: bytes
                });
                console.log('[rootkit] HOOK: ' + exp.name + ' @ ' + exp.address + ' (' + hookType + ')');
            }
        } catch (e) {}
    });

    console.log('[rootkit] ' + moduleName + ': ' + hooksFound + ' hooks found in ' + exports.length + ' exports');
}

/**
 * Scan memory for suspicious RWX regions
 */
function scanRWXRegions() {
    console.log('[rootkit] === Scanning RWX regions ===');
    var regions = Process.enumerateRanges('rwx');
    regions.forEach(function (range) {
        var module = Process.findModuleByAddress(range.base);
        var label = module ? module.name : '[anonymous]';
        console.log('[rootkit] RWX: ' + range.base + '-' + range.base.add(range.size) + ' ' + label);

        // Check for shellcode patterns
        try {
            var data = range.base.readByteArray(Math.min(range.size, 1024));
            var bytes = new Uint8Array(data);

            // Check for NOP sled
            var nopCount = 0;
            for (var i = 0; i < bytes.length; i++) {
                if (bytes[i] === 0x90) nopCount++; // x86 NOP
                if (bytes[i] === 0x00 && i > 0 && bytes[i - 1] === 0x00) nopCount++; // ARM NOP
            }

            if (nopCount > 50) {
                console.log('[rootkit]   SUSPICIOUS: ' + nopCount + ' NOP bytes found');
                scanResults.push({
                    module: label,
                    type: 'NOP_SLED',
                    address: range.base,
                    size: range.size
                });
            }
        } catch (e) {}
    });
}

/**
 * Scan for Frida/Xposed/Magisk artifacts in memory
 */
function scanForTools() {
    console.log('[rootkit] === Scanning for tool artifacts ===');
    var toolPatterns = [
        'frida', 'frida-agent', 'frida-server', 'frida-gadget',
        'xposed', 'XposedBridge', 'de.robv.android.xposed',
        'magisk', 'su', '/su', 'supersu',
        'substrate', 'Cydia', 'SSLKillSwitch'
    ];

    Process.enumerateModules().forEach(function (mod) {
        if (mod.name.indexOf('.so') === -1) return;

        toolPatterns.forEach(function (pattern) {
            var matches = Memory.scanSync(mod.base, mod.size, pattern);
            if (matches.length > 0) {
                console.log('[rootkit] FOUND: ' + pattern + ' in ' + mod.name);
                scanResults.push({
                    module: mod.name,
                    type: 'TOOL_ARTIFACT',
                    pattern: pattern,
                    address: matches[0].address,
                    count: matches.length
                });
            }
        });
    });
}

/**
 * Check for hooked/libhooked libc functions
 */
function scanLibc() {
    console.log('[rootkit] === Scanning libc.so ===');
    var libc = Process.findModuleByName('libc.so');
    if (!libc) return;

    var suspiciousFuncs = ['ptrace', 'dlopen', 'dlsym', 'mprotect', 'mmap'];
    suspiciousFuncs.forEach(function (funcName) {
        var addr = Module.findExportByName('libc.so', funcName);
        if (addr) {
            var firstBytes = addr.readByteArray(8);
            var bytes = new Uint8Array(firstBytes);
            console.log('[rootkit] libc.' + funcName + ' @ ' + addr + ': ' +
                Array.from(bytes).map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join(' '));
        }
    });
}

function rootkitScan() {
    console.log('\n[rootkit] ==========================================');
    console.log('[rootkit] === ROOTKIT SCAN STARTING ===');
    console.log('[rootkit] ==========================================\n');

    scanResults = [];

    // Scan key modules
    Process.enumerateModules().forEach(function (mod) {
        if (mod.name.indexOf('.so') !== -1 && mod.size > 10000) {
            scanForHooks(mod.name);
        }
    });

    scanRWXRegions();
    scanForTools();
    scanLibc();

    console.log('\n[rootkit] ==========================================');
    console.log('[rootkit] === SCAN COMPLETE: ' + scanResults.length + ' issues found ===');
    console.log('[rootkit] ==========================================\n');

    return scanResults;
}

console.log('[rootkit] Functions: rootkitScan(), scanForHooks("module.so"), scanForTools()');
console.log('[rootkit] Loaded');
