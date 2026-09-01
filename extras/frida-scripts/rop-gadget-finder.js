/**
 * rop-gadget-finder.js
 * Find ROP gadgets in native libraries for exploit development
 * Scans .text sections for common instruction patterns
 *
 * Usage: frida -U -f <package> -l rop-gadget-finder.js --no-pause
 */

'use strict';

console.log('[rop] ROP gadget finder loaded');

/**
 * Find gadgets in a specific module
 */
function findGadgets(moduleName) {
    var mod = Process.findModuleByName(moduleName);
    if (!mod) {
        console.log('[rop] Module not found: ' + moduleName);
        return;
    }

    console.log('[rop] Scanning ' + moduleName + ' (' + mod.base + ', ' + mod.size + ' bytes)');

    var gadgets = [];
    var textStart = mod.base;
    var textEnd = mod.base.add(mod.size);

    // Scan for common ROP patterns
    var patterns = [
        { name: 'pop {pc}', bytes: '5? 8? bd', desc: 'pop {r0-r12, lr}; pop {pc}' },
        { name: 'pop {r0, pc}', bytes: '?? bd', desc: 'pop {r0-r7, pc}' },
        { name: 'pop {r0, r1, pc}', bytes: '?? ?? bd', desc: 'pop {r0-r7, lr}; pop {pc}' },
        { name: 'mov r0, #0; pop {pc}', bytes: '00 20 bd', desc: 'mov r0, #0; pop {pc}' },
        { name: 'mov r0, #1; pop {pc}', bytes: '01 20 bd', desc: 'mov r0, #1; pop {pc}' },
        { name: 'mov r0, #0; bx lr', bytes: '00 20 70 47', desc: 'mov r0, #0; bx lr' },
        { name: 'mov r0, #1; bx lr', bytes: '01 20 70 47', desc: 'mov r0, #1; bx lr' },
        { name: 'bx lr', bytes: '70 47', desc: 'bx lr' },
        { name: 'pop {pc} (ret)', bytes: '?? bd', desc: 'pop {..., pc}' },
        { name: 'ldr r0, [sp]; pop {pc}', bytes: '?? 9? bd', desc: 'ldr r0, [sp, #offset]; pop {pc}' },
    ];

    patterns.forEach(function (pat) {
        var matches = Memory.scanSync(textStart, textEnd.sub(textStart), pat.bytes);
        matches.forEach(function (match) {
            gadgets.push({
                address: match.address,
                module: moduleName,
                name: pat.name,
                desc: pat.desc
            });
        });
    });

    // Print results
    gadgets.forEach(function (g) {
        console.log('[rop] ' + g.address + ' ' + g.name + ' (' + g.desc + ')');
    });

    console.log('[rop] Found ' + gadgets.length + ' gadgets in ' + moduleName);
    return gadgets;
}

/**
 * Find gadgets in all loaded native modules
 */
function findGadgetsAll() {
    Process.enumerateModules().forEach(function (mod) {
        if (mod.name.indexOf('.so') !== -1 && mod.size > 0) {
            findGadgets(mod.name);
        }
    });
}

/**
 * Find writable+executable memory regions (W^X violations)
 */
function findWXRegions() {
    console.log('[rop] === W+X Regions (potential ROP targets) ===');
    Process.enumerateRanges('rwx').forEach(function (range) {
        var module = Process.findModuleByAddress(range.base);
        var label = module ? module.name : '[anonymous]';
        console.log('[rop] ' + range.base + '-' + range.base.add(range.size) +
            ' ' + range.size + 'B ' + label);
    });
}

console.log('[rop] Functions: findGadgets("module.so"), findGadgetsAll(), findWXRegions()');
console.log('[rop] Loaded');
