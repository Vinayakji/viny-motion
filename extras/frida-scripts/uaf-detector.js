/**
 * uaf-detector.js
 * Detect use-after-free and double-free vulnerabilities in native code
 * Monitors malloc/free/realloc to detect dangling pointers
 *
 * Usage: frida -U -f <package> -l uaf-detector.js --no-pause
 */

'use strict';

console.log('[uaf] Use-after-free detector loaded');

var allocations = new Map(); // address -> {size, freed, backtrace, freedBacktrace}
var uafCount = 0;
var doubleFreeCount = 0;
var leakCount = 0;

function hookAllocator(name, funcAddr) {
    if (!funcAddr) return;

    Interceptor.attach(funcAddr, {
        onEnter: function (args) {
            this.size = args[0].toInt32();
        },
        onLeave: function (retval) {
            if (retval.isNull()) return;
            allocations.set(retval.toString(), {
                size: this.size,
                freed: false,
                backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
            });
        }
    });
}

function hookFree(name, funcAddr) {
    if (!funcAddr) return;

    Interceptor.attach(funcAddr, {
        onEnter: function (args) {
            var addr = args[0];
            var key = addr.toString();

            if (allocations.has(key)) {
                var alloc = allocations.get(key);
                if (alloc.freed) {
                    // Double free detected!
                    doubleFreeCount++;
                    console.log('[uaf] DOUBLE FREE at ' + addr + ' (size=' + alloc.size + ')');
                    console.log('[uaf]   First free backtrace:');
                    alloc.freedBacktrace.forEach(function (frame) {
                        console.log('[uaf]     ' + frame);
                    });
                    console.log('[uaf]   Second free backtrace:');
                    Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).forEach(function (frame) {
                            console.log('[uaf]     ' + frame);
                        });
                } else {
                    alloc.freed = true;
                    alloc.freedBacktrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress);
                }
            }
        }
    });
}

// Hook allocator functions
hookAllocator('malloc', Module.findExportByName('libc.so', 'malloc'));
hookAllocator('calloc', Module.findExportByName('libc.so', 'calloc'));
hookAllocator('realloc', Module.findExportByName('libc.so', 'realloc'));

// Hook free functions
hookFree('free', Module.findExportByName('libc.so', 'free'));

// Detect memory access after free by hooking common read functions
function hookAfterFreeRead(name, funcAddr) {
    if (!funcAddr) return;

    Interceptor.attach(funcAddr, {
        onEnter: function (args) {
            var addr = args[0];
            var key = addr.toString();
            if (allocations.has(key) && allocations.get(key).freed) {
                uafCount++;
                console.log('[uaf] USE-AFTER-FREE READ via ' + name + ' at ' + addr);
                Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).forEach(function (frame) {
                        console.log('[uaf]   ' + frame);
                    });
            }
        }
    });
}

// Hook memcpy, memmove, strcpy, strncpy for UAF detection
['memcpy', 'memmove', 'strcpy', 'strncpy', 'strcmp'].forEach(function (func) {
    hookAfterFreeRead(func, Module.findExportByName('libc.so', func));
});

function uafStats() {
    console.log('[uaf] === Stats ===');
    console.log('[uaf] Allocations tracked: ' + allocations.size);
    console.log('[uaf] UAF detected: ' + uafCount);
    console.log('[uaf] Double-free detected: ' + doubleFreeCount);

    // Count potential leaks (allocated but never freed)
    var leaks = 0;
    allocations.forEach(function (alloc) {
        if (!alloc.freed) leaks++;
    });
    console.log('[uaf] Potential leaks: ' + leaks);
}

function dumpLeaks() {
    console.log('[uaf] === Leaked Allocations ===');
    allocations.forEach(function (alloc, addr) {
        if (!alloc.freed && alloc.size > 0) {
            console.log('[uaf] ' + addr + ': ' + alloc.size + ' bytes');
        }
    });
}

console.log('[uaf] Functions: uafStats(), dumpLeaks()');
console.log('[uaf] Loaded');
