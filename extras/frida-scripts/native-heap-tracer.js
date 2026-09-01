/**
 * native-heap-tracer.js
 * Track native heap allocations to detect memory corruption, use-after-free, leaks
 *
 * Usage: frida -U -f <package> -l native-heap-tracer.js --no-pause
 */

'use strict';

console.log('[heap] Native heap tracer loaded');

var allocCount = 0;
var freeCount = 0;
var allocations = {}; // address -> {size, backtrace}
var heapEnabled = true;

// Hook malloc/free/realloc
var libc = Module.findExportByName('libc.so', 'malloc');
var libcFree = Module.findExportByName('libc.so', 'free');
var libcRealloc = Module.findExportByName('libc.so', 'realloc');
var libcCalloc = Module.findExportByName('libc.so', 'calloc');

if (libc) {
    Interceptor.attach(libc, {
        onEnter: function (args) {
            if (!heapEnabled) return;
            this.size = args[0].toInt32();
        },
        onLeave: function (retval) {
            if (!heapEnabled) return;
            allocCount++;
            var addr = retval;
            allocations[addr] = {
                size: this.size,
                backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
            };
            if (this.size >= 1024) { // Only log large allocations
                console.log('[heap] malloc(' + this.size + ') -> ' + addr);
            }
        }
    });
}

if (libcFree) {
    Interceptor.attach(libcFree, {
        onEnter: function (args) {
            if (!heapEnabled) return;
            var addr = args[0];
            if (allocations[addr]) {
                freeCount++;
                delete allocations[addr];
            }
        }
    });
}

if (libcRealloc) {
    Interceptor.attach(libcRealloc, {
        onEnter: function (args) {
            if (!heapEnabled) return;
            this.oldAddr = args[0];
            this.newSize = args[1].toInt32();
        },
        onLeave: function (retval) {
            if (!heapEnabled) return;
            var newAddr = retval;
            if (this.oldAddr && allocations[this.oldAddr]) {
                delete allocations[this.oldAddr];
            }
            allocations[newAddr] = { size: this.newSize };
        }
    });
}

if (libcCalloc) {
    Interceptor.attach(libcCalloc, {
        onEnter: function (args) {
            if (!heapEnabled) return;
            this.count = args[0].toInt32();
            this.elemSize = args[1].toInt32();
        },
        onLeave: function (retval) {
            if (!heapEnabled) return;
            allocCount++;
            allocations[retval] = { size: this.count * this.elemSize };
        }
    });
}

/**
 * Dump heap statistics
 */
function heapStats() {
    console.log('[heap] === Heap Stats ===');
    console.log('[heap] Allocations: ' + allocCount);
    console.log('[heap] Frees: ' + freeCount);
    console.log('[heap] Live: ' + Object.keys(allocations).length);

    // Find large allocations
    var large = [];
    for (var addr in allocations) {
        if (allocations[addr].size >= 4096) {
            large.push({ addr: addr, size: allocations[addr].size });
        }
    }
    large.sort(function (a, b) { return b.size - a.size; });

    console.log('[heap] Top large allocations:');
    large.slice(0, 10).forEach(function (a) {
        console.log('[heap]   ' + a.addr + ': ' + a.size + ' bytes');
    });
}

function toggleHeap() {
    heapEnabled = !heapEnabled;
    console.log('[heap] Heap tracing ' + (heapEnabled ? 'ENABLED' : 'DISABLED'));
}

console.log('[heap] Functions: heapStats(), toggleHeap()');
console.log('[heap] Loaded');
