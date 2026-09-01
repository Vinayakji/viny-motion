/**
 * mem-layout-viewer.js
 * View process memory layout, memory maps, and search for sensitive data
 *
 * Usage: frida -U -f <package> -l mem-layout-viewer.js --no-pause
 */

'use strict';

console.log('[mem] Memory layout viewer loaded');

/**
 * Dump memory map of the process
 */
function dumpMemoryMap() {
    console.log('\n[mem] === Memory Map ===');
    Process.enumerateRanges('r--').forEach(function (range) {
        var module = Process.findModuleByAddress(range.base);
        var label = module ? module.name : '[anonymous]';
        console.log('[mem] ' + range.base + '-' + range.base.add(range.size) +
            ' ' + range.size + 'B ' + range.protection + ' ' + label);
    });
    console.log('[mem] === End Memory Map ===\n');
}

/**
 * Dump memory regions with specific permissions
 */
function dumpRegions(perms) {
    perms = perms || 'rwx'; // Default: find executable+writeable (W^X violations)
    console.log('\n[mem] === Regions with perms: ' + perms + ' ===');
    Process.enumerateRanges(perms).forEach(function (range) {
        var module = Process.findModuleByAddress(range.base);
        var label = module ? module.name : '[anonymous]';
        console.log('[mem] ' + range.base + '-' + range.base.add(range.size) +
            ' ' + range.size + 'B ' + label);
    });
    console.log('=== End Regions ===\n');
}

/**
 * Search memory for a string pattern
 */
function searchMemory(pattern) {
    console.log('[mem] Searching memory for: "' + pattern + '"');
    var results = Memory.scanSync(ptr(0), Process.pageSize * 10000, pattern);
    results.forEach(function (match) {
        var module = Process.findModuleByAddress(match.address);
        var context = module ? module.name : 'unknown';
        console.log('[mem] Found at ' + match.address + ' in ' + context);
        // Try to read string at that address
        try {
            var str = match.address.readUtf8String(100);
            if (str) console.log('[mem]   String: "' + str + '"');
        } catch (e) {}
    });
    console.log('[mem] Scan complete: ' + results.length + ' matches');
    return results;
}

/**
 * Search for sensitive strings (keys, tokens, secrets)
 */
function searchSecrets() {
    var patterns = [
        'api_key', 'apikey', 'api-key', 'secret', 'password',
        'token', 'auth', 'bearer', 'jwt', 'private_key',
        'BEGIN RSA', 'BEGIN PRIVATE', 'BEGIN EC'
    ];

    console.log('[mem] === Searching for secrets ===');
    patterns.forEach(function (pattern) {
        searchMemory(pattern);
    });
}

/**
 * Dump readable memory from an address range
 */
function dumpMemory(addr, length) {
    console.log('[mem] === Memory dump from ' + addr + ' (' + length + ' bytes) ===');
    var data = Memory.readByteArray(ptr(addr), length);
    // Print as hex
    var bytes = new Uint8Array(data);
    var hex = '';
    var ascii = '';
    for (var i = 0; i < bytes.length; i++) {
        hex += ('0' + bytes[i].toString(16)).slice(-2) + ' ';
        ascii += (bytes[i] >= 32 && bytes[i] <= 126) ? String.fromCharCode(bytes[i]) : '.';
        if ((i + 1) % 16 === 0) {
            console.log('[mem] ' + hex + ' |' + ascii + '|');
            hex = '';
            ascii = '';
        }
    }
    if (hex) console.log('[mem] ' + hex.padEnd(48) + ' |' + ascii + '|');
    console.log('[mem] === End dump ===');
}

console.log('[mem] Functions: dumpMemoryMap(), dumpRegions(), searchMemory(), searchSecrets(), dumpMemory()');
console.log('[mem] Loaded');
