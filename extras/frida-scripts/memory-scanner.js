/**
 * memory-scanner.js
 * Scan process memory for secrets, keys, tokens, and sensitive data
 * Detect hardcoded credentials, API keys, and private data
 *
 * Usage: frida -U -f <package> -l memory-scanner.js --no-pause
 */

'use strict';

console.log('[memscan] Memory scanner loaded');

var findings = [];

function scanMemory(pattern, label) {
    var found = 0;
    Process.enumerateRanges('r--').forEach(function (range) {
        try {
            var matches = Memory.scanSync(range.base, range.size, pattern);
            matches.forEach(function (match) {
                found++;
                var data = match.address.readUtf8String(64);
                findings.push({
                    pattern: label,
                    address: match.address,
                    module: range.file ? range.file.path : 'unknown',
                    sample: data ? data.substring(0, 64) : ''
                });
            });
        } catch (e) {}
    });
    console.log('[memscan] ' + label + ': ' + found + ' matches');
    return found;
}

function fullScan() {
    console.log('[memscan] === Full Memory Scan ===');
    findings = [];

    // API keys and tokens
    scanMemory('(?i)(api[_-]?key|apikey)[=:]["\x27\\s]*([a-zA-Z0-9]{16,})', 'API_KEY');
    scanMemory('(?i)(token|jwt|bearer)[=:]["\x27\\s]*([a-zA-Z0-9\\-._]{20,})', 'TOKEN');
    scanMemory('(?i)(secret|password|passwd|pwd)[=:]["\x27\\s]*([^\x27"\\n]{4,})', 'SECRET');

    // AWS keys
    scanMemory('AKIA[0-9A-Z]{16}', 'AWS_ACCESS_KEY');
    scanMemory('(?i)aws[_-]?secret[_-]?access[_-]?key', 'AWS_SECRET_KEY');

    // Firebase
    scanMemory('AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}', 'FIREBASE_KEY');

    // Google API
    scanMemory('AIza[0-9A-Za-z_-]{35}', 'GOOGLE_API_KEY');

    // Private keys
    scanMemory('-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----', 'PRIVATE_KEY');

    // Phone numbers
    scanMemory('\\+91[6-9][0-9]{9}', 'INDIAN_PHONE');
    scanMemory('\\+1[2-9][0-9]{9}', 'US_PHONE');

    // Email addresses
    scanMemory('[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}', 'EMAIL');

    // IP addresses
    scanMemory('[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}', 'IP_ADDRESS');

    // URLs
    scanMemory('https?://[^\\s"<>]{10,}', 'URL');

    // Credit card patterns
    scanMemory('[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}', 'POSSIBLE_CARD');

    // SSN patterns
    scanMemory('[0-9]{3}-[0-9]{2}-[0-9]{4}', 'POSSIBLE_SSN');

    // JWT tokens
    scanMemory('eyJ[A-Za-z0-9_-]{10,}.eyJ[A-Za-z0-9_-]{10,}', 'JWT_TOKEN');

    console.log('\n[memscan] === Scan Complete: ' + findings.length + ' findings ===');
    findings.forEach(function (f, i) {
        console.log('[memscan] [' + i + '] ' + f.pattern);
        console.log('[memscan]   @ ' + f.address);
        console.log('[memscan]   Module: ' + f.module);
        if (f.sample) console.log('[memscan]   Sample: ' + f.sample);
    });
    console.log('[memscan] === End ===\n');

    return findings;
}

/**
 * Scan a specific memory region
 */
function scanRegion(base, size, label) {
    console.log('[memscan] Scanning region: ' + base + '-' + base.add(size));
    var results = [];
    var patterns = [
        ['(?i)(api[_-]?key|token|secret|password)[=:][^\\n]{4,64}', 'SENSITIVE_STRING'],
        ['eyJ[A-Za-z0-9_-]{20,}', 'JWT_TOKEN'],
        ['-----BEGIN PRIVATE KEY-----', 'PRIVATE_KEY']
    ];

    patterns.forEach(function (p) {
        var matches = Memory.scanSync(base, size, p[0]);
        matches.forEach(function (match) {
            var data = match.address.readUtf8String(128);
            results.push({
                pattern: p[1],
                address: match.address,
                sample: data ? data.substring(0, 128) : ''
            });
            console.log('[memscan] ' + p[1] + ' @ ' + match.address + ': ' + (data ? data.substring(0, 64) : ''));
        });
    });

    return results;
}

console.log('[memscan] Functions: fullScan(), scanRegion(base, size, label)');
console.log('[memscan] Loaded');
