/**
 * keystore-dumper.js
 * Dump Android KeyStore entries (keys, certificates, aliases)
 * Detect key generation, signing operations, and stored credentials
 *
 * Usage: frida -U -f <package> -l keystore-dumper.js --no-pause
 */

'use strict';

console.log('[ks] KeyStore dumper loaded');

var keyOps = [];
var keyAliases = [];

Java.perform(function () {
    // ─── KeyStore Instance Tracking ────────────────────
    try {
        var KeyStore = Java.use('java.security.KeyStore');

        KeyStore.getInstance.overload('java.lang.String').implementation = function (type) {
            console.log('[ks] KeyStore.getInstance: ' + type);
            keyOps.push({ type: 'getInstance', algorithm: type, timestamp: Date.now() });
            return this.getInstance(type);
        };

        KeyStore.getInstance.overload('java.lang.String', 'java.lang.String')
            .implementation = function (type, provider) {
                console.log('[ks] KeyStore.getInstance: ' + type + ' (' + provider + ')');
                keyOps.push({ type: 'getInstance', algorithm: type, provider: provider, timestamp: Date.now() });
                return this.getInstance(type, provider);
            };

        // Hook load
        KeyStore.load.overload('java.io.InputStream', '[C').implementation = function (stream, password) {
            console.log('[ks] KeyStore.load (stream, password=' + (password !== null ? '****' : 'null') + ')');
            return this.load(stream, password);
        };

        KeyStore.load.overload('java.security.KeyStore$LoadStoreParameter').implementation = function (param) {
            console.log('[ks] KeyStore.load (param)');
            return this.load(param);
        };

        // Hook aliases enumeration
        KeyStore.aliases.implementation = function () {
            var aliases = this.aliases();
            var aliasList = [];
            while (aliases.hasMoreElements()) {
                var alias = aliases.nextElement();
                aliasList.push(alias);
                keyAliases.push(alias);
                console.log('[ks] Alias: ' + alias);
            }
            // Return a new enumeration from the list
            var Enumeration = Java.use('java.util.Collections');
            return Enumeration.enumeration(Java.use('java.util.Arrays').asList(
                aliasList.map(function (a) { return Java.use('java.lang.String').$new(a); })
            ).toArray());
        };

        // Hook getKey
        KeyStore.getKey.overload('java.lang.String', '[C').implementation = function (alias, password) {
            console.log('[ks] getKey: ' + alias);
            keyOps.push({ type: 'getKey', alias: alias, hasPassword: password !== null, timestamp: Date.now() });
            return this.getKey(alias, password);
        };

        // Hook getCertificateChain
        KeyStore.getCertificateChain.overload('java.lang.String').implementation = function (alias) {
            var chain = this.getCertificateChain(alias);
            console.log('[ks] getCertificateChain: ' + alias + ' (' + chain.length + ' certs)');
            chain.forEach(function (cert, i) {
                console.log('[ks]   [' + i + '] ' + cert.getSubjectDN().toString());
            });
            return chain;
        };

        console.log('[ks] KeyStore hooks installed');
    } catch (e) {
        console.log('[ks] KeyStore hook failed: ' + e);
    }

    // ─── Android KeyStore (hardware-backed) ─────────────
    try {
        var AndroidKeyStore = Java.use('android.security.keystore.AndroidKeyStoreProvider');
        console.log('[ks] AndroidKeyStore provider found');
    } catch (e) {}

    // ─── KeyGenerator ──────────────────────────────────
    try {
        var KeyGenerator = Java.use('javax.crypto.KeyGenerator');
        KeyGenerator.getInstance.overload('java.lang.String').implementation = function (algo) {
            console.log('[ks] KeyGenerator: ' + algo);
            keyOps.push({ type: 'KeyGenerator', algorithm: algo, timestamp: Date.now() });
            return this.getInstance(algo);
        };

        KeyGenerator.getInstance.overload('java.lang.String', 'java.lang.String')
            .implementation = function (algo, provider) {
                console.log('[ks] KeyGenerator: ' + algo + ' (' + provider + ')');
                return this.getInstance(algo, provider);
            };
    } catch (e) {}

    // ─── Signature ─────────────────────────────────────
    try {
        var Signature = Java.use('java.security.Signature');
        Signature.getInstance.overload('java.lang.String').implementation = function (algo) {
            console.log('[ks] Signature: ' + algo);
            keyOps.push({ type: 'Signature', algorithm: algo, timestamp: Date.now() });
            return this.getInstance(algo);
        };

        Signature.initSign.overload('java.security.PrivateKey').implementation = function (key) {
            console.log('[ks] Signature.initSign (private key)');
            return this.initSign(key);
        };

        Signature.sign.implementation = function () {
            console.log('[ks] Signature.sign()');
            return this.sign();
        };
    } catch (e) {}

    console.log('[ks] All hooks installed');
});

function dumpKeyStoreInfo() {
    console.log('\n[ks] === KeyStore Info ===');
    console.log('[ks] Aliases found: ' + keyAliases.length);
    keyAliases.forEach(function (alias) {
        console.log('[ks]   ' + alias);
    });

    console.log('\n[ks] Key operations: ' + keyOps.length);
    keyOps.forEach(function (op) {
        console.log('[ks]   ' + op.type + ': ' + (op.algorithm || op.alias || ''));
    });
    console.log('[ks] === End ===\n');
}

console.log('[ks] Call dumpKeyStoreInfo() for summary');
console.log('[ks] Loaded');
