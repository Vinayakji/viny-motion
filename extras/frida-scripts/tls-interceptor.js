/**
 * tls-interceptor.js
 * Intercept and analyze TLS connections, certificate validation, and cipher suites
 * Detect weak ciphers, custom TrustManagers, and TLS configuration issues
 *
 * Usage: frida -U -f <package> -l tls-interceptor.js --no-pause
 */

'use strict';

console.log('[tls] TLS interceptor loaded');

var tlsIssues = [];

Java.perform(function () {
    // ─── Custom TrustManager Detection ─────────────────
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        Java.enumerateLoadedClasses({
            onMatch: function (className) {
                try {
                    var cls = Java.use(className);
                    if (cls.class.isInterface()) return;
                    // Check if class implements TrustManager
                    var interfaces = cls.class.getInterfaces();
                    for (var i = 0; i < interfaces.length; i++) {
                        if (interfaces[i].getName() === 'javax.net.ssl.X509TrustManager') {
                            tlsIssues.push({
                                type: 'CUSTOM_TRUST_MANAGER',
                                severity: 'HIGH',
                                detail: className + ' implements X509TrustManager'
                            });
                            console.log('[tls] CUSTOM TRUST MANAGER: ' + className);

                            // Check getAcceptedIssuers
                            try {
                                var acceptedIssuers = cls.getAcceptedIssuers;
                                if (acceptedIssuers) {
                                    var issuers = acceptedIssuers();
                                    console.log('[tls]   Accepted issuers: ' + issuers.length);
                                }
                            } catch (e) {}

                            // Hook checkServerTrusted to see bypasses
                            try {
                                cls.checkServerTrusted.overloads.forEach(function (overload) {
                                    overload.implementation = function () {
                                        console.log('[tls] checkServerTrusted called in ' + className);
                                        // Log certificate chain
                                        try {
                                            var chain = arguments[0];
                                            if (chain) {
                                                console.log('[tls]   Chain length: ' + chain.length);
                                                for (var j = 0; j < chain.length; j++) {
                                                    var cert = chain[j];
                                                    console.log('[tls]   [' + j + '] ' + cert.getSubjectDN().toString());
                                                }
                                            }
                                        } catch (e) {}
                                        // DON'T call super - this IS the bypass
                                    };
                                });
                            } catch (e) {}
                        }
                    }
                } catch (e) {}
            },
            onComplete: function () {}
        });
    } catch (e) {}

    // ─── SSLContext Configuration ──────────────────────
    try {
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
            .implementation = function (km, tm, sr) {
                if (tm) {
                    console.log('[tls] SSLContext.init with custom TrustManager: ' + tm[0].getClass().getName());
                }
                return this.init(km, tm, sr);
            };
    } catch (e) {}

    // ─── HostnameVerifier ──────────────────────────────
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var SSLSession = Java.use('javax.net.ssl.SSLSession');
        Java.registerClass({
            name: 'com.frida.tls.DummyHostnameVerifier',
            implements: [HostnameVerifier],
            methods: {
                verify: function (hostname, session) {
                    console.log('[tls] HostnameVerifier.verify: ' + hostname);
                    return true;
                }
            }
        });
    } catch (e) {}

    // ─── Cipher Suite Analysis ─────────────────────────
    try {
        var SSLSocket = Java.use('javax.net.ssl.SSLSocket');
        SSLSocket.setEnabledCipherSuites.overload('[Ljava.lang.String;').implementation = function (cipherSuites) {
            console.log('[tls] Setting cipher suites (' + cipherSuites.length + '):');
            var weakCiphers = ['DES', '3DES', 'RC4', 'MD5', 'NULL', 'EXPORT', 'anon'];
            cipherSuites.forEach(function (cipher) {
                var isWeak = weakCiphers.some(function (w) { return cipher.indexOf(w) !== -1; });
                if (isWeak) {
                    console.log('[tls]   WEAK: ' + cipher);
                    tlsIssues.push({
                        type: 'WEAK_CIPHER',
                        severity: 'HIGH',
                        detail: cipher
                    });
                }
            });
            return this.setEnabledCipherSuites(cipherSuites);
        };
    } catch (e) {}

    // ─── OkHttp3 TLS Configuration ─────────────────────
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Builder = Java.use('okhttp3.OkHttpClient$Builder');

        Builder.sslSocketFactory.overload('javax.net.ssl.SSLSocketFactory', 'javax.net.ssl.X509TrustManager')
            .implementation = function (factory, tm) {
                console.log('[tls] OkHttp sslSocketFactory set');
                return this.sslSocketFactory(factory, tm);
            };

        Builder.hostnameVerifier.implementation = function (verifier) {
            console.log('[tls] OkHttp hostnameVerifier set: ' + verifier.getClass().getName());
            return this.hostnameVerifier(verifier);
        };
    } catch (e) {}

    // ─── Network Security Config ───────────────────────
    try {
        var NSC = Java.use('android.security.NetworkSecurityConfig');
        console.log('[tls] NetworkSecurityConfig class found');
    } catch (e) {
        console.log('[tls] NetworkSecurityConfig not found (may allow cleartext)');
        tlsIssues.push({
            type: 'NO_NSC',
            severity: 'MEDIUM',
            detail: 'NetworkSecurityConfig not found in app'
        });
    }

    console.log('[tls] All hooks installed');
});

function dumpTlsIssues() {
    console.log('\n[tls] === TLS Issues (' + tlsIssues.length + ') ===');
    tlsIssues.forEach(function (issue, i) {
        console.log('[tls] [' + issue.severity + '] ' + issue.type + ': ' + issue.detail);
    });
    console.log('[tls] === End ===\n');
}

console.log('[tls] Call dumpTlsIssues() for findings');
console.log('[tls] Loaded');
