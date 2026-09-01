/**
 * network-security-bypass.js
 * Bypass network security: certificate pinning, cleartext traffic, trust managers
 * Covers: OkHttp, HttpsURLConnection, TrustManagerImpl, NetworkSecurityConfig
 *
 * Usage: frida -U -f <package> -l network-security-bypass.js --no-pause
 */

'use strict';

console.log('[net-sec] Loading network security bypasses...');

Java.perform(function () {
    // 1. Bypass TrustManagerImpl (Android platform)
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[net-sec] Bypassed TrustManagerImpl.verifyChain for: ' + host);
            return untrustedChain;
        };
        console.log('[net-sec] TrustManagerImpl hook installed');
    } catch (e) {
        console.log('[net-sec] TrustManagerImpl not found (non-AOSP ROM?)');
    }

    // 2. Bypass OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List')
            .implementation = function (hostname, peerCertificates) {
                console.log('[net-sec] Bypassed OkHttp3 pin check: ' + hostname);
            };
        console.log('[net-sec] OkHttp3 CertificatePinner hook installed');
    } catch (e) {
        console.log('[net-sec] OkHttp3 CertificatePinner not found');
    }

    // 3. Bypass OkHttp3 CertificatePinner (alternative overload)
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0')
            .implementation = function (hostname, function0) {
                console.log('[net-sec] Bypassed OkHttp3 pin check$okhttp: ' + hostname);
            };
    } catch (e) {}

    // 4. Bypass custom X509TrustManager implementations
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        var TrustAll = Java.registerClass({
            name: 'com.frida.TrustAllManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {
                    console.log('[net-sec] TrustAll: accepted server cert for ' + authType);
                },
                getAcceptedIssuers: function () { return []; }
            }
        });

        // Override SSLContext.init to use our trust manager
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom')
            .implementation = function (km, tm, sr) {
                console.log('[net-sec] Replacing TrustManager in SSLContext.init');
                return this.init(km, [TrustAll.$new()], sr);
            };
        console.log('[net-sec] SSLContext.init hook installed');
    } catch (e) {
        console.log('[net-sec] Custom TrustManager hook failed: ' + e);
    }

    // 5. Bypass HostnameVerifier
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (verifier) {
            console.log('[net-sec] Setting permissive HostnameVerifier');
            return this.setDefaultHostnameVerifier(function (hostname, session) {
                return true;
            });
        };
    } catch (e) {}

    // 6. Allow cleartext traffic (addusesCleartextTraffic bypass)
    try {
        var StrictMode = Java.use('android.os.StrictMode');
        StrictMode.enableDeathOnNetwork.implementation = function () {
            console.log('[net-sec] Blocked StrictMode.enableDeathOnNetwork()');
        };
    } catch (e) {}

    console.log('[net-sec] All network bypasses installed');
});
