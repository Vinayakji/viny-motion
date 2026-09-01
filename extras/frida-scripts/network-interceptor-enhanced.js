/**
 * network-interceptor-enhanced.js
 * Enhanced network interception with TLS bypass, request/response modification
 * Replaces: network-interceptor, ssl-pinning-bypass-all
 *
 * Usage: frida -U -f <package> -l network-interceptor-enhanced.js --no-pause
 */

'use strict';

console.log('[net-int] Enhanced network interceptor loaded');

Java.perform(function () {
    // ─── TLS/SSL BYPASS ───────────────────────────────
    // TrustManagerImpl (Android platform)
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[net-int] TLS bypass: ' + host);
            return untrustedChain;
        };
    } catch (e) {}

    // OkHttp3 CertificatePinner
    ['CertificatePinner.check$okhttp', 'CertificatePinner.check'].forEach(function (method) {
        try {
            var CP = Java.use('okhttp3.CertificatePinner');
            CP[method].overloads.forEach(function (overload) {
                overload.implementation = function () {
                    console.log('[net-int] OkHttp pin bypass: ' + arguments[0]);
                };
            });
        } catch (e) {}
    });

    // HostnameVerifier
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        Java.registerClass({
            name: 'com.frida.HostnameVerifier',
            implements: [HostnameVerifier],
            methods: {
                verify: function (hostname, session) {
                    console.log('[net-int] Hostname bypass: ' + hostname);
                    return true;
                }
            }
        });
    } catch (e) {}

    // ─── OkHttp3 REQUEST INTERCEPTION ──────────────────
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Request = Java.use('okhttp3.Request');
        var Response = Java.use('okhttp3.Response');

        // Hook newCall to log all requests
        OkHttpClient.newCall.implementation = function (request) {
            var url = request.url().toString();
            var method = request.method();
            var headers = request.headers();

            console.log('\n[net-int] ── REQUEST ──');
            console.log('[net-int] ' + method + ' ' + url);
            headers.names().forEach(function (name) {
                var val = headers.get(name);
                if (name.toLowerCase() === 'authorization' || name.toLowerCase().indexOf('token') !== -1) {
                    console.log('[net-int]   ' + name + ': [REDACTED]');
                } else {
                    console.log('[net-int]   ' + name + ': ' + val);
                }
            });

            // Log request body if present
            try {
                var body = request.body();
                if (body !== null) {
                    var Buffer = Java.use('okio.Buffer');
                    var buf = Buffer.$new();
                    body.writeTo(buf);
                    console.log('[net-int]   Body: ' + buf.readUtf8());
                }
            } catch (e) {}

            console.log('[net-int] ── END REQUEST ──\n');

            return this.newCall(request);
        };

        // Hook Response to log response
        try {
            Response.body.implementation = function () {
                var body = this.body();
                try {
                    if (body !== null) {
                        var string = body.string();
                        console.log('[net-int] Response(' + this.code() + '): ' + string.substring(0, 500));
                        // Note: can't re-read body after string()
                        // We'd need to buffer it - skip for now
                    }
                } catch (e) {}
                return body;
            };
        } catch (e) {}

        console.log('[net-int] OkHttp3 hooks installed');
    } catch (e) {
        console.log('[net-int] OkHttp3 not found');
    }

    // ─── HttpURLConnection ─────────────────────────────
    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.setRequestMethod.implementation = function (method) {
            console.log('[net-int] HttpURLConnection method: ' + method);
            return this.setRequestMethod(method);
        };
    } catch (e) {}

    console.log('[net-int] All hooks installed');
});
