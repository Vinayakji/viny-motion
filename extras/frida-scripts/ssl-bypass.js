/**
 * SSL Pinning Bypass for Android
 * Usage: frida -U -f com.example.app -l ssl-bypass.js --no-pause
 */

Java.perform(function() {
    console.log('[*] Starting SSL Pinning Bypass...');
    
    // Method 1: TrustManagerImpl bypass
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] TrustManagerImpl.verifyChain bypassed for: ' + host);
            return untrustedChain;
        };
        console.log('[+] TrustManagerImpl bypass installed');
    } catch(e) {
        console.log('[-] TrustManagerImpl not found');
    }
    
    // Method 2: Custom TrustManager
    try {
        var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        
        var CustomTrustManager = Java.registerClass({
            name: 'custom.BypassTrustManager',
            implements: [TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {
                    console.log('[+] checkClientTrusted bypassed');
                },
                checkServerTrusted: function(chain, authType) {
                    console.log('[+] checkServerTrusted bypassed');
                },
                getAcceptedIssuers: function() { 
                    return []; 
                }
            }
        });
        
        var TrustManagers = [CustomTrustManager.$new()];
        var SSLContextInit = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', 
            '[Ljavax.net.ssl.TrustManager;', 
            'java.security.SecureRandom'
        );
        SSLContextInit.implementation = function(keyManagers, trustManagers, secureRandom) {
            SSLContextInit.call(this, keyManagers, TrustManagers, secureRandom);
        };
        console.log('[+] Custom TrustManager installed');
    } catch(e) {
        console.log('[-] Custom TrustManager failed: ' + e);
    }
    
    // Method 3: OkHttp3 bypass (if present)
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[+] OkHttp3 CertificatePinner bypassed for: ' + hostname);
        };
        console.log('[+] OkHttp3 bypass installed');
    } catch(e) {
        console.log('[-] OkHttp3 not found');
    }
    
    console.log('[*] SSL Pinning Bypass complete');
});
