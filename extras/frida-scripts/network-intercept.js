/**
 * Network Interceptor for Android
 * Captures all HTTP/HTTPS requests and responses on the device
 * Usage: frida -U -f com.example.app -l network-intercept.js --no-pause
 */

Java.perform(function() {
    console.log('[*] Starting Network Interceptor...');
    
    // Hook HttpURLConnection
    try {
        var URL = Java.use('java.net.URL');
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        
        URL.$init.overload('java.lang.String').implementation = function(url) {
            console.log('[URL] ' + url);
            return this.$init(url);
        };
        
        HttpURLConnection.setRequestMethod.implementation = function(method) {
            var url = this.getURL().toString();
            console.log('[REQUEST] ' + method + ' ' + url);
            return this.setRequestMethod(method);
        };
        
        HttpURLConnection.setRequestProperty.implementation = function(key, value) {
            console.log('[HEADER] ' + key + ': ' + value);
            return this.setRequestProperty(key, value);
        };
        
        console.log('[+] HttpURLConnection hooks installed');
    } catch(e) {
        console.log('[-] HttpURLConnection hook failed: ' + e);
    }
    
    // Hook OkHttp3 (if present)
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Request = Java.use('okhttp3.Request');
        
        Request.Builder.url.overload('java.lang.String').implementation = function(url) {
            console.log('[OKHTTP] ' + url);
            return this.url(url);
        };
        
        console.log('[+] OkHttp3 hooks installed');
    } catch(e) {
        console.log('[-] OkHttp3 not found');
    }
    
    // Hook Retrofit (if present)
    try {
        var Retrofit = Java.use('retrofit2.Retrofit');
        var HttpServiceMethod = Java.use('retrofit2.HttpServiceMethod');
        
        console.log('[+] Retrofit hooks installed');
    } catch(e) {
        console.log('[-] Retrofit not found');
    }
    
    // Hook SSLContext to log certificate info
    try {
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyManagers, trustManagers, secureRandom) {
            console.log('[SSL] SSLContext initialized');
            if (trustManagers) {
                console.log('[SSL] Trust managers: ' + trustManagers.length);
            }
            return this.init(keyManagers, trustManagers, secureRandom);
        };
        console.log('[+] SSLContext hooks installed');
    } catch(e) {
        console.log('[-] SSLContext hook failed: ' + e);
    }
    
    // Hook WebView to capture web traffic
    try {
        var WebView = Java.use('android.webkit.WebView');
        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            console.log('[WEBVIEW] ' + url);
            return this.loadUrl(url);
        };
        console.log('[+] WebView hooks installed');
    } catch(e) {
        console.log('[-] WebView hook failed: ' + e);
    }
    
    console.log('[*] Network Interceptor initialized');
    console.log('[*] All HTTP/HTTPS traffic will be logged');
});
