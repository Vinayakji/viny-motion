/**
 * webview-debug.js
 * Enable WebView debugging, intercept URL loading, dump WebView state
 *
 * Usage: frida -U -f <package> -l webview-debug.js --no-pause
 */

'use strict';

console.log('[wv-debug] Loading WebView debug hooks...');

Java.perform(function () {
    // 1. Force-enable WebView debugging
    var WebView = Java.use('android.webkit.WebView');
    WebView.setWebContentsDebuggingEnabled.implementation = function (enabled) {
        console.log('[wv-debug] Force-enabling WebView debugging');
        return this.setWebContentsDebuggingEnabled(true);
    };

    // 2. Hook WebView initialization
    WebView.$init.overload('android.content.Context').implementation = function (context) {
        console.log('[wv-debug] WebView created: ' + context.getClass().getName());
        return this.$init(context);
    };

    WebView.$init.overload('android.content.Context', 'android.util.AttributeSet')
        .implementation = function (context, attrs) {
            console.log('[wv-debug] WebView created: ' + context.getClass().getName());
            return this.$init(context, attrs);
        };

    // 3. Hook loadUrl
    WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
        console.log('[wv-debug] loadUrl: ' + url);
        return this.loadUrl(url);
    };

    WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function (url, headers) {
        console.log('[wv-debug] loadUrl (with headers): ' + url);
        return this.loadUrl(url, headers);
    };

    // 4. Hook loadData
    WebView.loadData.implementation = function (data, mimeType, encoding) {
        console.log('[wv-debug] loadData: ' + data.substring(0, 200));
        return this.loadData(data, mimeType, encoding);
    };

    // 5. Hook evaluateJavascript
    WebView.evaluateJavascript.implementation = function (script, resultCallback) {
        console.log('[wv-debug] JS eval: ' + script.substring(0, 200));
        return this.evaluateJavascript(script, resultCallback);
    };

    // 6. Hook addJavascriptInterface
    WebView.addJavascriptInterface.implementation = function (obj, name) {
        console.log('[wv-debug] addJavascriptInterface: ' + name + ' -> ' + obj.getClass().getName());
        return this.addJavascriptInterface(obj, name);
    };

    // 7. Hook shouldOverrideUrlLoading
    var WebViewClient = Java.use('android.webkit.WebViewClient');
    WebViewClient.shouldOverrideUrlLoading.overload('android.webkit.WebView', 'java.lang.String')
        .implementation = function (view, url) {
            console.log('[wv-debug] shouldOverrideUrlLoading: ' + url);
            return false; // Allow all URL loading
        };

    // 8. Hook shouldInterceptRequest
    WebViewClient.shouldInterceptRequest.overload('android.webkit.WebView', 'java.lang.String')
        .implementation = function (view, url) {
            console.log('[wv-debug] shouldInterceptRequest: ' + url);
            return this.shouldInterceptRequest(view, url);
        };

    // 9. Hook SSL error handling
    var SslErrorHandler = Java.use('android.webkit.SslErrorHandler');
    SslErrorHandler.proceed.implementation = function () {
        console.log('[wv-debug] SSL error bypassed!');
        return this.proceed();
    };

    console.log('[wv-debug] All WebView hooks installed');
});

// Console function to dump WebView state
function dumpWebViewState() {
    Java.perform(function () {
        Java.choose('android.webkit.WebView', {
            onMatch: function (webView) {
                console.log('[wv-debug] WebView URL: ' + webView.getUrl());
                console.log('[wv-debug] WebView Title: ' + webView.getTitle());
                console.log('[wv-debug] WebView canGoBack: ' + webView.canGoBack());
                console.log('[wv-debug] WebView canGoForward: ' + webView.canGoForward());
            },
            onComplete: function () {}
        });
    });
}

console.log('[wv-debug] Call dumpWebViewState() to see current WebView state');
