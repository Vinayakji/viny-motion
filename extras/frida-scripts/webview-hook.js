// webview-hook.js — Hook WebView for JS bridge abuse, file access, SSL bypass
Java.perform(function() {
    var Tag = "WEBVIEW_HOOK";

    var WebView = Java.use("android.webkit.WebView");

    // Hook addJavascriptInterface — critical for JS bridge attacks
    WebView.addJavascriptInterface.implementation = function(obj, name) {
        send({type: "webview", action: "addJavascriptInterface", name: name, objClass: obj.getClass().getName()});
        console.log("[!] JS interface added: " + name + " -> " + obj.getClass().getName());

        // List all methods on the interface
        var methods = obj.getClass().getMethods();
        for (var i = 0; i < methods.length; i++) {
            var m = methods[i];
            if (m.getAnnotation(Java.use("android.webkit.JavascriptInterface").class) !== null) {
                send({type: "webview", action: "js_method", interface: name, method: m.getName(), params: m.getParameterTypes().length});
                console.log("    @JavascriptInterface: " + m.getName() + "()");
            }
        }
        return this.addJavascriptInterface(obj, name);
    };

    // Hook loadUrl — detect external URL loading
    WebView.loadUrl.overload("java.lang.String").implementation = function(url) {
        send({type: "webview", action: "loadUrl", url: url});
        if (url.startsWith("javascript:")) {
            send({type: "webview_vuln", vuln: "JS_EXECUTION", url: url});
            console.log("[!] JavaScript URL loaded: " + url);
        }
        if (url.startsWith("file://")) {
            send({type: "webview_vuln", vuln: "FILE_URL", url: url});
            console.log("[!] File URL loaded: " + url);
        }
        return this.loadUrl(url);
    };

    WebView.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function(url, headers) {
        send({type: "webview", action: "loadUrl_with_headers", url: url, headers: JSON.stringify(headers)});
        return this.loadUrl(url, headers);
    };

    // Hook evaluateJavascript
    WebView.evaluateJavascript.overload("java.lang.String", "android.webkit.ValueCallback").implementation = function(script, callback) {
        send({type: "webview", action: "evaluateJavascript", script: script});
        console.log("[!] JS evaluated: " + script.substring(0, 200));
        return this.evaluateJavascript(script, callback);
    };

    // Hook shouldOverrideUrlLoading — URL redirection
    var WebChromeClient = Java.use("android.webkit.WebChromeClient");
    var WebViewClient = Java.use("android.webkit.WebViewClient");

    WebViewClient.shouldOverrideUrlLoading.overload("android.webkit.WebView", "java.lang.String").implementation = function(view, url) {
        send({type: "webview", action: "shouldOverrideUrlLoading", url: url});
        return this.shouldOverrideUrlLoading(view, url);
    };

    // Hook onReceivedSslError — SSL bypass detection
    WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
        send({type: "webview_vuln", vuln: "SSL_ERROR_RECEIVED", error: error.toString()});
        console.log("[!] SSL error received in WebView: " + error.toString());
        // Call cancel to not bypass (we're monitoring, not exploiting)
        handler.cancel();
    };

    // Hook setJavaScriptEnabled
    WebView.setJavaScriptEnabled.implementation = function(flag) {
        send({type: "webview", action: "setJavaScriptEnabled", enabled: flag});
        if (flag) {
            console.log("[*] JavaScript enabled in WebView");
        }
        return this.setJavaScriptEnabled(flag);
    };

    // Hook file access settings
    WebView.setAllowFileAccess.implementation = function(flag) {
        send({type: "webview", action: "setAllowFileAccess", enabled: flag});
        if (flag) {
            send({type: "webview_vuln", vuln: "FILE_ACCESS_ENABLED"});
            console.log("[!] File access enabled");
        }
        return this.setAllowFileAccess(flag);
    };

    WebView.setAllowFileAccessFromFileURLs.implementation = function(flag) {
        send({type: "webview", action: "setAllowFileAccessFromFileURLs", enabled: flag});
        if (flag) {
            send({type: "webview_vuln", vuln: "FILE_ACCESS_FROM_FILE_URLS"});
            console.log("[!] File access from file URLs enabled - CRITICAL");
        }
        return this.setAllowFileAccessFromFileURLs(flag);
    };

    WebView.setAllowUniversalAccessFromFileURLs.implementation = function(flag) {
        send({type: "webview", action: "setAllowUniversalAccessFromFileURLs", enabled: flag});
        if (flag) {
            send({type: "webview_vuln", vuln: "UNIVERSAL_FILE_ACCESS"});
            console.log("[!] Universal file access from file URLs enabled - CRITICAL");
        }
        return this.setAllowUniversalAccessFromFileURLs(flag);
    };

    console.log("[*] WebView hooks loaded");
});
