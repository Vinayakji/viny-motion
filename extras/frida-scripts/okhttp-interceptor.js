// okhttp-interceptor.js — Hook OkHttp3 to capture full request/response bodies
Java.perform(function() {
    var Tag = "OKHTTP_HOOK";

    // Hook OkHttp3 Interceptor chain
    try {
        var RealCall = Java.use("okhttp3.internal.connection.RealCall");

        RealCall.getResponseWithInterceptorChain.implementation = function() {
            var response = this.getResponseWithInterceptorChain();
            try {
                var request = this.request();
                var url = request.url().toString();
                var method = request.method();
                var headers = {};
                var headerNames = request.headers().names().iterator();
                while (headerNames.hasNext()) {
                    var name = headerNames.next();
                    headers[name] = request.header(name);
                }

                // Read request body
                var reqBody = null;
                try {
                    var body = request.body();
                    if (body) {
                        var buffer = Java.use("okio.Buffer").$new();
                        body.writeTo(buffer);
                        reqBody = buffer.readUtf8();
                    }
                } catch(e) {}

                // Read response body
                var resBody = null;
                try {
                    resBody = response.peekBody(Java.use("java.lang.Long").parseLong("1048576")).string();
                } catch(e) {}

                send({type: "okhttp", method: method, url: url, requestHeaders: headers, requestBody: reqBody ? reqBody.substring(0, 2000) : null, responseCode: response.code(), responseBody: resBody ? resBody.substring(0, 2000) : null});

                console.log("[OKHTTP] " + method + " " + url + " -> " + response.code());

                // Check for sensitive data in response
                if (resBody) {
                    var lower = resBody.toLowerCase();
                    if (lower.includes("password") || lower.includes("token") || lower.includes("secret") || lower.includes("api_key") || lower.includes("access_token")) {
                        send({type: "okhttp_vuln", vuln: "SENSITIVE_DATA_IN_RESPONSE", url: url, snippet: resBody.substring(0, 500)});
                        console.log("[!] Sensitive data in response: " + url);
                    }
                }
            } catch(e) {
                console.log("[*] OkHttp hook error: " + e);
            }
            return response;
        };
    } catch(e) {
        console.log("[*] OkHttp3 RealCall hook failed: " + e);
    }

    // Hook OkHttpClient.Builder for SSL config
    try {
        var OkHttpClientBuilder = Java.use("okhttp3.OkHttpClient$Builder");
        OkHttpClientBuilder.sslSocketFactory.overload("javax.net.ssl.SSLSocketFactory", "javax.net.ssl.X509TrustManager").implementation = function(sslSocketFactory, trustManager) {
            send({type: "okhttp", action: "sslSocketFactory", trustManagerClass: trustManager.getClass().getName()});
            console.log("[*] OkHttp SSL socket factory set: " + trustManager.getClass().getName());
            return this.sslSocketFactory(sslSocketFactory, trustManager);
        };

        OkHttpClientBuilder.hostnameVerifier.implementation = function(hostnameVerifier) {
            send({type: "okhttp", action: "hostnameVerifier", verifierClass: hostnameVerifier.getClass().getName()});
            console.log("[*] OkHttp hostname verifier: " + hostnameVerifier.getClass().getName());
            return this.hostnameVerifier(hostnameVerifier);
        };
    } catch(e) {}

    // Hook Retrofit if present
    try {
        var Retrofit = Java.use("retrofit2.Retrofit");
        // Just log that Retrofit is used
        console.log("[*] Retrofit detected");
    } catch(e) {}

    console.log("[*] OkHttp hooks loaded");
});
