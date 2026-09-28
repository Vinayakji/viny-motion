/**
 * ssl-native-unpin.js — T6 native TLS unpinning supplement
 *
 * ssl-pinning-bypass.js covers the JAVA layer (SSLContext, TrustManagerImpl,
 * OkHttp, TrustKit, WebView). This script covers what Java hooks miss:
 *
 *   - libssl.so / libboringssl.so: SSL_CTX_set_verify -> VERIFY_NONE,
 *     SSL_verify_cert / X509_verify_cert forced success
 *   - Flutter: ssl_crypto_x509_session_verify_cert_chain in libflutter.so
 *     (pattern-scanned; BoringSSL lives inside the Flutter engine)
 *   - Cronet / native custom verifiers via X509_verify_cert forced 1
 *
 * RASP-enforced native pinning (Promon native-layer, RSEC-style): run
 * rasp-enforcement-cut.js FIRST — native pinning often kills on failure.
 *
 * Usage: frida -U -f <pkg> -l ssl-native-unpin.js
 *        (combine with ssl-pinning-bypass.js for full Java+native coverage)
 */
"use strict";

const TAG = "[SSL-NATIVE]";
function log(m) { console.log(TAG + " " + m); }

// ─── OpenSSL / BoringSSL generic ───
function hookOpenSsl() {
    const libs = ["libssl.so", "libboringssl.so", "libssl.so.1.1", "libssl_external.so"];
    let hookedAny = false;

    libs.forEach(function (libName) {
        let mod = null;
        try { mod = Process.findModuleByName(libName); } catch (e) { }
        if (!mod) return;

        // SSL_CTX_set_verify(ctx, mode, callback) -> force SSL_VERIFY_NONE (0)
        try {
            const p = mod.findExportByName("SSL_CTX_set_verify");
            if (p) {
                Interceptor.attach(p, {
                    onEnter: function (args) {
                        args[1] = ptr(0);   // mode = SSL_VERIFY_NONE
                        args[2] = ptr(0);   // callback = NULL
                        log(libName + " SSL_CTX_set_verify -> VERIFY_NONE");
                    }
                });
                hookedAny = true;
            }
        } catch (e) { log("SSL_CTX_set_verify: " + e); }

        // SSL_set_verify (per-SSL object) -> same
        try {
            const p = mod.findExportByName("SSL_set_verify");
            if (p) {
                Interceptor.attach(p, {
                    onEnter: function (args) {
                        args[1] = ptr(0);
                        args[2] = ptr(0);
                        log(libName + " SSL_set_verify -> VERIFY_NONE");
                    }
                });
                hookedAny = true;
            }
        } catch (e) { /* optional */ }

        // X509_verify_cert(ctx) -> always 1 (success)
        try {
            const p = mod.findExportByName("X509_verify_cert");
            if (p) {
                Interceptor.attach(p, {
                    onLeave: function (retval) {
                        if (retval.toInt32() !== 1) {
                            log(libName + " X509_verify_cert " + retval +
                                " -> 1 (forced success)");
                            retval.replace(ptr(1));
                        }
                    }
                });
                hookedAny = true;
            }
        } catch (e) { /* optional */ }

        // SSL_verify_cert (BoringSSL session chain verify) -> 1
        try {
            const p = mod.findExportByName("SSL_verify_cert");
            if (p) {
                Interceptor.attach(p, {
                    onLeave: function (retval) {
                        if (retval.toInt32() !== 0) {
                            log(libName + " SSL_verify_cert -> 0 (OK)");
                            retval.replace(ptr(0)); // 0 == success in BoringSSL
                        }
                    }
                });
                hookedAny = true;
            }
        } catch (e) { /* optional */ }
    });

    if (!hookedAny) log("no OpenSSL/BoringSSL module loaded yet — will also fire on dlopen");
    return hookedAny;
}

// ─── Flutter (BoringSSL compiled into libflutter.so) ───
function hookFlutter() {
    let mod = null;
    try { mod = Process.findModuleByName("libflutter.so"); } catch (e) { }
    if (!mod) { log("libflutter.so not loaded (native Flutter check pending)"); return; }

    // Primary export (older engines)
    const exports = [
        "ssl_crypto_x509_session_verify_cert_chain",
        "SSL_CTX_set_verify",
        "X509_verify_cert"
    ];
    let done = false;
    exports.forEach(function (name) {
        if (done) return;
        try {
            const p = mod.findExportByName(name);
            if (!p) return;
            if (name === "SSL_CTX_set_verify") {
                Interceptor.attach(p, {
                    onEnter: function (args) { args[1] = ptr(0); args[2] = ptr(0); }
                });
            } else {
                Interceptor.attach(p, {
                    onLeave: function (retval) {
                        log("flutter " + name + " " + retval + " -> success");
                        if (name.indexOf("session_verify") !== -1) retval.replace(ptr(1));
                        else if (name.indexOf("X509") !== -1) retval.replace(ptr(1));
                    }
                });
            }
            log("flutter hooked: " + name);
            done = true;
        } catch (e) { /* try next */ }
    });

    // Pattern-scan fallback (Riptls-style): search engine for the verify function
    if (!done) {
        try {
            // Common AArch64 pattern prologue of ssl_crypto_x509_session_verify_cert_chain
            const patterns = [
                "?? 0F 1C F8 ?? ?? 01 A9 ?? ?? 02 A9 ?? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9",
                "FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? ?? 06 94 68 1A 40 F9"
            ];
            for (let i = 0; i < patterns.length; i++) {
                const matches = Memory.scanSync(mod.base, mod.size, patterns[i]);
                if (matches.length > 0) {
                    const addr = matches[0].address;
                    Interceptor.attach(addr, {
                        onLeave: function (retval) {
                            log("flutter pattern-match verify @ " + addr + " -> 1");
                            retval.replace(ptr(1));
                        }
                    });
                    log("flutter pattern hooked @ " + addr + " (match " +
                        (i + 1) + "/" + patterns.length + ")");
                    done = true;
                    break;
                }
            }
        } catch (e) { log("flutter pattern scan: " + e); }
    }
    if (!done) log("flutter verify fn not located — engine version needs new pattern");
}

// ─── catch libraries loaded AFTER script start (lazy TLS stacks) ───
function watchLibraryLoads() {
    try {
        const dlopen = Module.findExportByName("linker64", "__loader_android_dlopen_ext") ||
            Module.findExportByName("linker", "__loader_android_dlopen_ext");
        if (!dlopen) return;
        Interceptor.attach(dlopen, {
            onLeave: function (retval) {
                // cheap re-check: if a TLS lib just landed, arm it (idempotent-ish)
                try {
                    if (Process.findModuleByName("libssl.so") ||
                        Process.findModuleByName("libboringssl.so")) {
                        hookOpenSsl();
                    }
                    if (Process.findModuleByName("libflutter.so")) {
                        hookFlutter();
                    }
                } catch (e) { /* ignore */ }
            }
        });
        log("library-load watcher armed");
    } catch (e) { log("watcher: " + e); }
}

if (hookOpenSsl()) log("OpenSSL layer armed");
hookFlutter();
watchLibraryLoads();

// L3 retry for lazy loads
setTimeout(function () { hookOpenSsl(); hookFlutter(); }, 1500);
setTimeout(function () { hookOpenSsl(); hookFlutter(); }, 4000);

log("native TLS unpin active — combine with ssl-pinning-bypass.js for Java layer");
