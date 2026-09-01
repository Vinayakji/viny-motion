#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 05_frida_hooks.sh - Custom Frida scripts (method tracing, memory search, SSL bypass)
PROFILE_PHASE="05_frida_hooks"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
HOOK_CLASSES="$(tget frida hook_classes)"

cd "$RUN_DIR" || exit 1
info "Custom Frida hooks on $PKG"

FRIDA_DIR="$RUN_DIR/frida"
mkdir -p "$FRIDA_DIR"

# Check frida
command -v frida >/dev/null 2>&1 || { warn "frida not installed (pip install frida-tools)"; exit 0; }
info "Frida version: $(frida --version 2>/dev/null || echo 'unknown')"

# ---- 1. Generate Frida scripts ----
info "[step-1/4] Generating Frida instrumentation scripts"

# SSL Pinning Bypass script
info "  [script-1/4] ssl_bypass.js — hooks TrustManagerImpl.verifyChain + TrustManager.checkServerTrusted"
cat > "$FRIDA_DIR/ssl_bypass.js" <<'EOF'
Java.perform(function() {
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        return untrustedChain;
    };
    
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManager = Java.registerClass({
        name: 'custom.TrustManager',
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    var TrustManagers = [TrustManager.$new()];
    var SSLContextInit = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
    SSLContextInit.implementation = function(keyManagers, trustManagers, secureRandom) {
        SSLContextInit.call(this, keyManagers, TrustManagers, secureRandom);
    };
    
    console.log('[+] SSL Pinning Bypassed');
});
EOF
info "    Written to $FRIDA_DIR/ssl_bypass.js"

# Method Tracer script
info "  [script-2/4] method_tracer.js — enumerates classes matching login|auth|token|password"
cat > "$FRIDA_DIR/method_tracer.js" <<'EOF'
Java.perform(function() {
    var classes = Java.enumerateLoadedClassesSync();
    classes.forEach(function(className) {
        if (className.includes('login') || className.includes('auth') || 
            className.includes('token') || className.includes('password')) {
            console.log('[*] Found: ' + className);
            try {
                var clazz = Java.use(className);
                var methods = clazz.class.getDeclaredMethods();
                methods.forEach(function(method) {
                    console.log('    -> ' + method.getName());
                });
            } catch(e) {}
        }
    });
});
EOF
info "    Written to $FRIDA_DIR/method_tracer.js"

# Memory Search script
info "  [script-3/4] memory_search.js — enumerates loaded classes matching sensitive patterns"
cat > "$FRIDA_DIR/memory_search.js" <<'EOF'
Java.perform(function() {
    var patterns = ['password', 'secret', 'token', 'api_key', 'apikey', 'auth'];
    
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            patterns.forEach(function(pattern) {
                if (className.toLowerCase().includes(pattern)) {
                    console.log('[!] Sensitive class: ' + className);
                }
            });
        },
        onComplete: function() {}
    });
});
EOF
info "    Written to $FRIDA_DIR/memory_search.js"

# Network Interception script
info "  [script-4/4] network_intercept.js — hooks java.net.URL and HttpURLConnection"
cat > "$FRIDA_DIR/network_intercept.js" <<'EOF'
Java.perform(function() {
    var URL = Java.use('java.net.URL');
    var HttpURLConnection = Java.use('java.net.HttpURLConnection');
    
    URL.$init.overload('java.lang.String').implementation = function(url) {
        console.log('[URL] ' + url);
        return this.$init(url);
    };
    
    HttpURLConnection.setRequestMethod.implementation = function(method) {
        console.log('[METHOD] ' + method + ' -> ' + this.getURL().toString());
        return this.setRequestMethod(method);
    };
});
EOF
info "    Written to $FRIDA_DIR/network_intercept.js"

ok "  All 4 Frida scripts generated"

# ---- 2. Run SSL bypass ----
info "[step-2/4] Executing SSL Pinning Bypass"
info "  Command: frida -U -f $PKG -l $FRIDA_DIR/ssl_bypass.js --no-pause"
info "  Capture: $FRIDA_DIR/ssl_output.txt"
info "  Duration: 10s"
frida -U -f "$PKG" -l "$FRIDA_DIR/ssl_bypass.js" --no-pause > "$FRIDA_DIR/ssl_output.txt" 2>&1 &
FRIDA_PID=$!
info "  Frida PID: $FRIDA_PID"
sleep 10
kill $FRIDA_PID 2>/dev/null || true
info "  Process terminated"

if grep -q "SSL Pinning Bypassed" "$FRIDA_DIR/ssl_output.txt" 2>/dev/null; then
  ok "  SSL bypass script executed successfully"
  fadd "SSL pinning bypass (Frida)" MEDIUM MEDIUM CWE-295 "A02:2021" "$FRIDA_DIR/ssl_output.txt"
else
  warn "  SSL bypass may have failed (no success marker in output)"
fi

# ---- 3. Run method tracer ----
info "[step-3/4] Executing Method Tracer"
info "  Command: frida -U -f $PKG -l $FRIDA_DIR/method_tracer.js --no-pause"
info "  Capture: $FRIDA_DIR/tracer_output.txt"
info "  Duration: 10s"
frida -U -f "$PKG" -l "$FRIDA_DIR/method_tracer.js" --no-pause > "$FRIDA_DIR/tracer_output.txt" 2>&1 &
FRIDA_PID=$!
info "  Frida PID: $FRIDA_PID"
sleep 10
kill $FRIDA_PID 2>/dev/null || true
info "  Process terminated"

if grep -q "Found:" "$FRIDA_DIR/tracer_output.txt" 2>/dev/null; then
  SENSITIVE_CLASSES=$(grep -c "Found:" "$FRIDA_DIR/tracer_output.txt")
  warn "  $SENSITIVE_CLASSES sensitive classes discovered by tracer"
  fadd "Sensitive classes found (Frida tracer)" LOW CERTAIN CWE-532 "A09:2021" "$FRIDA_DIR/tracer_output.txt"
else
  info "  No sensitive classes matched by tracer"
fi

# ---- 4. Summary ----
info "[step-4/4] Frida hook results summary"
SSL_LINES=$(wc -l < "$FRIDA_DIR/ssl_output.txt" 2>/dev/null || echo 0)
TRACER_LINES=$(wc -l < "$FRIDA_DIR/tracer_output.txt" 2>/dev/null || echo 0)
info "  ssl_output.txt: $SSL_LINES lines"
info "  tracer_output.txt: $TRACER_LINES lines"

ok "Frida hooks complete -> $FRIDA_DIR"
fsnapshot
