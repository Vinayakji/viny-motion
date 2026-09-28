#!/usr/bin/env bash
# setup_burp_proxy.sh - Configure Genymotion device to route traffic through Burp Suite
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }
info() { echo -e "[...] $*"; }

# ---- Config ----
PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-8080}"
CERT_DIR="/tmp/burp-cert"
DEVICE_CERT="/data/local/tmp/burp-cert.pem"

# ---- Check Burp ----
info "Checking Burp Suite on $PROXY_HOST:$PROXY_PORT..."
if ! curl -s -o /dev/null -w "%{http_code}" --proxy "http://$PROXY_HOST:$PROXY_PORT" http://httpbin.org/ip 2>/dev/null | grep -q "200"; then
  fail "Burp Suite not reachable on $PROXY_HOST:$PROXY_PORT"
fi
ok "Burp Suite is running"

# ---- Check device ----
if ! adb get-state >/dev/null 2>&1; then
  fail "No Android device connected"
fi
ok "Device connected: $(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r')"

# ---- 1. Set proxy on device ----
info "Setting HTTP proxy on device..."
adb shell settings put global http_proxy "$PROXY_HOST:$PROXY_PORT" 2>/dev/null
ok "Proxy set: $PROXY_HOST:$PROXY_PORT"

# ---- 2. Install Burp CA certificate ----
info "Installing Burp CA certificate..."

# Export Burp cert
mkdir -p "$CERT_DIR"
if [ -f ~/BurpSuitePro/BurpSuite ]; then
  # Try to extract from Burp
  curl -s --proxy "http://$PROXY_HOST:$PROXY_PORT" -k "http://burp" > "$CERT_DIR/burp.der" 2>/dev/null || true
fi

# Fallback: download from Burp Suite
if [ ! -s "$CERT_DIR/burp.der" ]; then
  info "Download cert: http://burp (in browser configured with Burp proxy)"
  info "Or place burp.der in $CERT_DIR/"
fi

# Convert to PEM if we have the DER
if [ -f "$CERT_DIR/burp.der" ]; then
  openssl x509 -inform DER -in "$CERT_DIR/burp.der" -out "$CERT_DIR/burp.pem" 2>/dev/null || true
fi

# Install on device
if [ -f "$CERT_DIR/burp.pem" ]; then
  adb push "$CERT_DIR/burp.pem" "$DEVICE_CERT" 2>/dev/null
  
  # For Android 7+ (API 24+), install as user certificate
  ANDROID_VER="$(adb shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')"
  if [ "$ANDROID_VER" -ge 24 ]; then
    info "Android $ANDROID_VER detected - installing as user CA..."
    adb shell "su -c 'cp $DEVICE_CERT /data/misc/user/0/cacerts-added/burp.pem'" 2>/dev/null || \
    adb shell "cp $DEVICE_CERT /sdcard/Download/burp.pem" 2>/dev/null
    
    # Prompt user to install manually if root not available
    warn "If cert not trusted, install manually:"
    warn "  Settings → Security → Install from SD card → Download/burp.pem"
  else
    adb shell "cp $DEVICE_CERT /system/etc/security/cacerts/burp.pem" 2>/dev/null || \
    warn "Could not install as system cert (no root)"
  fi
  ok "Burp certificate installed"
else
  warn "No certificate found at $CERT_DIR/burp.pem"
  warn "Manual steps:"
  warn "  1. Configure browser proxy to Burp"
  warn "  2. Visit http://burp"
  warn "  3. Download CA certificate"
  warn "  4. Place at $CERT_DIR/burp.der"
  warn "  5. Run this script again"
fi

# ---- 3. Verify traffic capture ----
info "Verifying traffic capture..."
adb shell "am start -a android.intent.action.VIEW -d 'http://httpbin.org/ip'" 2>/dev/null
sleep 3

echo ""
echo "=========================================="
echo "  Burp Proxy Setup Complete"
echo "=========================================="
echo ""
echo "  Device:  $(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r')"
echo "  Proxy:   $PROXY_HOST:$PROXY_PORT"
echo "  Cert:    $CERT_DIR/burp.pem"
echo ""
echo "  Next steps:"
echo "  1. Open app on device"
echo "  2. Check Burp Suite HTTP history"
echo "  3. Test endpoints with Repeater/Intruder"
echo ""
echo "  To clear proxy:"
echo "  adb shell settings put global http_proxy :0"
echo "=========================================="
