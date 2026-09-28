#!/bin/bash
# fix-genymotion-internet.sh — Clear dead global proxy blocking Genymotion internet
# Root cause: Android sets global HTTP proxy to QEMU SLIRP gateway (10.0.2.2:8080)
# which is NOT a real HTTP proxy. All app traffic fails.
#
# WiFi proxy (Burp Suite at host:8081) is separate and correct — left untouched.
#
# Usage: ./fix-genymotion-internet.sh [serial]
# Run after every Genymotion boot or when apps can't reach internet.

set -euo pipefail

SERIAL="${1:-}"
ADB="adb"
[[ -n "$SERIAL" ]] && ADB="adb -s $SERIAL"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*" >&2; }

# Pre-flight: check device
if ! $ADB shell echo ok &>/dev/null; then
    err "No ADB device connected"
    exit 1
fi

log "Genymotion Internet Fix"
echo "========================"

# Show current state
CURRENT_PROXY=$($ADB shell "settings get global http_proxy" 2>/dev/null | tr -d '\r')
WIFI_PROXY=$($ADB shell "dumpsys connectivity" 2>/dev/null | grep -oP 'HttpProxy: \[\K[^\]]+' | head -1 | tr -d '\r')

echo "Current global proxy: ${CURRENT_PROXY:-none}"
echo "WiFi proxy:           ${WIFI_PROXY:-none}"
echo ""

# Step 1: Clear dead global proxy
if [[ "$CURRENT_PROXY" != "null" && "$CURRENT_PROXY" != ":0" && -n "$CURRENT_PROXY" ]]; then
    log "Clearing dead global proxy: $CURRENT_PROXY"
    $ADB shell "settings delete global http_proxy" 2>/dev/null
    $ADB shell "settings delete global global_http_proxy_host" 2>/dev/null
    $ADB shell "settings delete global global_http_proxy_port" 2>/dev/null
    $ADB shell "settings delete global global_http_proxy_exclusion_list" 2>/dev/null
    $ADB shell "settings delete global proxy_pac_url" 2>/dev/null
    sleep 1
    log "Global proxy cleared"
else
    log "Global proxy already clean"
fi

# Step 2: Verify connectivity
echo ""
log "Testing connectivity..."
HTTP_OK=false
if $ADB shell "wget -q --spider --timeout=5 http://www.google.com" 2>/dev/null; then
    HTTP_OK=true
    log "HTTP: OK"
else
    warn "HTTP: FAIL"
fi

# Step 3: Verify proxy state
echo ""
AFTER_PROXY=$($ADB shell "settings get global http_proxy" 2>/dev/null | tr -d '\r')
WIFI_AFTER=$($ADB shell "dumpsys connectivity" 2>/dev/null | grep -oP 'HttpProxy: \[\K[^\]]+' | head -1 | tr -d '\r')
echo "Global proxy after fix: ${AFTER_PROXY:-none}"
echo "WiFi proxy preserved:   ${WIFI_AFTER:-none}"

# Step 4: Routes
echo ""
log "Device routes:"
$ADB shell "ip route" 2>/dev/null | sed 's/^/  /'

echo ""
if $HTTP_OK; then
    log "Internet is WORKING"
else
    warn "Internet still broken — check DNS and routes"
    warn "Try: svc data disable && svc data enable"
fi
