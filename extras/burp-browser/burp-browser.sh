#!/usr/bin/env bash
# burp-browser.sh - Playwright + FoxyProxy → Burp Suite browser harness
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BROWSER_SCRIPT="$SCRIPT_DIR/foxyproxy-burp.mjs"
PROFILE_DIR="/tmp/pw-burp-profile"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }
info() { echo -e "[...] $*"; }

# ---- Check prerequisites ----
command -v node >/dev/null 2>&1 || fail "node not found"
[ -f "$BROWSER_SCRIPT" ] || fail "foxyproxy-burp.mjs not found at $BROWSER_SCRIPT"

# Check if Playwright is installed
node -e "require('playwright')" 2>/dev/null || {
  info "Installing playwright..."
  npm install -g playwright 2>/dev/null
}

# Check Burp proxy
info "Checking Burp proxy on 127.0.0.1:8080..."
if curl -s -o /dev/null -w "%{http_code}" --proxy http://127.0.0.1:8080 http://httpbin.org/ip 2>/dev/null | grep -q "200"; then
  ok "Burp proxy is working"
else
  warn "Burp proxy may not be configured (continuing anyway)"
fi

# ---- Launch browser ----
info "Launching browser with FoxyProxy → Burp..."
DISPLAY=:0 node "$BROWSER_SCRIPT" --profile "$PROFILE_DIR" "$@"
