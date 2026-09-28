#!/usr/bin/env bash
# setup.sh - viny-motion Pipeline dependency installer
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
info() { echo -e "[...] $*"; }

ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "=========================================="
echo "  viny-motion APK Pentesting Pipeline"
echo "=========================================="
echo ""

# ---- 1. Check prerequisites ----
info "Checking prerequisites..."

for cmd in bash curl jq python3 adb; do
  command -v "$cmd" >/dev/null 2>&1 && ok "$cmd" || fail "$cmd (not found)"
done

# Check viny-motion
if [ -d "$HOME/genymotion" ]; then
  ok "viny-motion ($HOME/genymotion)"
else
  fail "viny-motion not found at ~/genymotion"
fi

# Check viny-motion binary
if [ -x "$HOME/genymotion/genymotion" ]; then
  ok "genymotion binary"
elif [ -x "$HOME/genymotion/player" ]; then
  ok "genymotion player"
else
  warn "genymotion binary not found (may need installation)"
fi

echo ""

# ---- 2. Check Python tools ----
info "Checking Python tools..."

PYTHON_TOOLS=(drozer objection frida-tools)
for tool in "${PYTHON_TOOLS[@]}"; do
  pip3 show "$tool" >/dev/null 2>&1 && ok "$tool" || warn "$tool (pip install $tool)"
done

echo ""

# ---- 3. Check Java tools ----
info "Checking Java tools..."

command -v jadx >/dev/null 2>&1 && ok "jadx" || warn "jadx (apt install jadx)"

# Check MobSF
if docker ps 2>/dev/null | grep -q mobsf; then
  ok "MobSF (running)"
elif docker images 2>/dev/null | grep -q mobsf; then
  warn "MobSF (image exists, not running - start with: docker run -p 8000:8000 opensecurity/mobsf)"
else
  warn "MobSF (not installed - docker pull opensecurity/mobsf)"
fi

echo ""

# ---- 4. Check Burp Suite ----
info "Checking Burp Suite..."

if [ -x "$HOME/BurpSuitePro/BurpSuite" ]; then
  ok "Burp Suite Pro"
elif command -v burpsuite >/dev/null 2>&1; then
  ok "Burp Suite"
else
  warn "Burp Suite not found (optional for traffic capture)"
fi

echo ""

# ---- 5. Create config template ----
CONFIG="$ROOT/config/target.yaml"
if [ ! -f "$CONFIG" ]; then
  info "Creating config template..."
  cat > "$CONFIG" <<'YAML'
# ============================================================
# viny-motion Pipeline - target config
# ============================================================

apk:
  path: ""                              # Local APK path
  package_name: ""                      # Android package name (e.g. com.example.app)
  download_url: ""                      # Or provide download URL

viny-motion:
  device_name: "pipeline-test"          # viny-motion device name
  android_version: "11.0"              # Android version
  resolution: "1080x1920"              # Screen resolution
  memory: 4096                          # RAM in MB

proxy:
  host: "127.0.0.1"
  port: 8080                            # Burp proxy port

frida:
  ssl_bypass: true
  root_bypass: true
  hook_classes: []                      # Additional classes to hook (e.g. ["com.example.LoginActivity"])

auth:
  jwt: ""
  headers: {}
YAML
  ok "config/target.yaml created"
else
  ok "config/target.yaml already exists"
fi

echo ""

# ---- 6. Make scripts executable ----
info "Setting permissions..."
chmod +x "$ROOT"/phases/*.sh "$ROOT"/run.sh 2>/dev/null
ok "scripts made executable"

echo ""
echo "=========================================="
echo "  Setup complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. Edit config/target.yaml with your APK and device settings"
echo "  2. Ensure viny-motion is installed: ~/genymotion/genymotion"
echo "  3. Run: ./run.sh check"
echo "  4. Run: ./run.sh all"
echo ""
echo "Optional:"
echo "  - pip install drozer objection frida-tools"
echo "  - apt install jadx"
echo "  - docker run -p 8000:8000 opensecurity/mobsf"
echo ""
