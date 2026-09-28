#!/usr/bin/env bash
# preflight-check.sh — Toolchain integrity and environment validation
set -uo pipefail
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

PASS=0; FAIL=0; WARN=0

check() {
  local name="$1" cmd="$2" min_version="${3:-}"
  if command -v "$cmd" >/dev/null 2>&1; then
    local ver
    ver=$($cmd --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+[0-9.]*' | head -1)
    if [ -n "$min_version" ] && [ -n "$ver" ]; then
      if printf '%s\n%s\n' "$min_version" "$ver" | sort -V | head -1 | grep -q "$min_version"; then
        echo -e "${GREEN}[PASS]${NC} $name ($cmd $ver)"
        PASS=$((PASS + 1))
      else
        echo -e "${YELLOW}[WARN]${NC} $name ($cmd $ver) < recommended $min_version"
        WARN=$((WARN + 1))
      fi
    else
      echo -e "${GREEN}[PASS]${NC} $name ($cmd ${ver:-installed})"
      PASS=$((PASS + 1))
    fi
  else
    echo -e "${RED}[FAIL]${NC} $name ($cmd not found)"
    FAIL=$((FAIL + 1))
  fi
}

check_optional() {
  local name="$1" cmd="$2"
  if command -v "$cmd" >/dev/null 2>&1; then
    echo -e "${GREEN}[PASS]${NC} $name ($cmd optional, installed)"
    PASS=$((PASS + 1))
  else
    echo -e "${YELLOW}[WARN]${NC} $name ($cmd optional, not installed)"
    WARN=$((WARN + 1))
  fi
}

check_file() {
  local name="$1" path="$2"
  if [ -f "$path" ]; then
    echo -e "${GREEN}[PASS]${NC} $name exists"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}[FAIL]${NC} $name missing ($path)"
    FAIL=$((FAIL + 1))
  fi
}

check_dir() {
  local name="$1" path="$2"
  if [ -d "$path" ]; then
    echo -e "${GREEN}[PASS]${NC} $name exists"
    PASS=$((PASS + 1))
  else
    echo -e "${YELLOW}[WARN]${NC} $name missing ($path)"
    WARN=$((WARN + 1))
  fi
}

echo "=============================================="
echo "  viny-motion APK Pipeline — Preflight Check"
echo "=============================================="
echo ""

echo "=== A. Core Tools ==="
check "Android Debug Bridge" "adb"
check "Frida" "frida"
check "Frida tools" "frida-ps"
check "JADX decompiler" "jadx" "1.5.0"
check "Objection" "objection"
check "Python 3" "python3" "3.8"
check "Curl" "curl"
check "Sqlite3" "sqlite3"
check "Java Runtime" "java" "11"
check "Unzip" "unzip"
check "Strings" "strings"
check "ReadELF" "readelf"

echo ""
echo "=== B. Android Tools ==="
check "AAPT" "aapt"
check_optional "AAPT2" "aapt2"
check_optional "APKTool" "apktool"
check_optional "D8/R8" "d8"
check_optional "Zipalign" "zipalign"
check_optional "Apksigner" "apksigner"

echo ""
echo "=== C. Security Tools ==="
check_optional "Nmap" "nmap"
check_optional "Semgrep" "semgrep"
check_optional "SQLMap" "sqlmap"
check_optional "Drozer" "drozer-console"
check_optional "Drozer" "drozer"
check_optional "Nuclei" "nuclei"
check_optional "FFUF" "ffuf"
check_optional "Gobuster" "gobuster"

echo ""
echo "=== D. Pipeline Files ==="
check_file "run.sh" "$PIPELINE_ROOT/run.sh"
check_file "lib/common.sh" "$PIPELINE_ROOT/lib/common.sh"
check_file "lib/findings.sh" "$PIPELINE_ROOT/lib/findings.sh"
check_file "config/target.yaml" "$PIPELINE_ROOT/config/target.yaml"
check_file "config/findings-schema.json" "$PIPELINE_ROOT/config/findings-schema.json"
check_file "config/rasp-detector-catalog.json" "$PIPELINE_ROOT/config/rasp-detector-catalog.json"
check_file "config/bypass-profiles.json" "$PIPELINE_ROOT/config/bypass-profiles.json"

echo ""
echo "=== E. Phase Scripts ==="
for phase in $(ls "$PIPELINE_ROOT/phases/" 2>/dev/null | sort); do
  check_file "Phase: $phase" "$PIPELINE_ROOT/phases/$phase"
done

echo ""
echo "=== F. Frida Scripts ==="
FRIDA_COUNT=$(ls "$PIPELINE_ROOT/extras/frida-scripts/" 2>/dev/null | wc -l)
if [ "$FRIDA_COUNT" -ge 60 ]; then
  echo -e "${GREEN}[PASS]${NC} Frida scripts: $FRIDA_COUNT (>= 60 target)"
  PASS=$((PASS + 1))
elif [ "$FRIDA_COUNT" -gt 0 ]; then
  echo -e "${YELLOW}[WARN]${NC} Frida scripts: $FRIDA_COUNT (< 60 target)"
  WARN=$((WARN + 1))
else
  echo -e "${RED}[FAIL]${NC} Frida scripts: $FRIDA_COUNT (missing)"
  FAIL=$((FAIL + 1))
fi

echo ""
echo "=== G. Device Connectivity ==="
if adb devices 2>/dev/null | grep -q "device$"; then
  DEVICE_COUNT=$(adb devices 2>/dev/null | grep -c "device$")
  echo -e "${GREEN}[PASS]${NC} ADB devices connected: $DEVICE_COUNT"
  PASS=$((PASS + 1))
  
  DEVICE_MODEL=$(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r')
  ANDROID_VER=$(adb shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')
  SDK_VER=$(adb shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')
  echo "       Device: $DEVICE_MODEL, Android $ANDROID_VER (SDK $SDK_VER)"
else
  echo -e "${RED}[FAIL]${NC} No ADB devices connected"
  FAIL=$((FAIL + 1))
fi

echo ""
echo "=== H. Burp Suite ==="
if curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080 2>/dev/null | grep -q "200"; then
  echo -e "${GREEN}[PASS]${NC} Burp Suite proxy running on :8080"
  PASS=$((PASS + 1))
else
  echo -e "${YELLOW}[WARN]${NC} Burp Suite proxy not detected on :8080"
  WARN=$((WARN + 1))
fi

echo ""
echo "=== I. RAG CLI ==="
if command -v rag >/dev/null 2>&1; then
  echo -e "${GREEN}[PASS]${NC} RAG CLI available"
  PASS=$((PASS + 1))
else
  echo -e "${YELLOW}[WARN]${NC} RAG CLI not in PATH"
  WARN=$((WARN + 1))
fi

echo ""
echo "=============================================="
echo -e "  ${GREEN}PASS: $PASS${NC}  ${YELLOW}WARN: $WARN${NC}  ${RED}FAIL: $FAIL${NC}"
echo "=============================================="

if [ "$FAIL" -gt 0 ]; then
  echo -e "${RED}[!] $FAIL critical checks failed — pipeline may not work${NC}"
  exit 1
elif [ "$WARN" -gt 0 ]; then
  echo -e "${YELLOW}[!] $WARN warnings — pipeline should work with reduced functionality${NC}"
  exit 0
else
  echo -e "${GREEN}[+] All checks passed — pipeline ready${NC}"
  exit 0
fi
