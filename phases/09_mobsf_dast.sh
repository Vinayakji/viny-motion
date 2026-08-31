#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 09_mobsf_dast.sh - MobSF + Burp DAST integration
PROFILE_PHASE="09_mobsf_dast"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
APK_PATH="$(tget apk path)"
[ -z "$PKG" ] && { err "No package_name"; exit 1; }

cd "$RUN_DIR" || exit 1
DAST_DIR="$RUN_DIR/dast"
mkdir -p "$DAST_DIR"

# ============================================================
# A. MobSF Automated Scan
# ============================================================
info "=== A. MobSF Scan ==="

# Check MobSF server
MOBSF_RUNNING=false
if curl -s http://127.0.0.1:8000/api/v1/upload > /dev/null 2>&1 || \
   curl -s http://127.0.0.1:8000/docs > /dev/null 2>&1; then
  MOBSF_RUNNING=true
  ok "MobSF server running"
else
  warn "MobSF not running. Start with: cd ~/tools/MobSF && python3 manage.py runserver 8000"
  info "Attempting to start MobSF..."
  if [ -d "$HOME/tools/MobSF" ]; then
    cd "$HOME/tools/MobSF" && python3 manage.py runserver 8000 &>/dev/null &
    sleep 5
    MOBSF_RUNNING=true
    ok "MobSF started"
  fi
fi

if $MOBSF_RUNNING && [ -n "$APK_PATH" ]; then
  # Upload APK to MobSF
  info "Uploading APK to MobSF..."
  UPLOAD_RESP=$(curl -s -F "file=@$APK_PATH" http://127.0.0.1:8000/api/v1/upload 2>/dev/null)
  HASH=$(echo "$UPLOAD_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('hash',''))" 2>/dev/null)

  if [ -n "$HASH" ]; then
    ok "APK uploaded: $HASH"

    # Static analysis
    info "Running MobSF static analysis..."
    curl -s -H "Content-Type: application/json" \
      -d '{"hash":"'$HASH'"}' \
      http://127.0.0.1:8000/api/v1/scan > "$DAST_DIR/mobsf_static.json" 2>/dev/null

    # Get report
    curl -s http://127.0.0.1:8000/api/v1/report_pdf?hash="$HASH" > "$DAST_DIR/mobsf_report.pdf" 2>/dev/null || true

    # Extract findings
    python3 -c "
import json, sys
try:
    with open('$DAST_DIR/mobsf_static.json') as f:
        data = json.load(f)
    # Extract high/critical issues
    if 'high_risk' in data:
        for item in data['high_risk']:
            print(f\"HIGH: {item.get('title','')} - {item.get('description','')}\")
    if 'critical' in data:
        for item in data['critical']:
            print(f\"CRITICAL: {item.get('title','')} - {item.get('description','')}\")
except: pass
" > "$DAST_DIR/mobsf_findings.txt" 2>/dev/null

    if [ -s "$DAST_DIR/mobsf_findings.txt" ]; then
      warn "MobSF findings detected"
      fadd "MobSF static analysis findings" MEDIUM CERTAIN CWE-0 "A00:2021" "$DAST_DIR/mobsf_findings.txt"
    fi
  fi
fi

# ============================================================
# B. Burp DAST — Extract Endpoints
# ============================================================
info "=== B. Burp Endpoint Extraction ==="

# Check Burp
if curl -s -o /dev/null http://127.0.0.1:8080 2>/dev/null; then
  ok "Burp proxy running"

  # Manual Burp requests for known endpoints
  for endpoint in \
    "GET /" \
    "GET /api" \
    "GET /api/v1" \
    "GET /api/v2" \
    "GET /graphql" \
    "GET /.well-known/openid-configuration" \
    "GET /swagger.json" \
    "GET /swagger-ui.html" \
    "GET /api-docs" \
    "GET /robots.txt" \
    "GET /sitemap.xml" \
    "GET /crossdomain.xml" \
    "GET /WEB-INF/web.xml"; do

    METHOD=$(echo "$endpoint" | cut -d' ' -f1)
    PATH_URL=$(echo "$endpoint" | cut -d' ' -f2)

    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X "$METHOD" "http://$(tget proxy host 2>/dev/null || echo 127.0.0.1):$(tget proxy port 2>/dev/null || echo 8080)${PATH_URL}" --proxy http://127.0.0.1:8080 2>/dev/null || echo "000")

    if [ "$RESPONSE" != "000" ] && [ "$RESPONSE" != "404" ]; then
      echo "$METHOD $PATH_URL -> $RESPONSE" >> "$DAST_DIR/endpoints.txt"
    fi
  done

  if [ -s "$DAST_DIR/endpoints.txt" ]; then
    ok "Endpoints discovered: $(wc -l < "$DAST_DIR/endpoints.txt")"
  fi
else
  warn "Burp proxy not running on 127.0.0.1:8080"
fi

# ============================================================
# C. Cleartext Traffic Analysis
# ============================================================
info "=== C. Cleartext Traffic ==="

# Check network security config
NSC="$RUN_DIR/static/network_security_config.xml"
if [ -f "$NSC" ]; then
  if grep -q "cleartextTrafficPermitted=\"true\"" "$NSC" 2>/dev/null; then
    warn "Cleartext traffic explicitly permitted"
    fadd "Cleartext traffic permitted in network security config" MEDIUM CERTAIN CWE-319 "A07:2021" "$NSC"
  fi
  if grep -q "trust-anchors" "$NSC" 2>/dev/null; then
    info "Custom trust anchors found in network security config"
  fi
fi

# Check AndroidManifest for usesCleartextTraffic
MANIFEST="$RUN_DIR/static/AndroidManifest.xml"
if [ -f "$MANIFEST" ]; then
  if grep -q "usesCleartextTraffic=\"true\"" "$MANIFEST" 2>/dev/null; then
    warn "usesCleartextTraffic=true in manifest"
    fadd "Cleartext traffic enabled in manifest" MEDIUM CERTAIN CWE-319 "A07:2021" "$MANIFEST"
  fi
fi

# ============================================================
# D. Insecure Logging Check
# ============================================================
info "=== D. Insecure Logging ==="

# Capture logcat and check for sensitive data
adb logcat -d -t 500 2>/dev/null | grep -iE "(password|token|secret|api.?key|authorization|bearer|cookie|session|credential)" > "$DAST_DIR/sensitive_logs.txt" 2>/dev/null || true

if [ -s "$DAST_DIR/sensitive_logs.txt" ]; then
  warn "Sensitive data in logs"
  fadd "Sensitive data in logcat" MEDIUM CERTAIN CWE-532 "A09:2021" "$DAST_DIR/sensitive_logs.txt"
fi

# ============================================================
# E. Clipboard Monitoring
# ============================================================
info "=== E. Clipboard Check ==="

CLIPBOARD=$(adb shell "am broadcast -a clipper.get" 2>/dev/null || true)
if echo "$CLIPBOARD" | grep -qi "token\|password\|secret\|key"; then
  warn "Sensitive data in clipboard"
  fadd "Sensitive data in clipboard" LOW CERTAIN CWE-316 "A04:2021" /dev/null
fi

ok "DAST phase complete -> $DAST_DIR"
fsnapshot
