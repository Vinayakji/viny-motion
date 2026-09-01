#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 09_mobsf_dast.sh - MobSF static scan + Burp DAST endpoint discovery + cleartext + logging + clipboard
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
info "=== A. MobSF Static Analysis Scan ==="

info "[step-A1/5] Checking MobSF server availability"
MOBSF_RUNNING=false
if curl -s http://127.0.0.1:8000/api/v1/upload > /dev/null 2>&1 || \
   curl -s http://127.0.0.1:8000/docs > /dev/null 2>&1; then
  MOBSF_RUNNING=true
  ok "  MobSF server running on port 8000"
else
  warn "  MobSF not running. Attempting auto-start..."
  if [ -d "$HOME/tools/MobSF" ]; then
    info "  Starting MobSF: cd $HOME/tools/MobSF && python3 manage.py runserver 8000"
    cd "$HOME/tools/MobSF" && python3 manage.py runserver 8000 &>/dev/null &
    sleep 5
    MOBSF_RUNNING=true
    ok "  MobSF started"
  else
    warn "  MobSF not found at ~/tools/MobSF; skipping MobSF scan"
  fi
fi

if $MOBSF_RUNNING && [ -n "$APK_PATH" ]; then
  info "[step-A2/5] Uploading APK to MobSF"
  info "  APK: $APK_PATH"
  UPLOAD_RESP=$(curl -s -F "file=@$APK_PATH" http://127.0.0.1:8000/api/v1/upload 2>/dev/null)
  HASH=$(echo "$UPLOAD_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('hash',''))" 2>/dev/null)

  if [ -n "$HASH" ]; then
    ok "  APK uploaded successfully: hash=$HASH"

    info "[step-A3/5] Running MobSF static analysis"
    info "  POST /api/v1/scan with hash=$HASH"
    curl -s -H "Content-Type: application/json" \
      -d '{"hash":"'$HASH'"}' \
      http://127.0.0.1:8000/api/v1/scan > "$DAST_DIR/mobsf_static.json" 2>/dev/null
    STATIC_SIZE=$(du -h "$DAST_DIR/mobsf_static.json" 2>/dev/null | cut -f1)
    info "  Static analysis response size: $STATIC_SIZE"

    info "[step-A4/5] Downloading MobSF PDF report"
    curl -s http://127.0.0.1:8000/api/v1/report_pdf?hash="$HASH" > "$DAST_DIR/mobsf_report.pdf" 2>/dev/null || true
    if [ -s "$DAST_DIR/mobsf_report.pdf" ]; then
      info "  PDF report downloaded: $(du -h "$DAST_DIR/mobsf_report.pdf" | cut -f1)"
    else
      info "  PDF report empty or unavailable"
    fi

    info "[step-A5/5] Extracting MobSF findings"
    python3 -c "
import json, sys
try:
    with open('$DAST_DIR/mobsf_static.json') as f:
        data = json.load(f)
    if 'high_risk' in data:
        for item in data['high_risk']:
            print(f\"HIGH: {item.get('title','')} - {item.get('description','')}\")
    if 'critical' in data:
        for item in data['critical']:
            print(f\"CRITICAL: {item.get('title','')} - {item.get('description','')}\")
except: pass
" > "$DAST_DIR/mobsf_findings.txt" 2>/dev/null

    MOBSF_HITS=$(wc -l < "$DAST_DIR/mobsf_findings.txt" 2>/dev/null || echo 0)
    if [ "$MOBSF_HITS" -gt 0 ]; then
      warn "  MobSF found $MOBSF_HITS high/critical findings"
      fadd "MobSF static analysis findings ($MOBSF_HITS issues)" MEDIUM CERTAIN CWE-0 "A00:2021" "$DAST_DIR/mobsf_findings.txt"
    else
      info "  MobSF returned no high/critical findings"
    fi
  else
    warn "  APK upload failed (no hash returned)"
  fi
fi

# ============================================================
# B. Burp DAST — Extract Endpoints
# ============================================================
info "=== B. Burp Endpoint Discovery ==="

info "[step-B1/3] Checking Burp proxy on port 8080"
if curl -s -o /dev/null http://127.0.0.1:8080 2>/dev/null; then
  ok "  Burp proxy running"

  info "[step-B2/3] Sending probe requests for common endpoints"
  ENDPOINTS=(
    "GET /"
    "GET /api"
    "GET /api/v1"
    "GET /api/v2"
    "GET /graphql"
    "GET /.well-known/openid-configuration"
    "GET /swagger.json"
    "GET /swagger-ui.html"
    "GET /api-docs"
    "GET /robots.txt"
    "GET /sitemap.xml"
    "GET /crossdomain.xml"
    "GET /WEB-INF/web.xml"
  )

  for endpoint in "${ENDPOINTS[@]}"; do
    METHOD=$(echo "$endpoint" | cut -d' ' -f1)
    PATH_URL=$(echo "$endpoint" | cut -d' ' -f2)
    info "  Probing: $METHOD $PATH_URL"
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X "$METHOD" "http://127.0.0.1:8080${PATH_URL}" --proxy http://127.0.0.1:8080 2>/dev/null || echo "000")
    if [ "$RESPONSE" != "000" ] && [ "$RESPONSE" != "404" ]; then
      echo "$METHOD $PATH_URL -> $RESPONSE" >> "$DAST_DIR/endpoints.txt"
      info "    -> $RESPONSE (interesting)"
    fi
  done

  ENDPOINT_HITS=$(wc -l < "$DAST_DIR/endpoints.txt" 2>/dev/null || echo 0)
  info "[step-B3/3] Endpoint discovery results: $ENDPOINT_HITS non-404 responses"
else
  warn "  Burp proxy not running on 127.0.0.1:8080; skipping endpoint probes"
fi

# ============================================================
# C. Cleartext Traffic Analysis
# ============================================================
info "=== C. Cleartext Traffic Analysis ==="

info "[step-C1/2] Checking network_security_config.xml"
NSC="$RUN_DIR/static/network_security_config.xml"
if [ -f "$NSC" ]; then
  info "  Found: $NSC"
  if grep -q "cleartextTrafficPermitted=\"true\"" "$NSC" 2>/dev/null; then
    warn "  Cleartext traffic explicitly permitted in network security config"
    fadd "Cleartext traffic permitted in network security config" MEDIUM CERTAIN CWE-319 "A07:2021" "$NSC"
  else
    info "  cleartextTrafficPermitted is not true"
  fi
  if grep -q "trust-anchors" "$NSC" 2>/dev/null; then
    info "  Custom trust-anchors found in network security config"
  fi
else
  info "  network_security_config.xml not found"
fi

info "[step-C2/2] Checking AndroidManifest for usesCleartextTraffic"
MANIFEST="$RUN_DIR/static/AndroidManifest.xml"
if [ -f "$MANIFEST" ]; then
  if grep -q "usesCleartextTraffic=\"true\"" "$MANIFEST" 2>/dev/null; then
    warn "  usesCleartextTraffic=true in manifest"
    fadd "Cleartext traffic enabled in manifest" MEDIUM CERTAIN CWE-319 "A07:2021" "$MANIFEST"
  else
    info "  usesCleartextTraffic is not true (or absent)"
  fi
else
  info "  AndroidManifest.xml not found"
fi

# ============================================================
# D. Insecure Logging Check
# ============================================================
info "=== D. Insecure Logging Check ==="

info "[step-D1/1] Scanning logcat for sensitive data patterns"
info "  Capturing last 500 logcat entries"
adb logcat -d -t 500 2>/dev/null | grep -iE "(password|token|secret|api.?key|authorization|bearer|cookie|session|credential)" > "$DAST_DIR/sensitive_logs.txt" 2>/dev/null || true

SENS_LOG_LINES=$(wc -l < "$DAST_DIR/sensitive_logs.txt" 2>/dev/null || echo 0)
if [ "$SENS_LOG_LINES" -gt 0 ]; then
  warn "  $SENS_LOG_LINES logcat lines contain sensitive keywords"
  fadd "Sensitive data in logcat ($SENS_LOG_LINES lines)" MEDIUM CERTAIN CWE-532 "A09:2021" "$DAST_DIR/sensitive_logs.txt"
else
  info "  No sensitive keywords found in recent logcat"
fi

# ============================================================
# E. Clipboard Monitoring
# ============================================================
info "=== E. Clipboard Check ==="

info "[step-E1/1] Checking clipboard for sensitive data"
CLIPBOARD=$(adb shell "am broadcast -a clipper.get" 2>/dev/null || true)
if echo "$CLIPBOARD" | grep -qi "token\|password\|secret\|key"; then
  warn "  Sensitive data detected in clipboard"
  fadd "Sensitive data in clipboard" LOW CERTAIN CWE-316 "A04:2021" /dev/null
else
  info "  No sensitive data in clipboard"
fi

ok "DAST phase complete -> $DAST_DIR"
ok "  MobSF: ${MOBSF_HITS:-0} findings | Endpoints: ${ENDPOINT_HITS:-0} | Logcat leaks: $SENS_LOG_LINES"
fsnapshot
