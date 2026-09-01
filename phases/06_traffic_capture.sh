#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 06_traffic_capture.sh - Burp proxy setup, traffic logging, API endpoint extraction
PROFILE_PHASE="06_traffic_capture"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"

cd "$RUN_DIR" || exit 1
info "Traffic capture on $PKG"

TRAFFIC_DIR="$RUN_DIR/traffic"
mkdir -p "$TRAFFIC_DIR"

# ---- 1. Setup proxy ----
info "[step-1/6] Configuring HTTP proxy for traffic interception"
setup_proxy
info "  Proxy configured; all app traffic will route through the proxy"

# ---- 2. Start logcat capture ----
info "[step-2/6] Starting logcat capture"
info "  Clearing existing logcat buffer: adb logcat -c"
adb logcat -c 2>/dev/null
info "  Starting logcat background capture to: $TRAFFIC_DIR/logcat.txt"
adb logcat -v time > "$TRAFFIC_DIR/logcat.txt" 2>&1 &
LOGCAT_PID=$!
info "  logcat PID: $LOGCAT_PID"
info "  logcat filter: all (no filter); capturing full device output"

# ---- 3. Check Burp ----
info "[step-3/6] Checking Burp Suite proxy status"
info "  Testing connectivity: curl -s -o /dev/null http://127.0.0.1:8080"
if curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080 2>/dev/null | grep -q "200\|403\|503"; then
  ok "  Burp Suite is running on port 8080 (HTTP intercept active)"
else
  warn "  Burp Suite not detected on port 8080"
  warn "  Start Burp: ~/BurpSuitePro/BurpSuite"
  warn "  Traffic will still be captured via logcat but without HTTP interception"
fi

# ---- 4. Capture traffic for N seconds ----
info "[step-4/6] Traffic capture window"
CAPTURE_DURATION="${CAPTURE_DURATION:-60}"
info "  Capture duration: ${CAPTURE_DURATION}s"

# Trigger app activity
if [ -n "$PKG" ]; then
  info "  Launching app to generate traffic: adb shell monkey -p $PKG -c android.intent.category.LAUNCHER 1"
  adb_launch "$PKG"
  info "  Waiting 5s for app initialization before capture begins..."
  sleep 5
fi

info "  Capturing traffic... (app should be generating HTTP calls during this window)"
sleep "$CAPTURE_DURATION"
info "  Capture window complete"

# ---- 5. Extract API endpoints ----
info "[step-5/6] Extracting API endpoints and hosts from captured traffic"

# From logcat
info "  [extract-1/4] Extracting URLs from logcat (pattern: https?://...)"
grep -oE 'https?://[a-zA-Z0-9./_?=&-]+' "$TRAFFIC_DIR/logcat.txt" 2>/dev/null | \
  sort -u > "$TRAFFIC_DIR/api_endpoints.txt"

# From network logs
info "  [extract-2/4] Extracting HTTP method+path pairs from logcat"
grep -iE '(GET|POST|PUT|DELETE|PATCH) ' "$TRAFFIC_DIR/logcat.txt" 2>/dev/null | \
  sort -u > "$TRAFFIC_DIR/http_methods.txt"

# Extract hosts
info "  [extract-3/4] Extracting unique hostnames from discovered URLs"
grep -oE '[a-z0-9.-]+\.[a-z]{2,}' "$TRAFFIC_DIR/api_endpoints.txt" 2>/dev/null | \
  sort -u > "$TRAFFIC_DIR/hosts.txt"

# Count results
ENDPOINT_COUNT=$(wc -l < "$TRAFFIC_DIR/api_endpoints.txt" 2>/dev/null || echo 0)
METHOD_COUNT=$(wc -l < "$TRAFFIC_DIR/http_methods.txt" 2>/dev/null || echo 0)
HOST_COUNT=$(wc -l < "$TRAFFIC_DIR/hosts.txt" 2>/dev/null || echo 0)
info "  [extract-4/4] Extraction results:"
info "    Unique URLs: $ENDPOINT_COUNT"
info "    HTTP method+path pairs: $METHOD_COUNT"
info "    Unique hosts: $HOST_COUNT"

# ---- 6. Check for sensitive data in logs ----
info "[step-6/6] Scanning for sensitive data leaks in captured logs"

if grep -qiE '(token|key|secret|password|auth)' "$TRAFFIC_DIR/logcat.txt" 2>/dev/null; then
  warn "  Sensitive keywords detected in logcat output"
  grep -iE '(token|key|secret|password|auth)' "$TRAFFIC_DIR/logcat.txt" > "$TRAFFIC_DIR/sensitive_data.txt" 2>/dev/null
  SENS_LINES=$(wc -l < "$TRAFFIC_DIR/sensitive_data.txt" 2>/dev/null || echo 0)
  warn "  $SENS_LINES lines contain sensitive keywords"
  fadd "Sensitive data in logcat" HIGH MEDIUM CWE-532 "A09:2021" "$TRAFFIC_DIR/sensitive_data.txt"
else
  info "  No sensitive keywords found in logcat output"
fi

# ---- Cleanup ----
info "  Stopping logcat capture (PID $LOGCAT_PID)"
kill $LOGCAT_PID 2>/dev/null || true
info "  Clearing proxy configuration"
clear_proxy
info "  Proxy cleared; device returns to direct connection"

ok "Traffic capture complete -> $TRAFFIC_DIR"
ok "  Endpoints: $ENDPOINT_COUNT | Methods: $METHOD_COUNT | Hosts: $HOST_COUNT"
fsnapshot
