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
setup_proxy

# ---- 2. Start logcat capture ----
info "Starting logcat capture..."
adb logcat -c 2>/dev/null
adb logcat -v time > "$TRAFFIC_DIR/logcat.txt" 2>&1 &
LOGCAT_PID=$!
info "logcat PID: $LOGCAT_PID"

# ---- 3. Check Burp ----
info "Checking Burp Suite..."
if curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080 2>/dev/null | grep -q "200\|403\|503"; then
  ok "Burp Suite is running on port 8080"
else
  warn "Burp Suite not detected on port 8080"
  warn "Start Burp: ~/BurpSuitePro/BurpSuite"
fi

# ---- 4. Capture traffic for N seconds ----
CAPTURE_DURATION=30
info "Capturing traffic for ${CAPTURE_DURATION}s..."

# Trigger app activity
if [ -n "$PKG" ]; then
  adb_launch "$PKG"
  sleep 5
fi

# Wait and collect
sleep "$CAPTURE_DURATION"

# ---- 5. Extract API endpoints ----
info "Extracting API endpoints..."

# From logcat
grep -oE 'https?://[a-zA-Z0-9./_?=&-]+' "$TRAFFIC_DIR/logcat.txt" 2>/dev/null | \
  sort -u > "$TRAFFIC_DIR/api_endpoints.txt"

# From network logs
grep -iE '(GET|POST|PUT|DELETE|PATCH) ' "$TRAFFIC_DIR/logcat.txt" 2>/dev/null | \
  sort -u > "$TRAFFIC_DIR/http_methods.txt"

# Extract hosts
grep -oE '[a-z0-9.-]+\.[a-z]{2,}' "$TRAFFIC_DIR/api_endpoints.txt" 2>/dev/null | \
  sort -u > "$TRAFFIC_DIR/hosts.txt"

ENDPOINT_COUNT=$(wc -l < "$TRAFFIC_DIR/api_endpoints.txt" 2>/dev/null || echo 0)
info "API endpoints found: $ENDPOINT_COUNT"

# ---- 6. Check for sensitive data in logs ----
info "Checking for sensitive data leaks..."

# Check for tokens/keys in logcat
if grep -qiE '(token|key|secret|password|auth)' "$TRAFFIC_DIR/logcat.txt" 2>/dev/null; then
  warn "Sensitive data found in logcat"
  grep -iE '(token|key|secret|password|auth)' "$TRAFFIC_DIR/logcat.txt" > "$TRAFFIC_DIR/sensitive_data.txt" 2>/dev/null
  fadd "Sensitive data in logcat" HIGH MEDIUM CWE-532 "A09:2021" "$TRAFFIC_DIR/sensitive_data.txt"
fi

# ---- 7. Cleanup ----
kill $LOGCAT_PID 2>/dev/null || true
clear_proxy

ok "Traffic capture complete -> $TRAFFIC_DIR"
fsnapshot
