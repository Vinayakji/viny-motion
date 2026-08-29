#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 07_deep_links.sh - Deep link and intent injection testing (NEW)
# Tests: URL scheme abuse, intent redirection, exported component abuse
PROFILE_PHASE="07_deep_links"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"
source "$PIPELINE_ROOT/lib/objection_helpers.sh"

PKG="$(tget apk package_name)"

cd "$RUN_DIR" || exit 1
info "Deep link and intent injection testing on $PKG"

DEEP_DIR="$RUN_DIR/deep_links"
mkdir -p "$DEEP_DIR"

# ---- 1. Extract deep links from manifest ----
info "Extracting deep links from manifest..."

if [ -f "$RUN_DIR/manifest.xml" ] || [ -f "$RUN_DIR/apktool/AndroidManifest.xml" ]; then
  MANIFEST="${RUN_DIR}/apktool/AndroidManifest.xml"
  [ -f "$RUN_DIR/manifest.xml" ] && MANIFEST="$RUN_DIR/manifest.xml"
  
  # Extract intent filters with schemes
  grep -A5 -B2 "scheme=" "$MANIFEST" > "$DEEP_DIR/schemes.txt" 2>/dev/null || true
  
  # Extract all deep link patterns
  grep -oP 'android:scheme="[^"]*"' "$MANIFEST" | sort -u > "$DEEP_DIR/schemes_raw.txt" 2>/dev/null || true
  grep -oP 'android:host="[^"]*"' "$MANIFEST" | sort -u > "$DEEP_DIR/hosts.txt" 2>/dev/null || true
  grep -oP 'android:pathPattern="[^"]*"' "$MANIFEST" | sort -u > "$DEEP_DIR/paths.txt" 2>/dev/null || true
  grep -oP 'android:pathPrefix="[^"]*"' "$MANIFEST" | sort -u >> "$DEEP_DIR/paths.txt" 2>/dev/null || true
  grep -oP 'android:path="[^"]*"' "$MANIFEST" | sort -u >> "$DEEP_DIR/paths.txt" 2>/dev/null || true
  
  # Extract app links
  grep -A10 "autoVerify" "$MANIFEST" > "$DEEP_DIR/applinks.txt" 2>/dev/null || true
  
  ok "Deep links extracted"
fi

# ---- 2. Discover schemes via adb ----
info "Discovering schemes via package manager..."

# Query all schemes for the package
adb shell pm query-intent-activities --brief -a android.intent.action.VIEW -t android.intent.category.BROWSABLE "$PKG" > "$DEEP_DIR/intent_activities.txt" 2>/dev/null || true

# Try to list all intent filters
adb shell dumpsys package "$PKG" > "$DEEP_DIR/package_dump.txt" 2>/dev/null || true

# Extract schemes from dumpsys
grep -A3 "scheme:" "$DEEP_DIR/package_dump.txt" > "$DEEP_DIR/dumpsys_schemes.txt" 2>/dev/null || true

# ---- 3. Generate deep link test payloads ----
info "Generating test payloads..."

# Read discovered schemes
SCHEMES=()
if [ -f "$DEEP_DIR/schemes_raw.txt" ]; then
  while IFS= read -r scheme; do
    scheme=$(echo "$scheme" | grep -oP '"[^"]*"' | tr -d '"')
    [ -n "$scheme" ] && SCHEMES+=("$scheme")
  done < "$DEEP_DIR/schemes_raw.txt"
fi

# Default schemes to test if none found
if [ ${#SCHEMES[@]} -eq 0 ]; then
  SCHEMES=("myapp" "app" "deeplink" "url" "callback" "oauth")
fi

# Generate test URLs
cat > "$DEEP_DIR/generate_tests.sh" <<'GENEOF'
#!/usr/bin/env bash
# Generate deep link test cases
DEEP_DIR="$1"
PKG="$2"

# Read schemes
SCHEMES=()
if [ -f "$DEEP_DIR/schemes_raw.txt" ]; then
  while IFS= read -r scheme; do
    scheme=$(echo "$scheme" | grep -oP '"[^"]*"' | tr -d '"')
    [ -n "$scheme" ] && SCHEMES+=("$scheme")
  done < "$DEEP_DIR/schemes_raw.txt"
fi

# Read hosts
HOSTS=()
if [ -f "$DEEP_DIR/hosts.txt" ]; then
  while IFS= read -r host; do
    host=$(echo "$host" | grep -oP '"[^"]*"' | tr -d '"')
    [ -n "$host" ] && HOSTS+=("$host")
  done < "$DEEP_DIR/hosts.txt"
fi

# Generate test cases
for scheme in "${SCHEMES[@]}"; do
  for host in "${HOSTS[@]}" "evil.com" "attacker.com" ""; do
    # Normal test
    echo "${scheme}://${host}/" >> "$DEEP_DIR/test_urls.txt"
    
    # Path traversal
    echo "${scheme}://${host}/../../../etc/passwd" >> "$DEEP_DIR/test_urls.txt"
    echo "${scheme}://${host}/%2e%2e/%2e%2e/etc/passwd" >> "$DEEP_DIR/test_urls.txt"
    
    # Open redirect
    echo "${scheme}://${host}/redirect?url=https://evil.com" >> "$DEEP_DIR/test_urls.txt"
    
    # Parameter injection
    echo "${scheme}://${host}/?admin=true" >> "$DEEP_DIR/test_urls.txt"
    echo "${scheme}://${host}/?role=admin" >> "$DEEP_DIR/test_urls.txt"
    echo "${scheme}://${host}/?debug=1" >> "$DEEP_DIR/test_urls.txt"
    
    # SSRF
    echo "${scheme}://${host}/fetch?url=http://169.254.169.254/latest/meta-data/" >> "$DEEP_DIR/test_urls.txt"
    echo "${scheme}://${host}/proxy?url=http://localhost:8080" >> "$DEEP_DIR/test_urls.txt"
    
    # SQL injection
    echo "${scheme}://${host}/?id=1'" >> "$DEEP_DIR/test_urls.txt"
    echo "${scheme}://${host}/?id=1%20OR%201=1" >> "$DEEP_DIR/test_urls.txt"
    
    # XSS
    echo "${scheme}://${host}/?q=<script>alert(1)</script>" >> "$DEEP_DIR/test_urls.txt"
    echo "${scheme}://${host}/?name=\"><img%20src=x%20onerror=alert(1)>" >> "$DEEP_DIR/test_urls.txt"
  done
done

sort -u "$DEEP_DIR/test_urls.txt" -o "$DEEP_DIR/test_urls.txt"
echo "[*] Generated $(wc -l < "$DEEP_DIR/test_urls.txt") test URLs"
GENEOF
chmod +x "$DEEP_DIR/generate_tests.sh"
bash "$DEEP_DIR/generate_tests.sh" "$DEEP_DIR" "$PKG"

# ---- 4. Test deep links via adb ----
info "Testing deep links..."

cat > "$DEEP_DIR/test_deep_links.sh" <<'TESTEOF'
#!/usr/bin/env bash
# Test deep links via adb
DEEP_DIR="$1"
PKG="$2"

echo "[*] Testing deep links for $PKG"

while IFS= read -r url; do
  [ -z "$url" ] && continue
  
  echo "[*] Testing: $url"
  
  # Capture logcat before
  adb logcat -c 2>/dev/null
  
  # Send deep link
  adb shell am start -a android.intent.action.VIEW -d "\"$url\"" "$PKG" 2>/dev/null
  
  # Wait for response
  sleep 2
  
  # Capture logcat for crashes or sensitive info
  LOGCAT=$(adb logcat -d -t 50 2>/dev/null)
  
  # Check for crashes
  if echo "$LOGCAT" | grep -qi "fatal\|crash\|exception"; then
    echo "[!] CRASH: $url" >> "$DEEP_DIR/crashes.txt"
    echo "$LOGCAT" >> "$DEEP_DIR/crash_logs.txt"
  fi
  
  # Check for sensitive info leakage
  if echo "$LOGCAT" | grep -qi "password\|token\|secret\|key\|auth"; then
    echo "[!] INFO LEAK: $url" >> "$DEEP_DIR/info_leaks.txt"
    echo "$LOGCAT" >> "$DEEP_DIR/leak_logs.txt"
  fi
  
done < "$DEEP_DIR/test_urls.txt"
TESTEOF
chmod +x "$DEEP_DIR/test_deep_links.sh"

# ---- 5. Intent redirection testing ----
info "Testing intent redirection..."

cat > "$DEEP_DIR/test_intent_redirection.sh" <<'INTENTEOF'
#!/usr/bin/env bash
# Test intent redirection vulnerabilities
PKG="$1"

echo "[*] Testing intent redirection for $PKG"

# Get exported activities
EXPORTED=$(adb shell dumpsys package "$PKG" 2>/dev/null | grep -B5 "exported=true" | grep -oP '[a-zA-Z0-9._]+Activity' | sort -u)

for activity in $EXPORTED; do
  echo "[*] Testing activity: $activity"
  
  # Test with malicious intent extra
  adb shell am start -n "$PKG/$activity" \
    --es "redirect_url" "https://evil.com" \
    --ez "admin" "true" \
    --ei "user_id" "1" 2>/dev/null
  
  sleep 1
  
  # Check if redirected
  CURRENT=$(adb shell dumpsys activity activities 2>/dev/null | grep -i "mResumedActivity" | head -1)
  if echo "$CURRENT" | grep -qi "evil\|browser"; then
    echo "[!] OPEN REDIRECT: $activity" >> "$DEEP_DIR/open_redirects.txt"
  fi
done
INTENTEOF
chmod +x "$DEEP_DIR/test_intent_redirection.sh"

# ---- 6. Generate report ----
cat > "$DEEP_DIR/report.md" << EOF
# Deep Link & Intent Injection Report

## Package: $PKG

## Discovered Schemes
$(cat "$DEEP_DIR/schemes_raw.txt" 2>/dev/null || echo "None discovered")

## Discovered Hosts
$(cat "$DEEP_DIR/hosts.txt" 2>/dev/null || echo "None discovered")

## Test URLs Generated
$(wc -l < "$DEEP_DIR/test_urls.txt" 2>/dev/null || echo 0) test cases

## Manual Testing Checklist

### URL Scheme Abuse
- [ ] Test custom URL schemes for injection
- [ ] Test open redirect via deep link
- [ ] Test path traversal
- [ ] Test parameter injection

### Intent Redirection
- [ ] Test exported activities with intent extras
- [ ] Test intent redirection to external apps
- [ ] Test privilege escalation via intent
- [ ] Test data leakage via intent

### App Links
- [ ] Verify app link verification
- [ ] Test path traversal on verified domains
- [ ] Test subdomain takeover potential

### Content Provider Abuse
- [ ] Test content:// URI access
- [ ] Test SQL injection on content providers
- [ ] Test path traversal on file providers

## Scripts
- generate_tests.sh - Generate test URLs
- test_deep_links.sh - Test deep links via adb
- test_intent_redirection.sh - Test intent redirection
EOF

ok "Deep link testing complete -> $DEEP_DIR"
fsnapshot
