#!/usr/bin/env bash
# run_android_pipeline.sh - Android-specific skill-based pipeline

set -uo pipefail
PIPELINE_ROOT="$(cd "$(dirname "$0")" && pwd)"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/skill_dispatcher.sh"
source "$PIPELINE_ROOT/lib/findings.sh"
source "$PIPELINE_ROOT/lib/objection_helpers.sh"

APK_PATH="${1:-}"
[ -z "$APK_PATH" ] && { err "Usage: $0 <apk_path>"; exit 1; }
[ ! -f "$APK_PATH" ] && { err "APK not found: $APK_PATH"; exit 1; }

# ---- PHASE 1: STATIC ANALYSIS ----

run_static_analysis() {
  local apk="$1"
  local run_dir="$RUN_DIR/static"
  mkdir -p "$run_dir"
  
  info "=== PHASE 1: STATIC ANALYSIS ==="
  
  # 1.1 AAPT dump
  info "Running AAPT analysis..."
  aapt dump badging "$apk" > "$run_dir/badging.txt" 2>/dev/null
  aapt dump permissions "$apk" > "$run_dir/permissions.txt" 2>/dev/null
  aapt dump configurations "$apk" > "$run_dir/configurations.txt" 2>/dev/null
  aapt dump xmltree "$apk" AndroidManifest.xml > "$run_dir/manifest_tree.txt" 2>/dev/null
  
  # 1.2 Extract package info
  local package=$(grep "package:" "$run_dir/badging.txt" | head -1 | awk '{print $2}' | sed "s/'//g")
  local version=$(grep "versionName" "$run_dir/badging.txt" | head -1 | awk -F"'" '{print $2}')
  echo "$package" > "$run_dir/package_name.txt"
  echo "$version" > "$run_dir/version.txt"
  info "Package: $package v$version"
  
  # 1.3 Decompile with jadx
  info "Decompiling with jadx..."
  jadx -d "$run_dir/jadx" "$apk" 2>/dev/null
  
  # 1.4 Extract secrets
  info "Extracting secrets..."
  {
    echo "=== API Keys ==="
    grep -rn "API_KEY\|api_key\|apiKey" "$run_dir/jadx" 2>/dev/null | head -20
    echo ""
    echo "=== Secrets ==="
    grep -rn "SECRET\|secret\|Secret" "$run_dir/jadx" 2>/dev/null | grep -v "\.class" | head -20
    echo ""
    echo "=== Tokens ==="
    grep -rn "TOKEN\|token\|Token" "$run_dir/jadx" 2>/dev/null | grep -v "\.class" | head -20
    echo ""
    echo "=== Passwords ==="
    grep -rn "PASSWORD\|password\|Password" "$run_dir/jadx" 2>/dev/null | grep -v "\.class" | head -20
  } > "$run_dir/secrets.txt" 2>/dev/null
  
  # 1.5 Analyze manifest for exported components
  info "Analyzing exported components..."
  {
    echo "=== Exported Activities ==="
    grep -B2 -A5 "exported=\"true\"" "$run_dir/jadx/resources/AndroidManifest.xml" 2>/dev/null | grep -E "activity|intent-filter" | head -20
    
    echo ""
    echo "=== Exported Services ==="
    grep -B2 -A5 "<service" "$run_dir/jadx/resources/AndroidManifest.xml" 2>/dev/null | grep -E "service|intent-filter" | head -20
    
    echo ""
    echo "=== Exported Receivers ==="
    grep -B2 -A5 "<receiver" "$run_dir/jadx/resources/AndroidManifest.xml" 2>/dev/null | grep -E "receiver|intent-filter" | head -20
    
    echo ""
    echo "=== Exported Providers ==="
    grep -B2 -A5 "<provider" "$run_dir/jadx/resources/AndroidManifest.xml" 2>/dev/null | grep -E "provider|exported" | head -20
  } > "$run_dir/exported_components.txt" 2>/dev/null
  
  # 1.6 Check for native libraries
  info "Checking native libraries..."
  find "$run_dir/jadx" -name "*.so" -exec file {} \; > "$run_dir/native_libs.txt" 2>/dev/null
  
  # 1.7 Check for debuggable flag
  info "Checking debuggable flag..."
  grep -i "debuggable" "$run_dir/jadx/resources/AndroidManifest.xml" > "$run_dir/debuggable.txt" 2>/dev/null
  
  info "Static analysis complete"
  
  echo "$run_dir"
}

# ---- PHASE 2: SKILL DISPATCH ----

dispatch_android_skills() {
  local static_dir="$1"
  local skills_json="$RUN_DIR/skills_to_load.json"
  
  info "=== PHASE 2: SKILL DISPATCH ==="
  
  # Initialize skills JSON
  echo '{"skills":[]}' > "$skills_json"
  
  # 2.1 Always load base Android skill
  jq '.skills += [{"name": "android-pentesting-tricks", "priority": 1, "description": "Base Android testing methodology"}]' \
    "$skills_json" > "$skills_json.tmp" && mv "$skills_json.tmp" "$skills_json"
  
  # 2.2 Check for exported components -> intent injection
  if grep -q "exported=\"true\"" "$static_dir/exported_components.txt" 2>/dev/null; then
    jq '.skills += [{"name": "android-pentesting-tricks", "priority": 2, "description": "Exported components found - test intent injection"}]' \
      "$skills_json" > "$skills_json.tmp" && mv "$skills_json.tmp" "$skills_json"
  fi
  
  # 2.3 Check for secrets
  if [ -s "$static_dir/secrets.txt" ] && grep -q "API_KEY\|SECRET\|TOKEN\|PASSWORD" "$static_dir/secrets.txt" 2>/dev/null; then
    jq '.skills += [{"name": "android-pentesting-tricks", "priority": 2, "description": "Secrets found - test hardcoded credentials"}]' \
      "$skills_json" > "$skills_json.tmp" && mv "$skills_json.tmp" "$skills_json"
  fi
  
  # 2.4 Check for debuggable
  if grep -q "debuggable.*true" "$static_dir/debuggable.txt" 2>/dev/null; then
    jq '.skills += [{"name": "android-pentesting-tricks", "priority": 1, "description": "App is debuggable - test runtime manipulation"}]' \
      "$skills_json" > "$skills_json.tmp" && mv "$skills_json.tmp" "$skills_json"
  fi
  
  # 2.5 Check for native libs
  if [ -s "$static_dir/native_libs.txt" ]; then
    jq '.skills += [{"name": "android-pentesting-tricks", "priority": 3, "description": "Native libraries found - test JNI/binary security"}]' \
      "$skills_json" > "$skills_json.tmp" && mv "$skills_json.tmp" "$skills_json"
  fi
  
  # 2.6 Add mobile-specific skills
  jq '.skills += [
    {"name": "mobile-ssl-pinning-bypass", "priority": 2, "description": "SSL pinning bypass testing"},
    {"name": "mobile-dynamic-analysis", "priority": 3, "description": "Dynamic analysis with Frida/Objection"}
  ]' "$skills_json" > "$skills_json.tmp" && mv "$skills_json.tmp" "$skills_json"
  
  # Deduplicate
  jq '.skills |= unique_by(.name) | .skills |= sort_by(.priority)' "$skills_json" > "$skills_json.tmp" && mv "$skills_json.tmp" "$skills_json"
  
  local skill_count=$(jq '.skills | length' "$skills_json")
  info "Skills to load: $skill_count"
  jq -r '.skills[] | "  [\(.priority)] \(.name) - \(.description)"' "$skills_json"
  
  echo "$skills_json"
}

# ---- PHASE 3: DYNAMIC ANALYSIS ----

run_dynamic_analysis() {
  local static_dir="$1"
  local skills_json="$2"
  
  info "=== PHASE 3: DYNAMIC ANALYSIS ==="
  
  local package=$(cat "$static_dir/package_name.txt")
  
  # 3.1 Setup viny-motion device
  info "Checking viny-motion device..."
  adb devices | grep -q "emulator\|device" || { warn "No device connected"; return 1; }
  
  # 3.2 Install APK
  info "Installing APK..."
  adb install -r "$APK_PATH" 2>/dev/null
  
  # 3.3 Launch app
  info "Launching app..."
  adb shell monkey -p "$package" -c android.intent.category.LAUNCHER 1 2>/dev/null
  
  # 3.4 Execute skills
  jq -r '.skills[] | .name' "$skills_json" | while read -r skill_name; do
    info "Executing skill: $skill_name"
    
    case "$skill_name" in
      android-pentesting-tricks)
        info "  Running Android security tests..."
        # Test exported components
        # Test shared preferences
        # Test SQLite databases
        # Test root detection
        ;;
      mobile-ssl-pinning-bypass)
        info "  Testing SSL pinning bypass..."
        # Generate and deploy Frida script
        ;;
      mobile-dynamic-analysis)
        info "  Running dynamic analysis..."
        # Setup proxy
        # Capture traffic
        # Test for vulnerabilities
        ;;
    esac
  done
}

# ---- PHASE 4: FINDINGS ----

generate_findings() {
  info "=== PHASE 4: FINDINGS ==="
  
  # Generate findings report
  fsnapshot
  
  # Export findings
  fexport json "$RUN_DIR/findings.json"
  fexport markdown "$RUN_DIR/findings.md"
  
  info "Findings saved to: $RUN_DIR"
}

# ---- MAIN EXECUTION ----

info "=== ANDROID SECURITY TESTING PIPELINE ==="
info "APK: $APK_PATH"

static_dir=$(run_static_analysis "$APK_PATH")
skills_json=$(dispatch_android_skills "$static_dir")
run_dynamic_analysis "$static_dir" "$skills_json"
generate_findings

info "=== PIPELINE COMPLETE ==="
