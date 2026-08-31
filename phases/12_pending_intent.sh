#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 12_pending_intent.sh - PendingIntent abuse + Intent redirection deep test
PROFILE_PHASE="12_pending_intent"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
[ -z "$PKG" ] && { err "No package_name"; exit 1; }

cd "$RUN_DIR" || exit 1
PENDING_DIR="$RUN_DIR/pending_intent"
mkdir -p "$PENDING_DIR"

# ============================================================
# A. Static Analysis — Find PendingIntent Usage
# ============================================================
info "=== A. Static PendingIntent Analysis ==="

JADX_DIR="$RUN_DIR/static/jadx"
if [ -d "$JADX_DIR" ]; then
  # Find PendingIntent creation
  grep -rn "PendingIntent.getActivity\|PendingIntent.getService\|PendingIntent.getBroadcast\|PendingIntent.getForegroundService" "$JADX_DIR/sources/" 2>/dev/null > "$PENDING_DIR/creation.txt" || true
  PI_COUNT=$(wc -l < "$PENDING_DIR/creation.txt" 2>/dev/null || echo 0)
  info "PendingIntent creation points: $PI_COUNT"

  # Find FLAG_MUTABLE (insecure)
  grep -rn "FLAG_MUTABLE" "$JADX_DIR/sources/" 2>/dev/null > "$PENDING_DIR/flag_mutable.txt" || true
  MUTABLE_COUNT=$(wc -l < "$PENDING_DIR/flag_mutable.txt" 2>/dev/null || echo 0)
  [ "$MUTABLE_COUNT" -gt 0 ] && fadd "$MUTABLE_COUNT FLAG_MUTABLE PendingIntents (insecure)" HIGH HIGH CWE-668 "A04:2021" "$PENDING_DIR/flag_mutable.txt"

  # Find FLAG_IMMUTABLE (secure)
  grep -rn "FLAG_IMMUTABLE" "$JADX_DIR/sources/" 2>/dev/null > "$PENDING_DIR/flag_immutable.txt" || true

  # Find intent redirection patterns
  grep -rn "getIntent\(\)\.getParcelableExtra\|getIntent\(\).get.*Extra\|Intent.parseUri\|Intent.getIntent" "$JADX_DIR/sources/" 2>/dev/null > "$PENDING_DIR/intent_redirect.txt" || true
  REDIRECT_COUNT=$(wc -l < "$PENDING_DIR/intent_redirect.txt" 2>/dev/null || echo 0)
  [ "$REDIRECT_COUNT" -gt 0 ] && fadd "$REDIRECT_COUNT potential intent redirections" HIGH HIGH CWE-610 "A01:2021" "$PENDING_DIR/intent_redirect.txt"

  # Find startActivity after getIntent
  grep -rn -A5 "getIntent\(\)" "$JADX_DIR/sources/" 2>/dev/null | grep -B1 "startActivity\|startService\|sendBroadcast" > "$PENDING_DIR/intent_flow.txt" || true

  # Find startActivityForResult
  grep -rn "startActivityForResult" "$JADX_DIR/sources/" 2>/dev/null > "$PENDING_DIR/activity_for_result.txt" || true

  # Find setTargetPackage / setPackage on PendingIntents
  grep -rn "setTargetPackage\|setPackage" "$JADX_DIR/sources/" 2>/dev/null > "$PENDING_DIR/package_targeting.txt" || true

  # Find exported components that create PendingIntents
  grep -rn "PendingIntent" "$JADX_DIR/sources/" 2>/dev/null | grep -B2 -A2 "exported\|intent-filter" > "$PENDING_DIR/exported_pi.txt" || true
fi

# ============================================================
# B. Dynamic Analysis — PendingIntent Hijacking
# ============================================================
info "=== B. Dynamic PendingIntent Testing ==="

# Test 1: Send intents to exported activities with null PendingIntents
info "Testing exported activities with crafted PendingIntents..."

# Get exported activities
EXPORTED=$(adb shell "dumpsys package $PKG" 2>/dev/null | grep -A2 "Activity" | grep -oP '\S+Activity\S*' | sort -u || true)

for act in $EXPORTED; do
  # Try to trigger with FLAG_MUTABLE PendingIntent
  adb shell "am start -n $PKG/$act --ei android.intent.extra.FLAG 268435456" 2>/dev/null || true
  sleep 1

  # Try with parcelable extra
  adb shell "am start -n $PKG/$act --ez require_auth false --ez is_admin true" 2>/dev/null || true
  sleep 1
done

# Test 2: Broadcast PendingIntents
info "Testing broadcast PendingIntents..."
adb shell "am broadcast -a android.intent.action.BOOT_COMPLETED -n $PKG/.BootReceiver" 2>/dev/null || true
adb shell "am broadcast -a android.intent.action.PACKAGE_REPLACED -n $PKG/.PackageReceiver --es android.intent.extra.UID 1000" 2>/dev/null || true

# Test 3: Service PendingIntents
info "Testing service PendingIntents..."
SERVICES=$(adb shell "dumpsys package $PKG" 2>/dev/null | grep -A2 "Service" | grep -oP '\S+Service\S*' | sort -u || true)
for svc in $SERVICES; do
  adb shell "am startservice -n $PKG/$svc --ei priority 999 --ez force true" 2>/dev/null || true
  sleep 1
done

# ============================================================
# C. Intent Redirection Exploitation
# ============================================================
info "=== C. Intent Redirection ==="

if [ -s "$PENDING_DIR/intent_redirect.txt" ]; then
  # Extract class names with intent redirection
  grep -oP '\w+\.\w+(?=\.)' "$PENDING_DIR/intent_redirect.txt" | sort -u > "$PENDING_DIR/redirect_classes.txt" 2>/dev/null || true

  while IFS= read -r cls; do
    info "Testing intent redirection in: $cls"

    # Try to redirect to a different component
    adb shell "am start -n $PKG/$cls --es android.intent.extra.INTENT 'component:com.android.settings/.Settings'" 2>/dev/null || true
    sleep 1

    # Try to redirect to settings
    adb shell "am start -n $PKG/$cls --es android.intent.extra.INTENT 'action:android.settings.SETTINGS'" 2>/dev/null || true
    sleep 1

    # Try with URI
    adb shell "am start -n $PKG/$cls --es android.intent.extra.INTENT 'uri:file:///data/data/com.android.settings/shared_prefs'" 2>/dev/null || true
    sleep 1
  done < "$PENDING_DIR/redirect_classes.txt"
fi

# ============================================================
# D. FLAG_MUTABLE Analysis
# ============================================================
info "=== D. FLAG_MUTABLE Analysis ==="

if [ -s "$PENDING_DIR/flag_mutable.txt" ]; then
  warn "FLAG_MUTABLE found - PendingIntents can be modified by other apps"
  fadd "FLAG_MUTABLE PendingIntents allow modification" HIGH HIGH CWE-668 "A04:2021" "$PENDING_DIR/flag_mutable.txt"

  # Check if FLAG_IMMUTABLE is used as well
  MUTABLE_ONLY=$((PI_COUNT - $(wc -l < "$PENDING_DIR/flag_immutable.txt" 2>/dev/null || echo 0)))
  if [ "$MUTABLE_ONLY" -gt 0 ]; then
    warn "$MUTABLE_ONLY PendingIntents are mutable without immutable alternative"
  fi
fi

# ============================================================
# E. Content Provider Intent Injection
# ============================================================
info "=== E. Provider → Intent Injection ==="

# Test if content providers can trigger intents
PROVIDERS=$(adb shell "dumpsys package $PKG" 2>/dev/null | grep -A2 "Provider" | grep -oP '\S+Provider\S*' | sort -u || true)

for prov in $PROVIDERS; do
  adb shell "content query --uri content://$PKG.$prov/" 2>/dev/null > "$PENDING_DIR/provider_query_$prov.txt" || true

  # Check if provider result contains intent data
  grep -qi "intent\|startActivity\|broadcast\|component" "$PENDING_DIR/provider_query_$prov.txt" 2>/dev/null && \
    warn "Provider $prov may trigger intents"
done

ok "PendingIntent testing complete -> $PENDING_DIR"
fsnapshot
