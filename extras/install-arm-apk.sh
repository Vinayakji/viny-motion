#!/usr/bin/env bash
# install-arm-apk.sh - install an ARM-only APK on the x86_64 viny-motion emulator.
#
# The API 35 google_apis x86_64 image ships libndk_translation, so arm64-v8a /
# armeabi-v7a APKs install and run on x86_64. Two things still bite:
#   1. React Native's SoLoader probes  base.apk!/lib/x86_64  (process ABI) while
#      the APK only ships lib/arm64-v8a. With extractNativeLibs=false the libs
#      live only inside the APK, so loading fails ("couldn't find DSO").
#   2. The APK must be installed with the arm64 ABI recorded.
# This script installs the APK, then (when extractNativeLibs=false) extracts the
# arm64 .so files into the app's /data/app/.../lib/arm64 dir so SoLoader finds
# them, and launches the app.
#
# Usage: install-arm-apk.sh <apk> [package-name]
# Requires: adb root on a userdebug image (API 35 google_apis x86_64).
set -uo pipefail

ANDROID_HOME="${ANDROID_HOME:-$HOME/android-sdk}"
ADB="$ANDROID_HOME/platform-tools/adb"
SERIAL="${VINY_SERIAL:-emulator-5554}"
APK="${1:?usage: install-arm-apk.sh <apk> [package]}"
PKG="${2:-}"

a() { "$ADB" -s "$SERIAL" "$@"; }

[ -f "$APK" ] || { echo "ERROR: APK not found: $APK"; exit 1; }

# --- 1. translation present? -------------------------------------------------
bridge=$(a shell getprop ro.dalvik.vm.native.bridge 2>/dev/null | tr -d '\r')
abilist=$(a shell getprop ro.product.cpu.abilist 2>/dev/null | tr -d '\r')
echo "[arm] native.bridge=$bridge abilist=$abilist"
case "$abilist" in
  *arm64-v8a*) ;;
  *) echo "ERROR: image has no arm64-v8a translation."
     echo "       Use system-images;android-35;google_apis;x86_64 (bundles libndk_translation)."
     exit 1 ;;
esac

# --- 2. root (needed to write into /data/app) --------------------------------
a root >/dev/null 2>&1; sleep 2; a wait-for-device

# --- 3. resolve package name from the APK ------------------------------------
if [ -z "$PKG" ]; then
  PKG=$(aapt dump badging "$APK" 2>/dev/null | sed -n "s/^package: name='\([^']*\)'.*/\1/p" | head -1)
fi
[ -n "$PKG" ] || { echo "ERROR: could not resolve package name (pass it as arg 2)"; exit 1; }

# --- 4. install --------------------------------------------------------------
echo "[arm] installing $APK ..."
a install -r "$APK" 2>&1 | tail -2

# --- 5. inspect ABI + extraction mode ---------------------------------------
abi=$(a shell dumpsys package "$PKG" 2>/dev/null | grep -m1 primaryCpuAbi | sed 's/.*=//' | tr -d '\r')
extract=$(a shell dumpsys package "$PKG" 2>/dev/null | grep -m1 extractNativeLibs | sed 's/.*=//' | tr -d '\r')
echo "[arm] package=$PKG primaryCpuAbi=$abi extractNativeLibs=$extract"

# map APK ABI dir -> runtime lib dir name
case "$abi" in
  arm64-v8a) libsub=arm64 ;;
  armeabi-v7a|armeabi) libsub=arm ;;
  *) libsub="$abi" ;;
esac

# --- 6. inject arm64 .so when libs are not extracted ------------------------
if [ "$extract" = "false" ]; then
  libdir=$(a shell "ls -d /data/app/*/$PKG*/lib/$libsub 2>/dev/null" | tr -d '\r' | head -1)
  if [ -z "$libdir" ]; then
    echo "[arm] WARN: native lib dir not found for $PKG; skipping injection"
  else
    tmp=$(mktemp -d)
    unzip -o -j "$APK" "lib/$abi/*.so" -d "$tmp" >/dev/null 2>&1
    n=$(ls "$tmp"/*.so 2>/dev/null | wc -l)
    echo "[arm] injecting $n $abi libs -> $libdir"
    a push "$tmp"/. "$libdir/" >/dev/null 2>&1
    uid=$(a shell "stat -c '%u:%g' /data/data/$PKG" 2>/dev/null | tr -d '\r')
    [ -n "$uid" ] || uid=1000
    a shell "chown -R $uid '$libdir'; chmod 755 '$libdir' '$libdir'/* 2>/dev/null; restorecon -R '$libdir' 2>/dev/null || true"
    rm -rf "$tmp"
  fi
else
  echo "[arm] extractNativeLibs=true — libs already on disk, no injection needed"
fi

# --- 7. launch ---------------------------------------------------------------
a shell am force-stop "$PKG" >/dev/null 2>&1
a shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
sleep 3
if a shell pidof "$PKG" >/dev/null 2>&1; then
  echo "[arm] OK: $PKG running (pid $(a shell pidof "$PKG" | tr -d '\r'))"
else
  echo "[arm] WARN: $PKG not running — check: adb logcat -d | grep -i AndroidRuntime"
fi
