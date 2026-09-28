#!/usr/bin/env bash
# setup-custom-emulator.sh - Provision the viny-motion custom emulator on a fresh machine.
# Installs: Android SDK cmdline-tools + platform-tools + emulator + BOTH system images,
# then creates both AVDs:
#   viny-motion       = google_apis        (userdebug -> root, Burp+Frida)  [default]
#   viny-motion-play  = google_apis_playstore (Play Store, no adb root)
# Genymotion-independent. Requires: java (JDK 17+), ~6GB disk, KVM for acceleration.
set -uo pipefail

ANDROID_HOME="${ANDROID_HOME:-$HOME/android-sdk}"
CMDLINE_URL="https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
API="${VINY_API:-30}"
ABI="x86_64"
DEVICE="${VINY_DEVICE:-pixel_5}"
PACKAGES=(
  "platform-tools"
  "emulator"
  "system-images;android-${API};google_apis;${ABI}"
  "system-images;android-${API};google_apis_playstore;${ABI}"
)

ok()   { echo -e "\033[32m[OK]\033[0m $*"; }
warn() { echo -e "\033[33m[WARN]\033[0m $*"; }
fail() { echo -e "\033[31m[FAIL]\033[0m $*"; exit 1; }

[ -x "$(command -v java)" ] || fail "java not found (install JDK 17+)"
[ -e /dev/kvm ] && ok "KVM available (hardware acceleration)" || warn "no /dev/kvm — emulator will be slow (software)"

mkdir -p "$ANDROID_HOME/cmdline-tools"

# ---- 1. cmdline-tools ----
if [ ! -x "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" ]; then
  warn "Installing Android SDK cmdline-tools..."
  TMP=$(mktemp -d)
  curl -fsSL -o "$TMP/cmt.zip" "$CMDLINE_URL" || fail "download failed: $CMDLINE_URL"
  unzip -q -o "$TMP/cmt.zip" -d "$TMP"
  mv "$TMP/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest" || fail "extract failed"
  rm -rf "$TMP"
fi
SDKM="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
AVDM="$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager"
ok "cmdline-tools ready"

# ---- 2. Accept licenses ----
yes | "$SDKM" --licenses >/dev/null 2>&1 || true
ok "licenses accepted"

# ---- 3. Install packages (both system images) ----
"$SDKM" --install "${PACKAGES[@]}" || fail "sdkmanager install failed"
ok "installed: ${PACKAGES[*]}"

# ---- 4. Create both AVDs ----
"$AVDM" delete avd -n viny-motion >/dev/null 2>&1
echo "no" | "$AVDM" create avd -n viny-motion -k "system-images;android-${API};google_apis;${ABI}" --device "$DEVICE" --force >/dev/null 2>&1 \
  && ok "AVD viny-motion (google_apis, rooted) created" || warn "AVD viny-motion create failed"

"$AVDM" delete avd -n viny-motion-play >/dev/null 2>&1
echo "no" | "$AVDM" create avd -n viny-motion-play -k "system-images;android-${API};google_apis_playstore;${ABI}" --device "$DEVICE" --force >/dev/null 2>&1 \
  && ok "AVD viny-motion-play (google_apis_playstore, Play Store) created" || warn "AVD viny-motion-play create failed"

echo
echo "=============================================="
echo "  Setup complete (ANDROID_HOME=$ANDROID_HOME)"
echo "  AVDs: viny-motion, viny-motion-play"
echo "  Start:  ./extras/viny-motion-emu.sh start"
echo "  Root:   ./extras/viny-motion-emu.sh root"
echo "=============================================="