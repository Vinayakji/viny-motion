#!/usr/bin/env bash
# viny-motion-emu.sh - Custom Android emulator driver (Genymotion-independent).
# Boots the AOSP/QEMU emulator headless with KVM, drives it via adb.
# Replaces every Genymotion player/gmtool operation used by the pipeline.
#
# Usage:
#   viny-motion-emu.sh start              # boot AVD headless, wait for boot
#   viny-motion-emu.sh stop               # shutdown emulator
#   viny-motion-emu.sh status             # device + boot state
#   viny-motion-emu.sh adb <args...>      # run adb against the emulator
#   viny-motion-emu.sh screenshot <path>  # capture screen to PNG
#   viny-motion-emu.sh snap save <name>   # save snapshot
#   viny-motion-emu.sh snap load <name>   # restore snapshot
#   viny-motion-emu.sh install <apk>      # install an APK
#   viny-motion-emu.sh proxy <h:p>        # set global HTTP proxy (e.g. Burp)
#   viny-motion-emu.sh unproxy            # clear global HTTP proxy
#   viny-motion-emu.sh info               # device model / android version / root
#   viny-motion-emu.sh root               # adb root (userdebug image)
set -uo pipefail

ANDROID_HOME="${ANDROID_HOME:-$HOME/android-sdk}"
EMU="$ANDROID_HOME/emulator/emulator"
ADB="$ANDROID_HOME/platform-tools/adb"
AVD_NAME="${VINY_AVD:-viny-motion}"
SERIAL="${VINY_SERIAL:-emulator-5554}"
BOOT_TIMEOUT="${VINY_BOOT_TIMEOUT:-180}"

[ -x "$EMU" ] || { echo "ERROR: emulator not found at $EMU"; exit 1; }
[ -x "$ADB" ] || { echo "ERROR: adb not found at $ADB"; exit 1; }

a() { "$ADB" -s "$SERIAL" "$@"; }

wait_boot() {
  echo "[viny-motion] waiting for boot (up to ${BOOT_TIMEOUT}s)..."
  for i in $(seq 1 $((BOOT_TIMEOUT / 5))); do
    b=$(a shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
    [ "$b" = "1" ] && { echo "[viny-motion] BOOTED after ~$((i * 5))s"; return 0; }
    sleep 5
  done
  echo "[viny-motion] ERROR: boot timeout"
  return 1
}

cmd="${1:-status}"
shift || true

case "$cmd" in
  start)
    if a get-state >/dev/null 2>&1; then
      echo "[viny-motion] already running ($SERIAL)"
      exit 0
    fi
    nohup "$EMU" -avd "$AVD_NAME" -no-window -no-audio -no-boot-anim \
      -gpu swiftshader_indirect -no-snapshot \
      -camera-back none -camera-front none \
      > /tmp/viny-motion-emu.log 2>&1 &
    echo "[viny-motion] emulator launching (pid $!)"
    for i in $(seq 1 24); do
      a get-state >/dev/null 2>&1 && break
      sleep 5
    done
    wait_boot
    ;;
  stop)
    a emu kill 2>/dev/null || pkill -f "$EMU.*$AVD_NAME" 2>/dev/null
    echo "[viny-motion] stop requested"
    ;;
  status)
    if a get-state >/dev/null 2>&1; then
      echo "[viny-motion] device: $SERIAL ($(a shell getprop ro.product.model 2>/dev/null | tr -d '\r'))"
      echo "[viny-motion] boot:   $(a shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')"
    else
      echo "[viny-motion] device: NOT RUNNING"
      exit 1
    fi
    ;;
  adb)
    a "$@"
    ;;
  screenshot)
    [ -n "${1:-}" ] || { echo "usage: viny-motion-emu.sh screenshot <path>"; exit 1; }
    a exec-out screencap -p > "$1"
    echo "[viny-motion] screenshot saved: $1 ($(stat -c%s "$1" 2>/dev/null) bytes)"
    ;;
  snap)
    case "${1:-}" in
      save) a emu avd snapshot save "${2:?name required}"; echo "[viny-motion] snapshot saved: $2" ;;
      load) a emu avd snapshot load "${2:?name required}"; echo "[viny-motion] snapshot loaded: $2" ;;
      *) echo "usage: viny-motion-emu.sh snap save|load <name>"; exit 1 ;;
    esac
    ;;
  install)
    [ -n "${1:-}" ] || { echo "usage: viny-motion-emu.sh install <apk>"; exit 1; }
    a install -r "$1"
    ;;
  proxy)
    [ -n "${1:-}" ] || { echo "usage: viny-motion-emu.sh proxy <host:port>"; exit 1; }
    a shell settings put global http_proxy "$1"
    echo "[viny-motion] proxy set: $1"
    ;;
  unproxy)
    a shell settings put global http_proxy :0
    echo "[viny-motion] proxy cleared"
    ;;
  root)
    a root && sleep 3 && echo "[viny-motion] adbd restarted as root"
    ;;
  info)
    echo "model:      $(a shell getprop ro.product.model 2>/dev/null | tr -d '\r')"
    echo "android:    $(a shell getprop ro.build.version.release 2>/dev/null | tr -d '\r') (SDK $(a shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r'))"
    echo "abi:        $(a shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')"
    echo "root:       $(a shell id 2>/dev/null | head -c 60 | tr -d '\r')"
    ;;
  *)
    echo "usage: viny-motion-emu.sh start|stop|status|adb|screenshot|snap|install|proxy|unproxy|root|info"
    exit 1
    ;;
esac