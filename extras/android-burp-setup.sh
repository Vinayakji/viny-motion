#!/usr/bin/env bash
# android-burp-setup.sh - permanently route the viny-motion emulator's app traffic
# through Burp with a TRUSTED Burp CA on Android 14/15 (API 34/35).
#
# WHY THIS IS NEEDED
#   On Android 14/15 the system CA store lives in the read-only Conscrypt APEX
#   (/apex/com.android.conscrypt/cacerts), NOT /system. Copying to /system or the
#   user-cert store is ignored by the app (it pins to the APEX store). The CA must
#   be bind-mounted over the APEX path before zygote forks user apps.
#
# HOW (permanent, survives reboot)
#   1. Merge the APEX CAs + Burp CA into a persistent store at /data/misc/cacerts.
#   2. Install /system/etc/viny-ca-mount.sh + /system/etc/init/viny-ca.rc, a
#      oneshot init service (su domain) that bind-mounts the store over the APEX
#      CA path at post-fs-data (before zygote) => every app inherits it.
#   3. Set the global HTTP proxy to Burp.
#
# Usage:
#   ./extras/android-burp-setup.sh [--proxy HOST:PORT] [--ca /path/burp_ca.der] [--reboot]
# Defaults: proxy 192.168.29.19:8081, CA ~/tools/apk_pentest/burp_ca.der
#
# NOTE: requires a `-writable-system` userdebug emulator image.
set -uo pipefail

ANDROID_HOME="${ANDROID_HOME:-$HOME/android-sdk}"
ADB="$ANDROID_HOME/platform-tools/adb"
SERIAL="${VINY_SERIAL:-emulator-5554}"
PROXY="192.168.29.19:8081"
CA="$HOME/tools/apk_pentest/burp_ca.der"
REBOOT=0

while [ $# -gt 0 ]; do
  case "$1" in
    --proxy) PROXY="$2"; shift 2 ;;
    --ca)    CA="$2"; shift 2 ;;
    --reboot) REBOOT=1; shift ;;
    *) echo "unknown arg: $1"; exit 1 ;;
  esac
done

a() { "$ADB" -s "$SERIAL" "$@"; }
[ -f "$CA" ] || { echo "ERROR: CA not found: $CA"; exit 1; }

echo "[*] adb root + remount /system"
a root >/dev/null 2>&1; sleep 2; a wait-for-device
a disable-verity >/dev/null 2>&1 || true
a remount >/dev/null 2>&1 || true

echo "[*] build persistent CA store at /data/misc/cacerts (APEX CAs + Burp CA)"
H=$(openssl x509 -inform DER -in "$CA" -out /tmp/_burp.pem 2>/dev/null; openssl x509 -in /tmp/_burp.pem -subject_hash_old -noout)
[ -n "$H" ] || { echo "ERROR: cannot parse CA"; exit 1; }
cp /tmp/_burp.pem "/tmp/$H.0"
a shell "rm -rf /data/misc/cacerts; mkdir -p /data/misc/cacerts; cp -a /apex/com.android.conscrypt/cacerts/. /data/misc/cacerts/ 2>/dev/null" >/dev/null
a push "/tmp/$H.0" "/data/misc/cacerts/$H.0" >/dev/null 2>&1
a shell "chmod 755 /data/misc/cacerts; chmod 644 /data/misc/cacerts/*; chcon -R u:object_r:system_security_cacerts_file:s0 /data/misc/cacerts" >/dev/null

echo "[*] write /system/etc/viny-ca-mount.sh"
cat > /tmp/viny-ca-mount.sh <<'EOS'
#!/system/bin/sh
STORE=/data/misc/cacerts
[ -d "$STORE" ] || exit 0
chcon -R u:object_r:system_security_cacerts_file:s0 "$STORE" 2>/dev/null
chmod 755 "$STORE" 2>/dev/null; chmod 644 "$STORE"/* 2>/dev/null
mount -o bind "$STORE" /apex/com.android.conscrypt/cacerts 2>/dev/null
exit 0
EOS

echo "[*] write /system/etc/init/viny-ca.rc"
cat > /tmp/viny-ca.rc <<'EOS'
# viny-motion: permanently trust the Burp CA on Android 14/15 (APEX CA store).
# oneshot root service in su domain, runs at post-fs-data before zygote forks.
service viny-ca /system/bin/sh /system/etc/viny-ca-mount.sh
    class core
    user root
    group root
    seclabel u:r:su:s0
    oneshot
    disabled

on post-fs-data
    start viny-ca
EOS

a push /tmp/viny-ca-mount.sh /system/etc/viny-ca-mount.sh >/dev/null 2>&1
a push /tmp/viny-ca.rc /system/etc/init/viny-ca.rc >/dev/null 2>&1
a shell "chmod 755 /system/etc/viny-ca-mount.sh; chmod 644 /system/etc/init/viny-ca.rc; chcon u:object_r:system_file:s0 /system/etc/viny-ca-mount.sh /system/etc/init/viny-ca.rc" >/dev/null

echo "[*] set proxy -> $PROXY"
a shell settings put global http_proxy "$PROXY"

echo "[+] permanent CA installed (hash $H). It mounts at every boot via init."
if [ "$REBOOT" = "1" ]; then
  echo "[*] rebooting to verify"; a reboot; sleep 12; a wait-for-device
  for i in $(seq 1 40); do [ "$(a shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] && break; sleep 5; done
  echo "[+] CA after reboot: $(a shell "ls /apex/com.android.conscrypt/cacerts/$H.0 2>/dev/null" | tr -d '\r')"
else
  echo "[*] reboot (or next boot) to activate the boot-time mount."
fi
