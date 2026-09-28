# Rooting the Play Store Emulator Image + Burp Setup

The custom emulator runs on the AOSP/QEMU emulator (Genymotion-independent). This doc covers
rooting the **Play Store** image and configuring Burp interception.

## Two AVDs (recommended)

| AVD | Image | adb root | Use for |
|-----|-------|----------|---------|
| `viny-motion` | `google_apis` (userdebug) | ✅ yes | Burp + Frida + objection + drozer (default) |
| `viny-motion-play` | `google_apis_playstore` (user/production) | ❌ no | apps requiring Google Play Store |

> **Why no `adb root` on Play Store images:** they are **production (`user`) builds**.
> Google disables `adb root` on Play-certified images. Only `google_apis` (userdebug) allows it.

## Option A — Root `google_apis` (userdebug) — already works

```bash
./extras/viny-motion-emu.sh start
./extras/viny-motion-emu.sh root        # adb root (uid 0)
```

## Option B — Root the Play Store image with Magisk (ramdisk patch)

The Play Store image can be rooted by replacing its ramdisk with a Magisk-patched one.

### In-app method (official, supported)

```bash
# 1. On host
curl -L -o magisk.apk https://github.com/topjohnwu/Magisk/releases/download/v30.7/Magisk-v30.7.apk

# 2. Boot the playstore AVD, install Magisk, push the stock ramdisk
~/android-sdk/platform-tools/adb -s emulator-5554 install -r magisk.apk
~/android-sdk/platform-tools/adb -s emulator-5554 \
  push ~/android-sdk/system-images/android-30/google_apis_playstore/x86_64/ramdisk.img /sdcard/ramdisk.img

# 3. In the Magisk app: Install → "Select and Patch a File" → pick /sdcard/ramdisk.img
#    Patched file is saved to /sdcard/Download/magisk_patched-*.img

# 4. Pull it and boot with it
~/android-sdk/platform-tools/adb -s emulator-5554 pull /sdcard/Download/magisk_patched-*.img ./patched.img
~/android-sdk/emulator/emulator -avd viny-motion-play -ramdisk ./patched.img ... &
```

### Host-side method (magiskboot, no UI)

```bash
unzip -q -o magisk.apk "lib/x86_64/*" -d magiskx
cd magiskx && cp lib/x86_64/libmagiskboot.so magiskboot && chmod +x magiskboot
cp lib/x86_64/libmagiskinit.so magiskinit && chmod +x magiskinit
cp lib/x86_64/libmagisk.so magisk && chmod +x magisk
xz -9 -c magisk > magisk.xz

mkdir raw && cd raw
gzip -dc ../ramdisk.img > ramdisk.cpio   # stock ramdisk from the image dir
../magiskboot cpio ramdisk.cpio \
  "add 0750 init magiskinit" \
  "mkdir 0750 overlay.d" \
  "mkdir 0750 overlay.d/sbin" \
  "add 0644 overlay.d/sbin/magisk.xz magisk.xz" \
  "patch"
gzip -9c ramdisk.cpio > ramdisk-magisk.img
# Boot with: emulator -avd viny-motion-play -ramdisk ramdisk-magisk.img ...
```

> The stock ramdisk is never modified — boot-test the patched one; revert is just relaunching
> without `-ramdisk`.

## Burp interception on the rooted emulator

```bash
# Convert Burp CA (Burp → Proxy → Options → Export CA certificate → DER)
openssl x509 -inform DER -in burp_ca.der -out /tmp/burp-ca.pem
HASH=$(openssl x509 -inform PEM -subject_hash_old -in /tmp/burp-ca.pem)

# Install as a USER cert via root (debug apps trust user CAs; no /system remount needed)
~/android-sdk/platform-tools/adb -s emulator-5554 root
~/android-sdk/platform-tools/adb -s emulator-5554 shell mkdir -p /data/misc/user/0/cacerts-added
~/android-sdk/platform-tools/adb -s emulator-5554 push /tmp/burp-ca.pem /data/misc/user/0/cacerts-added/$HASH.0
~/android-sdk/platform-tools/adb -s emulator-5554 shell chmod 644 /data/misc/user/0/cacerts-added/$HASH.0

# Point the emulator at Burp on the host (10.0.2.2 = host loopback from inside the emulator)
./extras/viny-motion-emu.sh proxy 10.0.2.2:8080
```

For apps that must trust a **system** CA (non-debug), boot with `-writable-system`, then:

```bash
~/android-sdk/platform-tools/adb -s emulator-5554 root
~/android-sdk/platform-tools/adb -s emulator-5554 remount
~/android-sdk/platform-tools/adb -s emulator-5554 push /tmp/burp-ca.pem /system/etc/security/cacerts/$HASH.0
~/android-sdk/platform-tools/adb -s emulator-5554 shell "chmod 644 /system/etc/security/cacerts/$HASH.0 && chcon u:object_r:system_file:s0 /system/etc/security/cacerts/$HASH.0"
~/android-sdk/platform-tools/adb -s emulator-5554 reboot
```