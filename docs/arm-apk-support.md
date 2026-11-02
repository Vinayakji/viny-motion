# ARM-only APKs & keyboard on the x86_64 emulator

The default `viny-motion` images are x86_64. Most APKs ship `x86`/`x86_64` libs,
but some (e.g. React-Native apps) ship **only `arm64-v8a` / `armeabi-v7a`**. This
page covers running those, and fixes the "keyboard not opening" issue.

## 1. Use an image that bundles `libndk_translation`

Google's **`system-images;android-35;google_apis;x86_64`** (Android 15) ships ARM
translation out of the box:

- `/system/lib64/libndk_translation.so`
- `/system/bin/ndk_translation_program_runner_binfmt_misc_arm64`
- `/system/etc/init/ndk_translation.rc`
- `ro.dalvik.vm.native.bridge=libndk_translation.so`

It is `google_apis` (userdebug) so `adb root` works — needed for Burp's CA and
the lib-injection step below.

### Provision it

```bash
export ANDROID_HOME="$HOME/android-sdk"
"$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" \
  --install "system-images;android-35;google_apis;x86_64"
echo no | "$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager" \
  create avd -n viny-motion-api35 \
  -k "system-images;android-35;google_apis;x86_64" -d pixel_6 --force
VINY_AVD=viny-motion-api35 ./extras/viny-motion-emu.sh start
```

The repo's `extras/setup-custom-emulator.sh` also accepts `VINY_API=35` to
provision this image for the standard `viny-motion` / `viny-motion-play` AVDs.

### Verify translation

```bash
adb -s emulator-5554 shell getprop ro.dalvik.vm.native.bridge   # libndk_translation.so
adb -s emulator-5554 shell getprop ro.product.cpu.abilist        # x86_64,arm64-v8a
```

## 2. Install an ARM-only APK

Use the helper:

```bash
./extras/install-arm-apk.sh /path/to/app.apk
# or, if the package name cannot be parsed:
./extras/install-arm-apk.sh /path/to/app.apk com.example.app
```

What it does:

1. Checks `abilist` contains `arm64-v8a` (translation present).
2. `adb root`.
3. `adb install -r` the APK (records `primaryCpuAbi=arm64-v8a`).
4. If `extractNativeLibs=false` (common for modern RN apps), extracts
   `lib/arm64-v8a/*.so` from the APK and pushes them into
   `/data/app/~~.../<pkg>-.../lib/arm64/`, then fixes `chown` + `restorecon`.
5. Force-stops and launches the app.

### Why the injection is needed

React-Native's `SoLoader` builds its search paths from the **process ABI**
(`x86_64` under translation), so it looks in `base.apk!/lib/x86_64`. The APK has
no `x86_64` dir → `couldn't find DSO to load: libreactnative.so`.

When `extractNativeLibs=true` Android unpacks the `.so` files into the app's
`lib/<abi>/` directory at install time and `SoLoader`'s `ApplicationSoSource`
finds them. When `extractNativeLibs=false` that directory stays empty, so we
populate it manually. Re-running `install-arm-apk.sh` (or reinstalling the APK)
is required after any app update because `/data/app/...` is recreated.

## 3. Keyboard not opening

The QEMU emulator always exposes an emulated **`AT Translated Set 2 keyboard`**
(and its touchscreen advertises a `STYLUS` source), so Gboard decides a hardware
keyboard is attached and shows only its toolbar / a floating pill instead of the
soft keyboard. This is not app-specific.

Fix with the driver:

```bash
./extras/viny-motion-emu.sh fix-keyboard
```

That sets `show_ime_with_hard_keyboard 1` (forces the soft IME to render despite
the emulated hardware keyboard) and reselects Gboard. `viny-motion-emu.sh start`
applies the same setting automatically on every boot, so it is permanent.

If Gboard is stuck in a **floating/collapsed toolbar** (a small icon pill on the
left edge), clear its state:

```bash
./extras/viny-motion-emu.sh fix-keyboard --reset
```

That runs `pm clear com.google.android.inputmethod.latin` (Gboard shows a
one-time "Try out your stylus" tutorial — dismiss it with **Cancel**), then
reselects the IME.

Manual fallback, if a keyboard still refuses to appear: tap the text field, tap
the **☰** in Gboard's toolbar, and choose **Show on-screen keyboard** (Alt+K).

Verify the emulated hardware keyboard is the cause:

```bash
adb shell dumpsys input | grep -i "AT Translated Set 2 keyboard"
```

## 4. Burp CA on API 35

`/system` is read-only on API 35 even with `-writable-system`. Bind-mount a
merged CA store instead (survives until reboot):

```bash
adb root
SRC=$(adb shell readlink -f /system/etc/security/cacerts | tr -d '\r')
adb shell "rm -rf /data/local/tmp/cacerts; mkdir -p /data/local/tmp/cacerts; cp -a $SRC/. /data/local/tmp/cacerts/"
# burp_ca.der is the exported Burp CA (DER)
openssl x509 -inform DER -in burp_ca.der -out /tmp/ca.pem
H=$(openssl x509 -in /tmp/ca.pem -subject_hash_old -noout)
cp /tmp/ca.pem /tmp/$H.0
adb push /tmp/$H.0 /data/local/tmp/cacerts/$H.0
adb shell "chmod 644 /data/local/tmp/cacerts/$H.0; restorecon -R /data/local/tmp/cacerts"
adb shell "mount -o bind /data/local/tmp/cacerts /system/etc/security/cacerts"
```

Set the proxy with `./extras/viny-motion-emu.sh proxy 10.0.2.2:8080`
(`10.0.2.2` = host from the AOSP emulator; `10.0.3.2` is the Genymotion alias).
