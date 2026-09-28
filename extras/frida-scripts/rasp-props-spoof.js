/**
 * rasp-props-spoof.js — T5 dual property-API spoofing
 *
 * Android reads props through THREE doors (0x00sec "both doors" lesson):
 *   1. __system_property_get(name, buf)          — classic, 92-byte contract
 *   2. __system_property_read_callback(pi, cb, cookie)  — newer API, most code
 *      uses this; spoofing ONLY #1 leaks the real emulator props
 *   3. __system_property_read(pi, serial, name, value)  — older read API
 *
 * Java Build.MODEL/FINGERPRINT spoofing alone is useless when detectors read
 * natively. /dev/__properties__ is writable pre-start on rooted devices too.
 *
 * Returns clean values for emulator/root fingerprint keys; passes everything else.
 *
 * Usage: frida -U -f <pkg> -l rasp-props-spoof.js
 */
"use strict";

const TAG = "[PROPS-SPOOF]";
function log(m) { console.log(TAG + " " + m); }

// Emulator / root / debug fingerprint keys -> clean (Pixel 7 on stock) values
const SPOOF = {
    "ro.hardware": "oriole",
    "ro.hardware.egl": "mali",
    "ro.product.model": "Pixel 7",
    "ro.product.brand": "google",
    "ro.product.manufacturer": "Google",
    "ro.product.name": "panther",
    "ro.product.device": "panther",
    "ro.product.board": "panther",
    "ro.board.platform": "gs201",
    "ro.build.product": "panther",
    "ro.build.fingerprint": "google/panther/panther:14/UQ1A.240205.002/11220170:user/release-keys",
    "ro.build.tags": "release-keys",
    "ro.build.type": "user",
    "ro.build.display.id": "UQ1A.240205.002",
    "ro.build.description": "panther-user 14 UQ1A.240205.002 11220170 release-keys",
    "ro.build.version.security_patch": "2024-02-05",
    "ro.bootloader": "ripcurrent-14.0",
    "ro.boot.flash.locked": "1",
    "ro.boot.verifiedbootstate": "green",
    "ro.boot.vbmeta.device_state": "locked",
    "ro.debuggable": "0",
    "ro.secure": "1",
    "ro.adb.secure": "1",
    "ro.kernel.qemu": "0",
    "init.svc.adbd": "stopped",
    "ro.kernel.qemu.gles": "0",
    "ro.radio.noril": "0",
    "gsm.version.baseband": "g5123b-118994-230904-B-1061606",
    "ro.boot.hardware": "oriole",
    "ro.serialno": "UNSET",
    "ro.boot.serialno": "UNSET",
    "sys.usb.config": "mtp",
    "sys.usb.state": "mtp",
    "qemu.sf.lcd_density": null,      // key should appear ABSENT on real device
    "ro.kernel.android.qemud": null,
    "init.svc.qemu-props": null,
    "hw.cmode": null,
    "ro.build.characteristics": "default"
};

// Keys whose presence alone = emulator; return null (suppress read result)
const ABSENT_KEYS = Object.keys(SPOOF).filter(function (k) { return SPOOF[k] === null; });

function spoofValue(key, real) {
    if (!(key in SPOOF)) return real;
    const v = SPOOF[key];
    if (v === null) return ""; // caller may treat empty as missing
    return v;
}

function shouldSpoof(key) { return key in SPOOF; }

// ─── Door 1: __system_property_get ───
function hookPropGet() {
    let addr = null;
    ["libc.so"].forEach(function (lib) {
        if (!addr) {
            try { addr = Module.findExportByName(lib, "__system_property_get"); }
            catch (e) { /* next */ }
        }
    });
    if (!addr) { log("__system_property_get not found"); return; }
    try {
        const orig = new NativeFunction(addr, "int", ["pointer", "pointer"]);
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try { this.key = args[0].readCString(); } catch (e) { this.key = null; }
                this.buf = args[1];
            },
            onLeave: function (retval) {
                if (!this.key || !shouldSpoof(this.key)) return;
                const v = spoofValue(this.key, null);
                // contract: caller pre-allocates PROP_VALUE_MAX (92) — never overflow
                try {
                    const clean = (v === "") ? "" : v;
                    if (clean.length < 92) this.buf.writeUtf8String(clean);
                } catch (e) { /* leave real */ }
                log("__system_property_get('" + this.key + "') -> " +
                    (v === null || v === "" ? "<absent>" : v));
            }
        });
        log("door 1 hooked: __system_property_get");
    } catch (e) { log("prop_get: " + e); }
}

// ─── Door 2: __system_property_read_callback (the leaking door) ───
function hookPropReadCallback() {
    let addr = null;
    try { addr = Module.findExportByName("libc.so", "__system_property_read_callback"); }
    catch (e) { /* ignore */ }
    if (!addr) { log("__system_property_read_callback not found (old Android?)"); return; }
    try {
        // void __system_property_read_callback(const prop_info* pi,
        //     void (*callback)(void* cookie, const char* name, const char* value, uint32_t serial),
        //     void* cookie)
        //
        // Strategy: wrap the caller's callback — our wrapper rewrites value/name
        // before forwarding to the ORIGINAL callback. Same lie, this door too.
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.pi = args[0];
                this.origCb = args[1];
                this.cookie = args[2];
                if (this.origCb.isNull()) return;
                const origCb = this.origCb;
                const cookie = this.cookie;
                // Build a replacement callback that filters then forwards
                const wrapper = new NativeCallback(function (ck, namePtr, valuePtr, serial) {
                    let name = null, value = null;
                    try { name = namePtr.isNull() ? null : namePtr.readCString(); } catch (e) { }
                    try { value = valuePtr.isNull() ? null : valuePtr.readCString(); } catch (e) { }
                    if (name && shouldSpoof(name)) {
                        const v = spoofValue(name, value);
                        log("read_callback('" + name + "') -> " +
                            (v === "" ? "<absent>" : v));
                        // Allocate spoofed value string that lives for the call
                        const clean = (v === "") ? "" : v;
                        const buf = Memory.allocUtf8String(clean);
                        const origFn = new NativeFunction(origCb, "void",
                            ["pointer", "pointer", "pointer", "uint32"]);
                        origFn(ck, namePtr, buf, serial);
                        return;
                    }
                    const origFn = new NativeFunction(origCb, "void",
                        ["pointer", "pointer", "pointer", "uint32"]);
                    origFn(ck, namePtr, valuePtr, serial);
                }, "void", ["pointer", "pointer", "pointer", "uint32"]);
                args[1] = wrapper;
            }
        });
        log("door 2 hooked: __system_property_read_callback (wrapper forwards spoofed values)");
    } catch (e) { log("read_callback: " + e); }
}

// ─── Door 3: __system_property_read (older API) ───
function hookPropRead() {
    let addr = null;
    try { addr = Module.findExportByName("libc.so", "__system_property_read"); }
    catch (e) { /* ignore */ }
    if (!addr) return;
    try {
        // int __system_property_read(const prop_info* pi, uint32_t* serial,
        //                            char* name, char* value)
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.nameBuf = args[2];
                this.valueBuf = args[3];
            },
            onLeave: function (retval) {
                try {
                    const name = this.nameBuf.readCString();
                    if (name && shouldSpoof(name)) {
                        const v = spoofValue(name, null);
                        if (v !== null && v.length < 92) this.valueBuf.writeUtf8String(v);
                        log("__system_property_read('" + name + "') -> " +
                            (v === "" ? "<absent>" : v));
                    }
                } catch (e) { /* leave as-is */ }
            }
        });
        log("door 3 hooked: __system_property_read");
    } catch (e) { log("prop_read: " + e); }
}

// ─── Java Build fields (complementary — some checks read Build.* directly) ───
function hookJavaBuild() {
    if (!Java.available) { setTimeout(hookJavaBuild, 500); return; }
    Java.perform(function () {
        const fields = {
            "MODEL": "Pixel 7", "BRAND": "google", "MANUFACTURER": "Google",
            "DEVICE": "panther", "PRODUCT": "panther", "BOARD": "panther",
            "HARDWARE": "oriole", "SERIAL": "UNSET",
            "FINGERPRINT": SPOOF["ro.build.fingerprint"],
            "TYPE": "user", "TAGS": "release-keys"
        };
        Object.keys(fields).forEach(function (f) {
            try {
                const B = Java.use("android.os.Build");
                B[f].value = fields[f];
            } catch (e) { /* field locked on some versions */ }
        });
        try {
            const DISP = Java.use("android.os.Build$VERSION");
            // security patch string lives on Build.VERSION
        } catch (e) { /* optional */ }
        log("java Build fields spoofed (complementary layer)");
    });
}

hookPropGet();
hookPropReadCallback();
hookPropRead();
hookJavaBuild();
log("all three property doors hooked — verify with: adb shell getprop (real) vs app-visible (spoofed)");
