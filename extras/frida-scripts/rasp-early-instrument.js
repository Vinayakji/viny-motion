/**
 * rasp-early-instrument.js — T4 early-instrumentation timing
 *
 * Constructor-time RASP (Promon .init_array, EverSafe, libDexHelper, DexProtector)
 * runs BEFORE normal attach points. Three seams (kanxue/0x00sec/infosecrajesh):
 *
 *   L1: __loader_android_dlopen_ext  — earliest stable linker export; fires for
 *       every library load. On return of a protection lib: packers materialize
 *       JNI_OnLoad + symbols AFTER init_array (libDexHelper) — this is THE window.
 *   L2: ActivityThread.handleBindApplication — before Application.onCreate
 *       (Appdome boots in Application class).
 *   L3: setTimeout 1s/3s — lazy-loaded SDKs after startup.
 *
 * soinfo::call_constructors (mangled _ZN6soinfo15call_constructorsEv) lets you
 * install hooks BEFORE a lib's init_array runs (EverSafe pattern) — attached when
 * the symbol resolves.
 *
 * Usage: frida -U -f <pkg> -l rasp-early-instrument.js   (MUST spawn, not attach)
 */
"use strict";

const TAG = "[EARLY-INSTRUMENT]";
function log(m) { console.log(TAG + " " + m); }

// Known protection libraries (extend per APKiD output)
const RASP_LIBS = [
    "libDexHelper", "libRiskStub", "libbangcle_risk", "libSecShell",
    "libshield", "libdexprotector", "libdpboot", "libalice",
    "libcovault-appsec", "libdxxcuxd", "loader", "libliapp",
    "libtoolChecker", "libsafe-lib", "libantitrace", "libdedge",
    "libever", "libsecure", "libintegrity", "libRASP", "libtalsec",
    "libappdome", "libprotection", "libguard", "libsecexe", "libsecmain"
];

function isRaspLib(name) {
    if (!name) return false;
    const lower = name.toLowerCase();
    return RASP_LIBS.some(function (k) { return lower.indexOf(k.toLowerCase()) !== -1; });
}

// ─── L1: android_dlopen_ext (linker) ───
function hookDlopen() {
    let dlopenAddr = null;
    let dlopenName = null;
    // Prefer loader export (stable across versions)
    const candidates = [
        ["linker", "__loader_android_dlopen_ext"],
        ["linker64", "__loader_android_dlopen_ext"],
        [null, "android_dlopen_ext"],
        ["linker", "__loader_dlopen"],
        ["linker64", "__loader_dlopen"]
    ];
    for (let i = 0; i < candidates.length && !dlopenAddr; i++) {
        try {
            dlopenAddr = Module.findExportByName(candidates[i][0], candidates[i][1]);
            if (dlopenAddr) dlopenName = candidates[i][1];
        } catch (e) { /* next */ }
    }
    if (!dlopenAddr) {
        // last resort: scan linker symbols
        try {
            const syms = Module.enumerateSymbols("linker64");
            for (let i = 0; i < syms.length; i++) {
                if (syms[i].name.indexOf("android_dlopen_ext") !== -1) {
                    dlopenAddr = syms[i].address;
                    dlopenName = syms[i].name;
                    break;
                }
            }
        } catch (e) { /* give up */ }
    }
    if (!dlopenAddr) { log("dlopen symbol not found"); return; }

    log("hooking " + dlopenName + " @ " + dlopenAddr);

    Interceptor.attach(dlopenAddr, {
        onEnter: function (args) {
            try {
                this.path = args[0].isNull() ? null : args[0].readCString();
            } catch (e) { this.path = null; }
            this.isTarget = isRaspLib(this.path);
            if (this.isTarget) log("LOADING protection lib: " + this.path);
        },
        onLeave: function (retval) {
            if (!this.isTarget || retval.isNull()) return;
            // === THE WINDOW ===
            // init_array already ran; symbol table swapped; JNI_OnLoad not yet called.
            // libDexHelper: JNI_OnLoad "appears" only now — locate and stage hooks.
            const mod = Process.findModuleByName(this.path.split("/").pop());
            if (mod) {
                log("window OPEN: " + mod.name + " base=" + mod.base + " size=0x" +
                    mod.size.toString(16));
                try {
                    const jni = Module.findExportByName(mod.name, "JNI_OnLoad");
                    if (jni) {
                        log("JNI_OnLoad resolved at " + jni + " (was NULL before return!)");
                        // Attach deferred surgical hooks HERE (see kanxue-292197):
                        // Interceptor.attach(jni, { onEnter/onLeave ... })
                    } else {
                        log("JNI_OnLoad not exported — enumerate symbols for RegisterNatives");
                    }
                } catch (e) { log("symbol probe: " + e); }
                // Custom per-target hook installation point
                installTargetHooks(mod);
            }
        }
    });
    log("dlopen timing seam active");
}

// ─── soinfo::call_constructors — BEFORE init_array (EverSafe pattern) ───
function hookConstructors() {
    const mangled = "_ZN6soinfo15call_constructorsEv";
    let addr = null;
    ["linker64", "linker"].forEach(function (lname) {
        if (addr) return;
        try {
            addr = Module.findExportByName(lname, mangled);
        } catch (e) { /* next */ }
    });
    if (!addr) {
        // try enumerate (visibility varies by Android version)
        try {
            const syms = Module.enumerateSymbols("linker64");
            for (let i = 0; i < syms.length; i++) {
                if (syms[i].name.indexOf("call_constructors") !== -1) {
                    addr = syms[i].address;
                    log("found via symbol scan: " + syms[i].name);
                    break;
                }
            }
        } catch (e) { /* give up */ }
    }
    if (!addr) { log("soinfo::call_constructors not resolvable (version-dependent) — dlopen seam still active"); return; }

    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                // Fires per-library right before its init_array. Check if any known
                // RASP lib is mapped and arm hooks NOW (before constructors run).
                const mods = Process.enumerateModules();
                for (let i = 0; i < mods.length; i++) {
                    if (isRaspLib(mods[i].name) && !mods[i]._armed) {
                        try { mods[i]._armed = true; } catch (e) { /* frozen obj ok */ }
                        log("ARMING before init_array: " + mods[i].name +
                            " (install libc/syscall hooks in this window)");
                        installPreConstructorHooks(mods[i]);
                    }
                }
            }
        });
        log("call_constructors seam active");
    } catch (e) { log("call_constructors: " + e); }
}

// ─── L2: ActivityThread.handleBindApplication (pre-Application.onCreate) ───
function hookBindApplication() {
    if (!Java.available) { setTimeout(hookBindApplication, 500); return; }
    Java.perform(function () {
        try {
            const AT = Java.use("android.app.ActivityThread");
            const m = AT.handleBindApplication;
            if (m) {
                m.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        const r = ov.apply(this, arguments);
                        log("handleBindApplication passed — installing L2 java hooks");
                        installJavaHooks();
                        return r;
                    };
                });
                log("L2 seam active (handleBindApplication)");
            }
        } catch (e) { log("L2: " + e); }
    });
}

// ─── L3: lazy SDK retries ───
function lazyRetries() {
    [1000, 3000].forEach(function (ms) {
        setTimeout(function () {
            if (Java.available) {
                Java.perform(function () {
                    installJavaHooks();
                    log("L3 retry @" + ms + "ms");
                });
            }
        }, ms);
    });
}

// ===== CUSTOMIZATION POINTS (fill per target after APKiD + jadx) =====
function installTargetHooks(mod) {
    // e.g. libDexHelper: hook sub_F490 DEX-open entry to dump decrypted DEX;
    //       patch anti-debug crash fn to empty (sub_11C64 pattern)
    log("installTargetHooks(" + mod.name + ") — add target-specific offsets here");
}

function installPreConstructorHooks(mod) {
    // e.g. interpose libc fopen/kill for THIS lib before its checks run
    log("installPreConstructorHooks(" + mod.name + ") — add pre-init interposes here");
}

var javaHooksInstalled = false;
function installJavaHooks() {
    if (javaHooksInstalled || !Java.available) return;
    javaHooksInstalled = true;
    try {
        // L2 catch-all: System.loadLibrary visibility
        const S = Java.use("java.lang.System");
        const origLoad = S.loadLibrary.overload("java.lang.String");
        origLoad.implementation = function (name) {
            if (isRaspLib("lib" + name) || isRaspLib(name)) {
                log("System.loadLibrary('" + name + "') — RASP lib loading");
            }
            return origLoad.call(S, name);
        };
        log("L2 java hooks installed");
    } catch (e) { log("java hooks: " + e); }
}

// ===== RUN (spawn mode required) =====
hookDlopen();
hookConstructors();
hookBindApplication();
lazyRetries();
log("early-instrument active — run with frida -f (spawn), attach misses constructor window");
