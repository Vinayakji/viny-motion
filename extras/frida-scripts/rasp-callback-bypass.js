/**
 * rasp-callback-bypass.js — T1 callback/verdict suppression
 *
 * freeRASP/Talsec: detections arrive via BroadcastReceiver with action TALSEC_INFO;
 * hooking Intent.getStringExtra and returning "" when action matches blinds ALL
 * detectors through one point that survives SDK obfuscation (regne.me technique).
 *
 * Appdome: native threat query String[]->boolean[] — return all-false.
 *
 * Pair with rasp-enforcement-cut.js for exitProcess(0)/killProcess backstops.
 *
 * Usage: frida -U -f <pkg> -l rasp-callback-bypass.js
 */
"use strict";

const TAG = "[CALLBACK-BYPASS]";
function log(m) { console.log(TAG + " " + m); }

const RASP_ACTIONS = [
    "TALSEC_INFO",          // freeRASP / Talsec
    "TALSEC", "APPDOME",    // common vendor actions
    "com.talsec.*", "com.appdome.*"
];

function isRaspAction(action) {
    if (!action) return false;
    for (let i = 0; i < RASP_ACTIONS.length; i++) {
        const a = RASP_ACTIONS[i];
        if (a.endsWith("*")) {
            if (action.indexOf(a.slice(0, -1)) === 0) return true;
        } else if (action === a) return true;
    }
    return false;
}

if (!Java.available) {
    console.log(TAG + " Java unavailable — run with spawn");
} else {
    Java.perform(function () {
        // ── 1. Intent.getStringExtra — blank RASP detection extras ──
        try {
            const Intent = Java.use("android.content.Intent");
            Intent.getStringExtra.overload("java.lang.String").implementation = function (key) {
                const val = this.getStringExtra(key);
                const action = this.getAction();
                if (isRaspAction(action)) {
                    log("BLANKED extra '" + key + "' on action '" + action + "' " +
                        "(was: " + String(val).substring(0, 60) + ")");
                    return "";
                }
                return val;
            };
            log("Intent.getStringExtra hooked (TALSEC_INFO pattern)");
        } catch (e) { log("getStringExtra: " + e); }

        // ── 2. getIntent extras on Activity (same pattern, different entry) ──
        try {
            const Activity = Java.use("android.app.Activity");
            Activity.getIntent.implementation = function () {
                const intent = this.getIntent();
                return intent;
            };
            // getIntent itself is not filtered — getStringExtra above covers reads
        } catch (e) { /* optional */ }

        // ── 3. freeRASP threat listener callbacks — swallow directly if present ──
        const listenerInterfaces = [
            "com.aheaditec.talsec.threat.ThreatListener",
            "free.rasp.ThreatListener"
        ];
        listenerInterfaces.forEach(function (iface) {
            try {
                const L = Java.use(iface);
                // Hook every method (onRootDetected, onHookDetected, ...)
                L.class.getDeclaredMethods().forEach(function (m) {
                    try {
                        const name = m.getName();
                        if (name.indexOf("on") === 0 && name.indexOf("Detected") > -1) {
                            const impl = L[name];
                            if (impl) {
                                impl.overloads.forEach(function (ov) {
                                    ov.implementation = function () {
                                        log("SWALLOWED " + iface + "." + name);
                                    };
                                });
                                log("hooked " + iface + "." + name);
                            }
                        }
                    } catch (e) { /* per-method skip */ }
                });
            } catch (e) { /* interface not present */ }
        });

        // ── 4. Appdome threat verdict: (String[] threats) -> boolean[] all-false ──
        try {
            Java.enumerateLoadedClasses({
                onMatch: function (name) {
                    // Appdome rotates names — detect by method signature instead
                    if (name.indexOf("dalvik.") === 0) return;
                },
                onComplete: function () { }
            });
        } catch (e) { /* optional */ }

        // Generic: any loaded class with native method taking String[] returning boolean[]
        try {
            Java.enumerateMethods({
                query: "native *.*([Ljava/lang/String;)[Z",
                onMatch: function (handle) {
                    try {
                        const cls = Java.use(handle.className);
                        const methods = cls.class.getDeclaredMethods();
                        methods.forEach(function (m) {
                            if (m.getName() === handle.methodName) {
                                try {
                                    const impl = cls[handle.methodName];
                                    if (impl && impl.overloads) {
                                        impl.overloads.forEach(function (ov) {
                                            if (ov.argumentTypes.length === 1 &&
                                                ov.argumentTypes[0].className === "[Ljava.lang.String;") {
                                                ov.implementation = function (arr) {
                                                    const n = arr ? arr.length : 0;
                                                    log("BLINDED native threat query " +
                                                        handle.className + "." + handle.methodName +
                                                        " (" + n + " checks -> all false)");
                                                    const out = [];
                                                    for (let i = 0; i < n; i++) out.push(false);
                                                    return Java.array("boolean", out);
                                                };
                                                log("blinded " + handle.className + "." + handle.methodName);
                                            }
                                        });
                                    }
                                } catch (e) { /* per-method skip */ }
                            }
                        });
                    } catch (e) { /* per-class skip */ }
                },
                onComplete: function () { log("verdict-array scan complete"); }
            });
        } catch (e) { log("enumerateMethods: " + e); }

        // ── 5. BroadcastReceiver onReceive — drop RASP broadcasts entirely ──
        try {
            const Context = Java.use("android.content.Context");
            const overloads = Context.sendBroadcast.overloads;
            overloads.forEach(function (ov) {
                ov.implementation = function () {
                    try {
                        const intent = arguments[0];
                        if (intent && intent.getAction) {
                            const act = intent.getAction();
                            if (isRaspAction(act)) {
                                log("DROPPED sendBroadcast action=" + act);
                                return;
                            }
                        }
                    } catch (e) { /* fall through */ }
                    return ov.apply(this, arguments);
                };
            });
            log("sendBroadcast filtered for RASP actions");
        } catch (e) { log("sendBroadcast: " + e); }

        log("callback bypass installed — pair with rasp-enforcement-cut.js");
    });
}
