/**
 * rasp-enforcement-cut.js — T2 enforcement neutralization
 *
 * Core principle (0x00sec/zsk/Appdome): detection that cannot ACT is harmless.
 * Let every detector run; cut the kill switch at BOTH layers:
 *   - native: kill/tgkill/raise/abort/exit/exit_group (libc wrappers AND raw svc forms)
 *   - java: System.exit, Runtime.exit/halt, Process.killProcess, Activity.finishAndRemoveTask
 *
 * APEX bionic (Android 12+): Interceptor.replace + NativeCallback (attach fails
 * with "not a function" on PLT stubs).
 *
 * Usage: frida -U -f <pkg> -l rasp-enforcement-cut.js   (SPAWN — before .init_array)
 * Bypasses: LIAPP, Appdome, AppSealing, Promon watchdog, freeRASP exitProcess,
 *           Bangcle svc-based killers (libc wrappers; raw svc handled via libc path
 *           only when they route through kill/exit_group wrappers — see notes).
 */
"use strict";

const TAG = "[ENFORCE-CUT]";
const blockedSignals = [6, 9, 19, 15]; // ABRT, KILL, STOP, TERM (self-directed)

function log(m) { console.log(TAG + " " + m); }

// ─── NATIVE LAYER (must run at script load, before any RASP constructor) ───
function nativeCut() {
    const libc = Process.getModuleByName("libc.so");
    if (!libc) { log("libc.so not found"); return; }

    // kill(pid, sig) — block self/parent kills with fatal signals
    const pKill = libc.findExportByName("kill");
    if (pKill) {
        try {
            const origKill = new NativeFunction(pKill, "int", ["int", "int"]);
            Interceptor.replace(pKill, new NativeCallback(function (pid, sig) {
                const self = Process.id;
                if ((sig === 9 || sig === 6 || sig === 19 || sig === 15) &&
                    (pid === self || pid === 0)) {
                    log("BLOCKED kill(" + pid + ", " + sig + ")");
                    return 0;
                }
                return origKill(pid, sig);
            }, "int", ["int", "int"]));
            log("kill() interposed");
        } catch (e) { log("kill replace failed: " + e); }
    }

    // tgkill(tgid, tid, sig)
    const pTgkill = libc.findExportByName("tgkill");
    if (pTgkill) {
        try {
            const origTgkill = new NativeFunction(pTgkill, "int", ["int", "int", "int"]);
            Interceptor.replace(pTgkill, new NativeCallback(function (tgid, tid, sig) {
                const self = Process.id;
                if ((sig === 9 || sig === 6 || sig === 19 || sig === 15) &&
                    (tgid === self || tgid === 0)) {
                    log("BLOCKED tgkill(" + tgid + "," + tid + "," + sig + ")");
                    return 0;
                }
                return origTgkill(tgid, tid, sig);
            }, "int", ["int", "int", "int"]));
            log("tgkill() interposed");
        } catch (e) { log("tgkill replace failed: " + e); }
    }

    // tkill(tid, sig)
    const pTkill = libc.findExportByName("tkill");
    if (pTkill) {
        try {
            const origTkill = new NativeFunction(pTkill, "int", ["int", "int"]);
            Interceptor.replace(pTkill, new NativeCallback(function (tid, sig) {
                if (sig === 9 || sig === 6 || sig === 19) {
                    log("BLOCKED tkill(" + tid + "," + sig + ")");
                    return 0;
                }
                return origTkill(tid, sig);
            }, "int", ["int", "int"]));
            log("tkill() interposed");
        } catch (e) { log("tkill replace failed: " + e); }
    }

    // raise(sig)
    const pRaise = libc.findExportByName("raise");
    if (pRaise) {
        try {
            const origRaise = new NativeFunction(pRaise, "int", ["int"]);
            Interceptor.replace(pRaise, new NativeCallback(function (sig) {
                if (sig === 6 || sig === 9) {
                    log("BLOCKED raise(" + sig + ")");
                    return 0;
                }
                return origRaise(sig);
            }, "int", ["int"]));
            log("raise() interposed");
        } catch (e) { log("raise replace failed: " + e); }
    }

    // abort() — no args, returns void, never returns normally
    const pAbort = libc.findExportByName("abort");
    if (pAbort) {
        try {
            const origAbort = new NativeFunction(pAbort, "void", []);
            Interceptor.replace(pAbort, new NativeCallback(function () {
                log("BLOCKED abort()");
                return;
            }, "void", []));
            log("abort() interposed (orig kept for rare legit calls)");
        } catch (e) { log("abort replace failed: " + e); }
    }

    // exit(status) — neutralize self-exit (RASP pattern), but this also stops legit exits.
    // Scope: block only status-less termination paths RASP uses (exit(0) after detection
    // and exit(1)). Comment out if app needs real exit for normal flows.
    const pExit = libc.findExportByName("exit");
    if (pExit) {
        try {
            const origExit = new NativeFunction(pExit, "void", ["int"]);
            Interceptor.replace(pExit, new NativeCallback(function (status) {
                log("BLOCKED exit(" + status + ")");
                return; // stay alive
            }, "void", ["int"]));
            log("exit() interposed");
        } catch (e) { log("exit replace failed: " + e); }
    }

    // exit_group(status) — kernel-level exit, catches raw svc paths that still
    // resolve through libc in most builds
    const pEg = libc.findExportByName("exit_group");
    if (pEg) {
        try {
            const origEg = new NativeFunction(pEg, "void", ["int"]);
            Interceptor.replace(pEg, new NativeCallback(function (status) {
                log("BLOCKED exit_group(" + status + ")");
                return;
            }, "void", ["int"]));
            log("exit_group() interposed");
        } catch (e) { log("exit_group replace failed: " + e); }
    }

    // fork() — RASP watchdogs fork a child that kills the parent (bypasses hooks in
    // parent). Return -1 (fork failed) so watchdog never spawns (Promon ptrace-lock
    // pattern too). Only if app doesn't legitimately fork.
    const pFork = libc.findExportByName("fork");
    if (pFork) {
        try {
            const origFork = new NativeFunction(pFork, "int", []);
            Interceptor.replace(pFork, new NativeCallback(function () {
                log("BLOCKED fork() (watchdog child prevention)");
                return -1;
            }, "int", []));
            log("fork() interposed");
        } catch (e) { log("fork replace failed: " + e); }
    }

    log("native cut installed — raw svc 0 killers (MOV X8,#56 + SVC) bypass libc: " +
        "grep .text for d4000001 and branch-patch if needed (T9)");
}

// ─── JAVA LAYER (after VM ready) ───
function javaCut() {
    if (!Java.available) { log("Java unavailable"); return; }
    Java.perform(function () {
        try {
            const System = Java.use("java.lang.System");
            System.exit.implementation = function (code) {
                log("BLOCKED System.exit(" + code + ")");
            };
            log("System.exit hooked");
        } catch (e) { log("System.exit: " + e); }

        try {
            const R = Java.use("java.lang.Runtime");
            R.exit.implementation = function (code) {
                log("BLOCKED Runtime.exit(" + code + ")");
            };
            R.halt.implementation = function (code) {
                log("BLOCKED Runtime.halt(" + code + ")");
            };
            log("Runtime.exit/halt hooked");
        } catch (e) { log("Runtime: " + e); }

        try {
            const P = Java.use("android.os.Process");
            P.killProcess.overload("int").implementation = function (pid) {
                const me = P.myPid();
                if (pid === me) { log("BLOCKED Process.killProcess(self)"); return; }
                return this.killProcess(pid);
            };
            log("Process.killProcess hooked");
        } catch (e) { log("Process.killProcess: " + e); }

        try {
            const A = Java.use("android.app.Activity");
            A.finishAndRemoveTask.implementation = function () {
                log("BLOCKED Activity.finishAndRemoveTask");
            };
            log("Activity.finishAndRemoveTask hooked");
        } catch (e) { log("finishAndRemoveTask: " + e); }

        // Appdome-style controller: neutralize when class matches killer signature
        try {
            Java.enumerateLoadedClasses({
                onMatch: function (name) {
                    if (/killMyProcess|AppSealingAlertDialog/i.test(name)) {
                        try {
                            const C = Java.use(name);
                            const methods = C.class.getDeclaredMethods();
                            for (let i = 0; i < methods.length; i++) {
                                const m = methods[i];
                                if (/killMyProcess|showAlertDialog/i.test(m.getName())) {
                                    const impl = C[m.getName()];
                                    if (impl && impl.implementation !== undefined) {
                                        impl.overloads.forEach(function (ov) {
                                            ov.implementation = function () {
                                                log("BLOCKED " + name + "." + m.getName());
                                            };
                                        });
                                    }
                                }
                            }
                            log("neutralized killer class: " + name);
                        } catch (e) { /* per-class skip */ }
                    }
                },
                onComplete: function () { log("killer-class scan complete"); }
            });
        } catch (e) { log("killer-class scan: " + e); }

        log("java cut installed");
    });
}

nativeCut();
setTimeout(javaCut, 300); // L3-lite: VM boot delay; for lazy SDKs retry at 1s/3s
setTimeout(function () { if (Java.available) Java.perform(javaCut); }, 1000);
setTimeout(function () { if (Java.available) Java.perform(javaCut); }, 3000);
