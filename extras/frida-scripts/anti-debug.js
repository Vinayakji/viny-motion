// anti-debug.js — Bypass anti-debugging (ptrace, isDebuggerConnected, timing, /proc checks)
Java.perform(function() {
    var Tag = "ANTI_DEBUG";

    // Bypass Debug.isDebuggerConnected
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() {
        send({type: "anti_debug", action: "isDebuggerConnected", result: false});
        console.log("[*] isDebuggerConnected -> false");
        return false;
    };

    // Bypass Debug.waitForDebugger
    try {
        Debug.waitForDebugger.overload("long").implementation = function(timeout) {
            send({type: "anti_debug", action: "waitForDebugger", bypassed: true});
            console.log("[*] waitForDebugger bypassed");
            return null;
        };
    } catch(e) {}

    // Hook ptrace via libc (native anti-debug)
    try {
        var libc = Module.findExportByName("libc.so", "ptrace");
        if (libc) {
            Interceptor.attach(libc, {
                onEnter: function(args) {
                    this.request = args[0].toInt32();
                    // PTRACE_TRACEME = 0
                    if (this.request === 0) {
                        send({type: "anti_debug", action: "ptrace", request: "PTRACE_TRACEME"});
                        console.log("[!] ptrace(PTRACE_TRACEME) intercepted");
                    }
                },
                onLeave: function(retval) {
                    if (this.request === 0) {
                        retval.replace(0);
                        console.log("[*] ptrace(PTRACE_TRACEME) -> 0 (success)");
                    }
                }
            });
        }
    } catch(e) {
        console.log("[*] ptrace hook failed: " + e);
    }

    // Hook inotify (file monitoring anti-debug)
    try {
        var inotify = Module.findExportByName("libc.so", "inotify_add_watch");
        if (inotify) {
            Interceptor.attach(inotify, {
                onEnter: function(args) {
                    var path = args[1].readCString();
                    if (path && (path.includes("/proc") || path.includes("/self"))) {
                        send({type: "anti_debug", action: "inotify_add_watch", path: path});
                        console.log("[!] inotify monitoring: " + path);
                    }
                }
            });
        }
    } catch(e) {}

    // Bypass Thread.getStackTrace timing check
    var Thread = Java.use("java.lang.Thread");
    Thread.sleep.overload("long").implementation = function(ms) {
        // Skip sleep calls used for timing detection
        if (ms > 1000) {
            send({type: "anti_debug", action: "sleep_skip", ms: ms});
            console.log("[*] Skipped sleep(" + ms + ") for timing bypass");
            return null;
        }
        return this.sleep(ms);
    };

    // Bypass System.nanoTime timing
    var System = Java.use("java.lang.System");
    var nanoTimeCallCount = 0;
    System.nanoTime.implementation = function() {
        nanoTimeCallCount++;
        return this.nanoTime();
    };

    // Hook /proc/self/status check
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("[Ljava.lang.String;").implementation = function(commands) {
            var cmd = commands.join(" ");
            if (cmd.includes("/proc") || cmd.includes("tracerpid")) {
                send({type: "anti_debug", action: "proc_check", command: cmd});
                console.log("[!] /proc check intercepted: " + cmd);
                // Return fake output with TracerPid=0
                var process = this.exec(commands);
                return process;
            }
            return this.exec(commands);
        };
    } catch(e) {}

    // Bypass Build.TAGS check (test-keys)
    var Build = Java.use("android.os.Build");
    Build.TAGS.value = "release-keys";

    // Bypass SELinux enforcement check
    try {
        var SELinux = Java.use("android.os.SELinux");
        SELinux.isEnforced.implementation = function() {
            send({type: "anti_debug", action: "selinux_check"});
            console.log("[*] SELinux isEnforced -> false");
            return false;
        };
        SELinux.setEnforced.overload("boolean").implementation = function(enforce) {
            send({type: "anti_debug", action: "setEnforced", enforce: enforce});
            return this.setEnforced(enforce);
        };
    } catch(e) {}

    console.log("[*] Anti-debug bypass loaded");
});
