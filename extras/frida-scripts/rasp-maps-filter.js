/**
 * rasp-maps-filter.js — T3 read-path filtering (/proc sanitizer)
 *
 * Sits between detectors and what they read (0x00sec principle):
 *   1. fopen/fgets: filter /proc/self/maps lines (frida/xposed/linjector/hluda/
 *      memfd:frida/gum/substrate/lspd keywords) + zero TracerPid in /proc/self/status
 *   2. strstr/strcasestr/memmem: null-out needle matches for string scanners
 *      (OWASP UnCrackable-L3 native watchdog reads maps then strstr's it)
 *   3. open/read: comm-file thread-name sanitizer (gum-js-loop/gmain/gdbus/
 *      pool-frida/linjector blacklists from LIAPP sub_3DDB4)
 *   4. connect(): ECONNREFUSED for ports 27042-27050 (Frida default range)
 *
 * Strip a SUPERSET of signatures — stripping one line too many costs nothing;
 * missing one line the scanner reads costs everything.
 *
 * Known limit: readers using RAW svc syscalls bypass libc (patch .text instead).
 * Do NOT globally interpose openat (crash-loops idmap/setgid — see 0x00sec).
 *
 * Usage: frida -U -f <pkg> -l rasp-maps-filter.js
 */
"use strict";

const TAG = "[MAPS-FILTER]";
function log(m) { console.log(TAG + " " + m); }

// Superset of instrumentation signatures (maps line keywords + paths)
const MAP_KEYWORDS = [
    "frida", "gum-js", "linjector", "hluda",
    "xposed", "edxposed", "liblspd", "lspd", "libriru", "riru",
    "substrate", "libFupk", "blackdex", "/data/fart",
    "gadget", "re.frida", "libfrida",
    "/data/local/tmp", "MAGISK_INJ",
    "libxposed", "edxpu_"
];
// memfd special-case: memfd:frida / memfd:gum / memfd:agent / memfd:jit? (jit-cache is
// Phantom's own rename — keep if YOU built it, drop keyword to hide stock frida)
const MEMFD_NEEDLES = ["frida", "gum", "agent"];
// Thread comm blacklist (LIAPP decrypts per-byte; we match plaintext + common forms)
const COMM_BLACKLIST = ["gum-js", "gmain", "gdbus", "pool-frida", "linjector",
    "pool-spawn", "frida", "gum"];
const FRIDA_PORTS_START = 27042, FRIDA_PORTS_END = 27050;

function lineIsSuspicious(line) {
    if (!line || line.length < 5) return false;
    const l = line.toLowerCase();
    for (let i = 0; i < MAP_KEYWORDS.length; i++) {
        if (l.indexOf(MAP_KEYWORDS[i].toLowerCase()) !== -1) return true;
    }
    const mfi = l.indexOf("memfd:");
    if (mfi !== -1) {
        const rest = l.substring(mfi + 6);
        for (let i = 0; i < MEMFD_NEEDLES.length; i++) {
            if (rest.indexOf(MEMFD_NEEDLES[i]) !== -1) return true;
        }
    }
    return false;
}

// ─── 1. fopen / fgets path (libc readers) ───
function hookFileRead() {
    const libc = Process.getModuleByName("libc.so");
    if (!libc) return;

    const pFopen = libc.findExportByName("fopen");
    const pFgets = libc.findExportByName("fgets");
    if (!pFopen || !pFgets) { log("fopen/fgets not found"); return; }

    // Track which FILE* came from sensitive paths
    const tracked = new Set();

    try {
        const origFopen = new NativeFunction(pFopen, "pointer", ["pointer", "pointer"]);
        Interceptor.attach(pFopen, {
            onEnter: function (args) {
                try {
                    this.path = args[0].readCString();
                } catch (e) { this.path = null; }
            },
            onLeave: function (retval) {
                if (!this.path || retval.isNull()) return;
                if (/\/proc\/.*\/(maps|status|task)/.test(this.path) ||
                    this.path === "/proc/self/maps" || this.path === "/proc/self/status") {
                    tracked.add(retval.toString());
                    this.sensitive = true;
                }
            }
        });
        log("fopen attached (tracking maps/status/task FILE*)");
    } catch (e) { log("fopen: " + e); }

    // fgets: drop suspicious lines by re-reading until clean (bounded loop),
    // patch TracerPid: N -> TracerPid:\t0
    try {
        const origFgets = new NativeFunction(pFgets, "pointer", ["pointer", "int", "pointer"]);
        Interceptor.attach(pFgets, {
            onEnter: function (args) {
                this.buf = args[0];
                this.size = args[1].toInt32();
                this.stream = args[2].toString();
                this.tracked = tracked.has(this.stream);
            },
            onLeave: function (retval) {
                if (!this.tracked || retval.isNull()) return;
                try {
                    let line = this.buf.readCString();
                    if (line === null) return;
                    // TracerPid zeroing (anti-debug)
                    if (line.indexOf("TracerPid:") !== -1 && line.indexOf("TracerPid:\t0") === -1 &&
                        line.indexOf("TracerPid: 0") === -1) {
                        const patched = line.replace(/TracerPid:\s*\d+/, "TracerPid:\t0");
                        this.buf.writeUtf8String(patched);
                        log("TracerPid -> 0");
                        return;
                    }
                    // Maps line filtering: skip suspicious lines by advancing
                    let guard = 0;
                    while (lineIsSuspicious(line) && guard < 64) {
                        log("FILTERED line: " + line.trim().substring(0, 90));
                        const next = origFgets(this.buf, this.size, this.stream);
                        if (next.isNull()) { retval.replace(next); return; }
                        line = this.buf.readCString();
                        guard++;
                    }
                    if (guard >= 64) log("WARN: filter guard hit — stream may be all-suspicious");
                } catch (e) { /* leave as-is */ }
            }
        });
        log("fgets attached (line filter + TracerPid)");
    } catch (e) { log("fgets: " + e); }
}

// ─── 2. strstr / strcasestr / memmem — needle nulling (UnCrackable-L3) ───
function hookStringScanners() {
    const libc = Process.getModuleByName("libc.so");
    if (!libc) return;
    const needles = ["frida", "xposed", "linjector", "gadget", "substrate", "lspd", "hluda"];

    ["strstr", "strcasestr"].forEach(function (fname) {
        const p = libc.findExportByName(fname);
        if (!p) return;
        try {
            const orig = new NativeFunction(p, "pointer", ["pointer", "pointer"]);
            Interceptor.attach(p, {
                onEnter: function (args) {
                    try {
                        const needle = args[1].readCString() || "";
                        this.hide = needles.some(function (n) {
                            return needle.toLowerCase().indexOf(n) !== -1;
                        });
                        if (this.hide) log("strstr-haystack for '" + needle + "' -> forced NULL");
                    } catch (e) { this.hide = false; }
                },
                onLeave: function (retval) {
                    if (this.hide) retval.replace(ptr(0));
                }
            });
            log(fname + " attached");
        } catch (e) { log(fname + ": " + e); }
    });

    const pMemmem = libc.findExportByName("memmem");
    if (pMemmem) {
        try {
            Interceptor.attach(pMemmem, {
                onEnter: function (args) {
                    try {
                        const nlen = args[3].toInt32();
                        if (nlen > 0 && nlen < 64) {
                            const needle = args[2].readUtf8String(nlen).toLowerCase();
                            this.hide = needles.some(function (n) {
                                return needle.indexOf(n) !== -1;
                            });
                            if (this.hide) log("memmem needle '" + needle + "' -> forced NULL");
                        } else this.hide = false;
                    } catch (e) { this.hide = false; }
                },
                onLeave: function (retval) {
                    if (this.hide) retval.replace(ptr(0));
                }
            });
            log("memmem attached");
        } catch (e) { log("memmem: " + e); }
    }
}

// ─── 3. Thread comm sanitizer (LIAPP-style /proc/self/task/*/comm readers) ───
function hookCommReads() {
    const libc = Process.getModuleByName("libc.so");
    if (!libc) return;
    const pOpen = libc.findExportByName("open") || libc.findExportByName("open64");
    const pRead = libc.findExportByName("read");
    if (!pRead) return;

    const commFds = new Map(); // fd -> path

    if (pOpen) {
        try {
            Interceptor.attach(pOpen, {
                onEnter: function (args) {
                    try { this.path = args[0].readCString(); } catch (e) { this.path = null; }
                },
                onLeave: function (retval) {
                    if (this.path && /\/task\/\d+\/comm$/.test(this.path)) {
                        const fd = retval.toInt32();
                        if (fd >= 0) commFds.set(fd, this.path);
                    }
                }
            });
            log("open() comm tracking attached");
        } catch (e) { log("open: " + e); }
    }

    try {
        const origRead = new NativeFunction(pRead, "long", ["int", "pointer", "ulong"]);
        Interceptor.attach(pRead, {
            onEnter: function (args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
                this.count = args[2].toInt32();
                this.tracked = commFds.has(this.fd);
            },
            onLeave: function (retval) {
                if (!this.tracked || retval.toInt32() <= 0) return;
                try {
                    const got = retval.toInt32();
                    const content = this.buf.readUtf8String(got);
                    const lower = (content || "").toLowerCase();
                    for (let i = 0; i < COMM_BLACKLIST.length; i++) {
                        if (lower.indexOf(COMM_BLACKLIST[i]) !== -1) {
                            // overwrite with benign name, keep length (kernel expects the count)
                            const clean = "Binder:1_1\n";
                            const out = clean.length < got ? clean + "\n".repeat(got - clean.length) : clean;
                            this.buf.writeUtf8String(out.substring(0, got));
                            log("SANITIZED comm '" + content.trim() + "' -> benign");
                            return;
                        }
                    }
                } catch (e) { /* leave as-is */ }
            }
        });
        log("read() comm sanitizer attached");
    } catch (e) { log("read: " + e); }

    // cleanup fd tracking on close
    const pClose = libc.findExportByName("close");
    if (pClose) {
        Interceptor.attach(pClose, {
            onEnter: function (args) {
                commFds.delete(args[0].toInt32());
            }
        });
    }
}

// ─── 4. connect() — refuse Frida port scans (27042-27050 + common alt ports) ───
function hookPortScan() {
    const libc = Process.getModuleByName("libc.so");
    if (!libc) return;
    const pConnect = libc.findExportByName("connect");
    if (!pConnect) return;
    try {
        const origConnect = new NativeFunction(pConnect, "int", ["int", "pointer", "int"]);
        Interceptor.replace(pConnect, new NativeCallback(function (fd, addr, len) {
            try {
                const family = addr.readU16(); // sa_family little-endian
                if (family === 2 /* AF_INET */) {
                    const port = ((addr.add(2).readU8() << 8) | addr.add(3).readU8());
                    if (port >= FRIDA_PORTS_START && port <= FRIDA_PORTS_END) {
                        log("BLOCKED connect -> port " + port + " (ECONNREFUSED)");
                        return -111; // ECONNREFUSED
                    }
                }
            } catch (e) { /* fall through */ }
            return origConnect(fd, addr, len);
        }, "int", ["int", "pointer", "int"]));
        log("connect() port filter attached (" + FRIDA_PORTS_START + "-" + FRIDA_PORTS_END + ")");
    } catch (e) { log("connect: " + e); }
}

hookFileRead();
hookStringScanners();
hookCommReads();
hookPortScan();
log("read-path filter installed — raw svc readers bypass this (patch .text / out-of-process read instead)");
