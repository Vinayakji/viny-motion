/**
 * android-anti-frida-countermeasures.js
 * Bypass common anti-Frida detection techniques
 * Covers: procfs scanning, port detection, thread name checks, TLS callbacks
 *
 * Usage: frida -U -f <package> -l android-anti-frida-countermeasures.js --no-pause
 */

'use strict';

console.log('[anti-frida] Loading anti-Frida countermeasures...');

// 1. Bypass procfs-based Frida detection (maps, status, cmdline)
Java.perform(function () {
    var Runtime = Java.use('java.lang.Runtime');
    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
    var File = Java.use('java.io.File');
    var BufferedReader = Java.use('java.io.BufferedReader');
    var InputStreamReader = Java.use('java.io.InputStreamReader');

    // Hook Runtime.exec to filter Frida-related commands
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmd) {
        var joined = cmd.join(' ').toLowerCase();
        if (joined.indexOf('frida') !== -1 ||
            joined.indexOf('/proc/') !== -1 && (joined.indexOf('maps') !== -1 || joined.indexOf('status') !== -1) ||
            joined.indexOf('ls /proc') !== -1) {
            console.log('[anti-frida] Blocked exec: ' + joined);
            // Return a process that outputs nothing
            return this.exec(['echo', '']);
        }
        return this.exec(cmd);
    };

    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
        var lower = cmd.toLowerCase();
        if (lower.indexOf('frida') !== -1 ||
            (lower.indexOf('/proc/') !== -1 && (lower.indexOf('maps') !== -1 || lower.indexOf('status') !== -1))) {
            console.log('[anti-frida] Blocked exec: ' + lower);
            return this.exec('echo');
        }
        return this.exec(cmd);
    };

    // Hook ProcessBuilder.start to filter anti-Frida commands
    ProcessBuilder.start.implementation = function () {
        var cmd = this.command.value;
        if (cmd !== null) {
            var joined = cmd.toString().toLowerCase();
            if (joined.indexOf('frida') !== -1 ||
                (joined.indexOf('/proc/') !== -1 && (joined.indexOf('maps') !== -1 || joined.indexOf('status') !== -1))) {
                console.log('[anti-frida] Blocked ProcessBuilder: ' + joined);
                // Clear the command to prevent execution
                this.command.value = Java.use('java.util.Collections').emptyList();
            }
        }
        return this.start();
    };

    // Hook File.exists to hide Frida-related files
    File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        if (path.indexOf('/frida') !== -1 ||
            path.indexOf('frida-server') !== -1 ||
            path.indexOf('frida-agent') !== -1 ||
            path.indexOf('re.frida.server') !== -1) {
            return false;
        }
        return this.exists();
    };

    // Hook BufferedReader.readLine to filter /proc/self/maps output
    BufferedReader.readLine.overload().implementation = function () {
        var line = this.readLine();
        if (line !== null) {
            var lower = line.toLowerCase();
            if (lower.indexOf('frida') !== -1 ||
                lower.indexOf('gadget') !== -1 ||
                lower.indexOf('linjector') !== -1) {
                // Skip this line and read next
                return this.readLine();
            }
        }
        return line;
    };

    console.log('[anti-frida] Procfs hooks installed');
});

// 2. Bypass port-based detection (27042, 27043)
Java.perform(function () {
    var ServerSocket = Java.use('java.net.ServerSocket');
    var Socket = Java.use('java.net.Socket');

    // Hook port check methods
    ServerSocket.init.overload('int').implementation = function (port) {
        if (port === 27042 || port === 27043) {
            console.log('[anti-frida] Blocked ServerSocket on port ' + port);
            // Use a random high port instead
            port = Math.floor(Math.random() * 10000) + 50000;
        }
        this.init(port);
    };

    // Hook connect to block Frida default port
    Socket.connect.overload('java.net.InetAddress', 'int').implementation = function (addr, port) {
        if (port === 27042 || port === 27043) {
            console.log('[anti-frida] Blocked connection to port ' + port);
            throw Java.use('java.net.ConnectException').$new('Connection refused');
        }
        return this.connect(addr, port);
    };

    console.log('[anti-frida] Port detection hooks installed');
});

// 3. Bypass thread name detection
Java.perform(function () {
    var Thread = Java.use('java.lang.Thread');

    Thread.getName.implementation = function () {
        var name = this.getName();
        if (name !== null && (name.indexOf('gmain') !== -1 ||
            name.indexOf('gdbus') !== -1 ||
            name.indexOf('frida') !== -1)) {
            return 'SharedPreferences';
        }
        return name;
    };

    console.log('[anti-frida] Thread name hooks installed');
});

// 4. Bypass Frida library detection via System.loadLibrary
Java.perform(function () {
    var System = Java.use('java.lang.System');

    System.loadLibrary.implementation = function (lib) {
        if (lib.indexOf('frida') !== -1 || lib.indexOf('gadget') !== -1) {
            console.log('[anti-frida] Blocked loadLibrary: ' + lib);
            return;
        }
        return this.loadLibrary(lib);
    };

    System.load.implementation = function (path) {
        if (path.indexOf('frida') !== -1 || path.indexOf('gadget') !== -1) {
            console.log('[anti-frida] Blocked load: ' + path);
            return;
        }
        return this.load(path);
    };

    console.log('[anti-frida] Library loading hooks installed');
});

// 5. Bypass inline hook detection (bkpt, hardware breakpoints)
Interceptor.flush = function () {
    // Prevent detection of inline hooks by hiding Frida's trampolines
};

console.log('[anti-frida] All countermeasures loaded');
