/**
 * Root Detection Bypass
 * Usage: frida -U -f com.example.app -l root-bypass.js --no-pause
 */

Java.perform(function() {
    console.log('[*] Starting Root Detection Bypass...');
    
    // Method 1: File checks
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            if (path.indexOf('su') !== -1 || path.indexOf('Superuser') !== -1 || 
                path.indexOf('supersu') !== -1 || path.indexOf('magisk') !== -1) {
                console.log('[+] File.exists bypassed: ' + path);
                return false;
            }
            return this.exists();
        };
        console.log('[+] File.exists bypass installed');
    } catch(e) {
        console.log('[-] File bypass failed: ' + e);
    }
    
    // Method 2: Runtime.exec checks
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function(commands) {
            var cmd = commands.join(' ');
            if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1) {
                console.log('[+] Runtime.exec bypassed: ' + cmd);
                throw Java.use('java.io.IOException').$new('not found');
            }
            return this.exec(commands);
        };
        console.log('[+] Runtime.exec bypass installed');
    } catch(e) {
        console.log('[-] Runtime.exec bypass failed: ' + e);
    }
    
    // Method 3: System property checks
    try {
        var System = Java.use('java.lang.System');
        System.getProperty.overload('java.lang.String').implementation = function(key) {
            if (key === 'ro.build.tags' || key === 'ro.build.type') {
                console.log('[+] System.getProperty bypassed: ' + key);
                return 'release';
            }
            return this.getProperty(key);
        };
        console.log('[+] System.getProperty bypass installed');
    } catch(e) {
        console.log('[-] System.getProperty bypass failed: ' + e);
    }
    
    // Method 4: PackageManager checks
    try {
        var PackageManager = Java.use('android.app.ApplicationPackageManager');
        PackageManager.getInstalledPackages.implementation = function(flags) {
            var packages = this.getInstalledPackages(flags);
            var iterator = packages.iterator();
            while(iterator.hasNext()) {
                var pkg = iterator.next();
                var name = pkg.packageName.toString();
                if (name.indexOf('supersu') !== -1 || name.indexOf('superuser') !== -1 ||
                    name.indexOf('magisk') !== -1 || name.indexOf('kingo') !== -1) {
                    console.log('[+] Removed root package: ' + name);
                    iterator.remove();
                }
            }
            return packages;
        };
        console.log('[+] PackageManager bypass installed');
    } catch(e) {
        console.log('[-] PackageManager bypass failed: ' + e);
    }
    
    console.log('[*] Root Detection Bypass complete');
});
