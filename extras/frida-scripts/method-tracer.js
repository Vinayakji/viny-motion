/**
 * Method Tracer - Trace sensitive methods
 * Usage: frida -U -f com.example.app -l method-tracer.js --no-pause
 */

Java.perform(function() {
    console.log('[*] Starting Method Tracer...');
    
    var targetPackages = ['login', 'auth', 'token', 'password', 'secret', 'api', 'network', 'http'];
    
    // Enumerate loaded classes
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            var lowerName = className.toLowerCase();
            for (var i = 0; i < targetPackages.length; i++) {
                if (lowerName.indexOf(targetPackages[i]) !== -1) {
                    console.log('[*] Found sensitive class: ' + className);
                    traceClass(className);
                    break;
                }
            }
        },
        onComplete: function() {
            console.log('[*] Class enumeration complete');
        }
    });
    
    function traceClass(className) {
        try {
            var clazz = Java.use(className);
            var methods = clazz.class.getDeclaredMethods();
            
            methods.forEach(function(method) {
                var methodName = method.getName();
                try {
                    clazz[methodName].implementation = function() {
                        var args = Array.prototype.slice.call(arguments);
                        console.log('[CALL] ' + className + '.' + methodName + '(' + args.join(', ') + ')');
                        
                        // Call original method
                        return this[methodName].apply(this, arguments);
                    };
                } catch(e) {}
            });
        } catch(e) {
            console.log('[-] Failed to trace ' + className + ': ' + e);
        }
    }
    
    console.log('[*] Method Tracer initialized');
});
