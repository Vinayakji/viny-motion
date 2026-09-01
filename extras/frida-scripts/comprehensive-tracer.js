/**
 * comprehensive-tracer.js
 * Comprehensive method tracer with filtering, timing, and argument/return capture
 * Replaces: trace-all-methods, method-tracer, method-tracer-enhanced
 *
 * Usage: frida -U -f <package> -l comprehensive-tracer.js --no-pause
 */

'use strict';

console.log('[tracer] Comprehensive method tracer loaded');

var traceCount = 0;
var traceConfig = {
    classes: [],        // Filter by class name prefix
    methods: [],        // Filter by method name
    exclude: [],        // Exclude class patterns
    logArgs: true,      // Log arguments
    logReturn: true,    // Log return values
    logTiming: true,    // Log execution time
    maxTraceLen: 200    // Max string length for logged values
};

/**
 * Trace a specific class
 */
function traceClass(className, opts) {
    opts = opts || {};
    Java.perform(function () {
        try {
            var cls = Java.use(className);
            var methods = cls.class.getDeclaredMethods();

            methods.forEach(function (method) {
                var methodName = method.getName();
                if (opts.methods && opts.methods.indexOf(methodName) === -1) return;
                if (opts.exclude && opts.exclude.some(function (p) { return methodName.indexOf(p) !== -1; })) return;

                cls[methodName].overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        var args = Array.prototype.slice.call(arguments);
                        var startTime = traceConfig.logTiming ? Date.now() : 0;
                        traceCount++;

                        // Log call
                        if (traceConfig.logArgs) {
                            var argStr = args.map(function (a) {
                                return truncate(a !== null ? a.toString() : 'null');
                            }).join(', ');
                            console.log('[tracer] #' + traceCount + ' ' + className + '.' + methodName + '(' + argStr + ')');
                        }

                        // Execute
                        var result = this[methodName].apply(this, args);

                        // Log return
                        if (traceConfig.logReturn && result !== undefined) {
                            console.log('[tracer]   -> ' + truncate(result.toString()));
                        }

                        // Log timing
                        if (traceConfig.logTiming) {
                            var elapsed = Date.now() - startTime;
                            if (elapsed > 0) console.log('[tracer]   (' + elapsed + 'ms)');
                        }

                        return result;
                    };
                });
            });

            console.log('[tracer] Tracing ' + className + ' (' + methods.length + ' methods)');
        } catch (e) {
            console.log('[tracer] Class not found: ' + className);
        }
    });
}

/**
 * Trace all classes matching a pattern
 */
function tracePattern(pattern, opts) {
    Java.perform(function () {
        Java.enumerateLoadedClasses({
            onMatch: function (className) {
                if (className.indexOf(pattern) !== -1) {
                    traceClass(className, opts);
                }
            },
            onComplete: function () {}
        });
    });
}

/**
 * Trace native functions in a module
 */
function traceNative(moduleName, funcName) {
    var exports = Module.findExportByName(moduleName, funcName);
    if (exports) {
        Interceptor.attach(exports, {
            onEnter: function (args) {
                this.startTime = Date.now();
                traceCount++;
                console.log('[tracer] #' + traceCount + ' NATIVE ' + moduleName + '!' + funcName +
                    '(' + args[0] + ', ' + args[1] + ', ' + args[2] + ')');
            },
            onLeave: function (retval) {
                console.log('[tracer]   -> ' + retval + ' (' + (Date.now() - this.startTime) + 'ms)');
            }
        });
        console.log('[tracer] Native hook: ' + moduleName + '!' + funcName);
    }
}

function truncate(str) {
    if (str.length > traceConfig.maxTraceLen) {
        return str.substring(0, traceConfig.maxTraceLen) + '...';
    }
    return str;
}

console.log('[tracer] Functions: traceClass(), tracePattern(), traceNative()');
console.log('[tracer] Loaded');
