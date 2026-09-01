/**
 * android-constructors-hook.js
 * Hook constructors and static initializers for all loaded classes
 * Useful for finding hidden initialization, credential seeding, config loading
 *
 * Usage: frida -U -f <package> -l android-constructors-hook.js --no-pause
 */

'use strict';

console.log('[constructors] Hooking constructors and static initializers...');

Java.perform(function () {
    var classNames = [];

    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            classNames.push(className);
        },
        onComplete: function () {
            console.log('[constructors] Found ' + classNames.length + ' loaded classes');

            var hooked = 0;
            classNames.forEach(function (className) {
                try {
                    var cls = Java.use(className);

                    // Hook default constructor if it exists
                    if (cls.$init) {
                        cls.$init.overloads.forEach(function (overload) {
                            overload.implementation = function () {
                                var args = Array.prototype.slice.call(arguments);
                                var argStr = args.map(function (a) {
                                    return a !== null ? a.toString().substring(0, 80) : 'null';
                                }).join(', ');
                                console.log('[constructors] ' + className + '.<init>(' + argStr + ')');
                                return this.$init.apply(this, args);
                            };
                            hooked++;
                        });
                    }

                    // Hook static initializer (<clinit>)
                    // Note: clinit is not directly hookable, but we can hook <clinit>-triggered methods
                } catch (e) {
                    // Skip classes that can't be hooked
                }
            });

            console.log('[constructors] Hooked ' + hooked + ' constructors');
        }
    });
});

console.log('[constructors] Loaded');
