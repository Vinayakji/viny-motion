/**
 * haptic-feedback-interceptor.js
 * Intercept haptic feedback and vibration patterns
 * Monitor vibration usage for potential abuse
 *
 * Usage: frida -U -f <package> -l haptic-feedback-interceptor.js --no-pause
 */

'use strict';

console.log('[hfi] Haptic feedback interceptor loaded');

var hapticOps = [];

Java.perform(function () {
    // ─── Vibrator ──────────────────────────────────────
    try {
        var Vibrator = Java.use('android.os.Vibrator');
        Vibrator.vibrate.overload('long').implementation = function (milliseconds) {
            console.log('[hfi] Vibrate: ' + milliseconds + 'ms');
            hapticOps.push({ type: 'vibrate', duration: milliseconds, timestamp: Date.now() });
            return this.vibrate(milliseconds);
        };

        Vibrator.vibrate.overload('android.os.VibrationEffect').implementation = function (effect) {
            console.log('[hfi] VibrationEffect');
            hapticOps.push({ type: 'vibrateEffect', timestamp: Date.now() });
            return this.vibrate(effect);
        };

        Vibrator.vibrate.overload('[J', 'int').implementation = function (pattern, repeat) {
            console.log('[hfi] Vibrate pattern: ' + pattern.length + ' values');
            hapticOps.push({ type: 'vibratePattern', length: pattern.length, timestamp: Date.now() });
            return this.vibrate(pattern, repeat);
        };
    } catch (e) {}

    // ─── VibrationEffect ───────────────────────────────
    try {
        var VibrationEffect = Java.use('android.os.VibrationEffect');
        VibrationEffect.createOneShot.overload('long', 'int').implementation = function (duration, amplitude) {
            console.log('[hfi] OneShot: ' + duration + 'ms, amplitude=' + amplitude);
            return this.createOneShot(duration, amplitude);
        };

        VibrationEffect.createWaveform.overload('[J', '[I', 'int').implementation = function (timings, amplitudes, repeat) {
            console.log('[hfi] Waveform: ' + timings.length + ' timings');
            return this.createWaveform(timings, amplitudes, repeat);
        };
    } catch (e) {}

    // ─── HapticFeedbackConstants ───────────────────────
    try {
        var HapticFeedbackConstants = Java.use('android.view.HapticFeedbackConstants');
        console.log('[hfi] HapticFeedbackConstants available');
    } catch (e) {}

    // ─── View.performHapticFeedback ────────────────────
    try {
        var View = Java.use('android.view.View');
        View.performHapticFeedback.implementation = function (feedbackConstant) {
            console.log('[hfi] performHapticFeedback: constant=' + feedbackConstant);
            hapticOps.push({ type: 'hapticFeedback', constant: feedbackConstant, timestamp: Date.now() });
            return this.performHapticFeedback(feedbackConstant);
        };
    } catch (e) {}

    console.log('[hfi] All hooks installed');
});

function hapticReport() {
    console.log('\n[hfi] === Haptic Feedback Report ===');
    console.log('[hfi] Total operations: ' + hapticOps.length);
    hapticOps.forEach(function (op) {
        console.log('[hfi]   ' + op.type + ': ' + (op.duration || op.constant || ''));
    });
    console.log('[hfi] === End ===\n');
}

console.log('[hfi] Functions: hapticReport()');
console.log('[hfi] Loaded');
