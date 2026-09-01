/**
 * keyboard-cache-checker.js
 * Check keyboard cache for sensitive data leakage
 * Monitor input field caching and autocomplete behavior
 *
 * Usage: frida -U -f <package> -l keyboard-cache-checker.js --no-pause
 */

'use strict';

console.log('[kcc] Keyboard cache checker loaded');

var inputOps = [];

Java.perform(function () {
    // ─── EditText input monitoring ─────────────────────
    try {
        var EditText = Java.use('android.widget.EditText');
        EditText.setText.implementation = function (text) {
            var hint = this.getHint();
            var inputType = this.getInputType();
            console.log('[kcc] setText: ' + (text ? text.toString().substring(0, 20) : 'null') +
                ' (hint=' + hint + ', type=' + inputType + ')');
            inputOps.push({ type: 'setText', hint: hint ? hint.toString() : null, inputType: inputType });
            return this.setText(text);
        };

        EditText.onTextChanged.implementation = function (s, start, before, count) {
            if (s && s.length() > 0) {
                var inputType = this.getInputType();
                // Check if it's a password field
                if (inputType & 0x80) { // INPUT_TYPE_TEXT_VARIATION_PASSWORD
                    console.log('[kcc] ⚠️  Password field input detected');
                }
            }
            return this.onTextChanged(s, start, before, count);
        };
    } catch (e) {}

    // ─── InputConnection monitoring ────────────────────
    try {
        var BaseInputConnection = Java.use('android.view.inputmethod.BaseInputConnection');
        BaseInputConnection.commitText.overload('java.lang.CharSequence', 'int').implementation = function (text, newCursorPosition) {
            console.log('[kcc] commitText: ' + text.toString().substring(0, 20));
            return this.commitText(text, newCursorPosition);
        };
    } catch (e) {}

    // ─── AutoCompleteTextView ──────────────────────────
    try {
        var AutoCompleteTextView = Java.use('android.widget.AutoCompleteTextView');
        AutoCompleteTextView.setAdapter.implementation = function (adapter) {
            console.log('[kcc] AutoComplete setAdapter: ' + adapter.getClass().getName());
            inputOps.push({ type: 'autoComplete', adapter: adapter.getClass().getName() });
            return this.setAdapter(adapter);
        };
    } catch (e) {}

    // ─── InputMethodManager ────────────────────────────
    try {
        var IMM = Java.use('android.view.inputmethod.InputMethodManager');
        IMM.showSoftInput.overload('android.view.View', 'int').implementation = function (view, flags) {
            console.log('[kcc] showSoftInput: ' + view.getClass().getName());
            return this.showSoftInput(view, flags);
        };
    } catch (e) {}

    console.log('[kcc] All hooks installed');
});

function keyboardCacheReport() {
    console.log('\n[kcc] === Keyboard Cache Report ===');
    console.log('[kcc] Total input operations: ' + inputOps.length);

    var passwordFields = inputOps.filter(function (op) {
        return op.inputType && (op.inputType & 0x80);
    });
    console.log('[kcc] Password field inputs: ' + passwordFields.length);

    inputOps.forEach(function (op) {
        console.log('[kcc]   ' + op.type + ': ' + (op.hint || op.adapter || ''));
    });
    console.log('[kcc] === End ===\n');
}

console.log('[kcc] Functions: keyboardCacheReport()');
console.log('[kcc] Loaded');
