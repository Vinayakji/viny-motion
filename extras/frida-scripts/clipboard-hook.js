// clipboard-hook.js — Hook ClipboardManager for clipboard data capture
Java.perform(function() {
    var Tag = "CLIPBOARD_HOOK";

    var ClipboardManager = Java.use("android.content.ClipboardManager");

    ClipboardManager.setPrimaryClip.implementation = function(clip) {
        var items = [];
        for (var i = 0; i < clip.getItemCount(); i++) {
            var item = clip.getItemAt(i);
            var text = item.getText() ? item.getText().toString() : null;
            var uri = item.getUri() ? item.getUri().toString() : null;
            var intent = item.getIntent() ? item.getIntent().toString() : null;
            items.push({text: text, uri: uri, intent: intent});

            console.log("[CLIPBOARD] setPrimaryClip: " + (text || uri || "intent"));
            if (text) {
                var lower = text.toLowerCase();
                if (lower.includes("token") || lower.includes("password") || lower.includes("api") || lower.includes("secret") || lower.includes("eyJ") || lower.includes("sk_")) {
                    send({type: "clipboard_vuln", vuln: "SENSITIVE_CLIPBOARD", data: text});
                    console.log("[!] Sensitive data in clipboard: " + text.substring(0, 100));
                }
            }
        }
        send({type: "clipboard", action: "setPrimaryClip", items: items, label: clip.getDescription() ? clip.getDescription().toString() : null});
        return this.setPrimaryClip(clip);
    };

    ClipboardManager.getPrimaryClip.implementation = function() {
        var clip = this.getPrimaryClip();
        if (clip) {
            var items = [];
            for (var i = 0; i < clip.getItemCount(); i++) {
                var item = clip.getItemAt(i);
                items.push({text: item.getText() ? item.getText().toString() : null, uri: item.getUri() ? item.getUri().toString() : null});
            }
            send({type: "clipboard", action: "getPrimaryClip", items: items});
            console.log("[CLIPBOARD] getPrimaryClip");
        }
        return clip;
    };

    ClipboardManager.hasPrimaryClip.implementation = function() {
        var has = this.hasPrimaryClip();
        send({type: "clipboard", action: "hasPrimaryClip", result: has});
        return has;
    };

    console.log("[*] Clipboard hooks loaded");
});
