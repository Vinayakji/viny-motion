// content-provider-hook.js — Hook ContentResolver for all CRUD operations
Java.perform(function() {
    var Tag = "CONTENT_PROVIDER_HOOK";

    var ContentResolver = Java.use("android.content.ContentResolver");

    // Hook query
    ContentResolver.query.overload("android.net.Uri", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String").implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
        send({type: "provider", action: "query", uri: uri.toString(), projection: projection ? javaArrToArr(projection) : null, selection: selection, selectionArgs: selectionArgs ? javaArrToArr(selectionArgs) : null, sortOrder: sortOrder});
        console.log("[PROVIDER] query: " + uri.toString());
        if (selection) console.log("  WHERE: " + selection);
        return this.query(uri, projection, selection, selectionArgs, sortOrder);
    };

    ContentResolver.query.overload("android.net.Uri", "[Ljava.lang.String;", "android.os.Bundle", "android.os.CancellationSignal").implementation = function(uri, projection, queryArgs, cancellationSignal) {
        send({type: "provider", action: "query_bundle", uri: uri.toString(), projection: projection ? javaArrToArr(projection) : null, args: queryArgs ? queryArgs.toString() : null});
        console.log("[PROVIDER] query (bundle): " + uri.toString());
        return this.query(uri, projection, queryArgs, cancellationSignal);
    };

    // Hook insert
    ContentResolver.insert.implementation = function(uri, values) {
        send({type: "provider", action: "insert", uri: uri.toString(), values: values ? values.toString() : null});
        console.log("[PROVIDER] insert: " + uri.toString());
        if (values) console.log("  VALUES: " + values.toString());
        return this.insert(uri, values);
    };

    // Hook update
    ContentResolver.update.overload("android.net.Uri", "android.content.ContentValues", "java.lang.String", "[Ljava.lang.String;").implementation = function(uri, values, selection, selectionArgs) {
        send({type: "provider", action: "update", uri: uri.toString(), selection: selection, selectionArgs: selectionArgs ? javaArrToArr(selectionArgs) : null});
        console.log("[PROVIDER] update: " + uri.toString());
        if (selection) console.log("  WHERE: " + selection);
        return this.update(uri, values, selection, selectionArgs);
    };

    // Hook delete
    ContentResolver.delete.overload("android.net.Uri", "java.lang.String", "[Ljava.lang.String;").implementation = function(uri, selection, selectionArgs) {
        send({type: "provider", action: "delete", uri: uri.toString(), selection: selection, selectionArgs: selectionArgs ? javaArrToArr(selectionArgs) : null});
        console.log("[PROVIDER] delete: " + uri.toString());
        if (selection) console.log("  WHERE: " + selection);
        return this.delete(uri, selection, selectionArgs);
    };

    // Hook call (provider method invocation)
    try {
        ContentResolver.call.overload("android.net.Uri", "java.lang.String", "java.lang.String", "android.os.Bundle").implementation = function(uri, method, arg, extras) {
            send({type: "provider", action: "call", uri: uri.toString(), method: method, arg: arg});
            console.log("[PROVIDER] call: " + uri.toString() + " -> " + method + "(" + arg + ")");
            return this.call(uri, method, arg, extras);
        };
    } catch(e) {}

    // Helper
    function javaArrToArr(javaArr) {
        var arr = [];
        for (var i = 0; i < javaArr.length; i++) arr.push(javaArr[i]);
        return arr;
    }

    console.log("[*] Content provider hooks loaded");
});
