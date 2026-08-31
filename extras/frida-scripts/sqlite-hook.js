// sqlite-hook.js — Hook SQLiteDatabase for all SQL operations
Java.perform(function() {
    var Tag = "SQLITE_HOOK";

    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");

    // Hook query
    SQLiteDatabase.query.overload("java.lang.String", "boolean", "java.lang.String", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.String").implementation = function(table, distinct, columns, selection, selectionArgs, groupBy, having, orderBy, limit) {
        send({type: "sqlite", action: "query", table: table, columns: columns ? columns.join(",") : "*", selection: selection, selectionArgs: selectionArgs ? selectionArgs.join(",") : null});
        console.log("[SQL] SELECT " + (columns ? columns.join(",") : "*") + " FROM " + table + (selection ? " WHERE " + selection : ""));
        return this.query(table, distinct, columns, selection, selectionArgs, groupBy, having, orderBy, limit);
    };

    // Hook rawQuery
    SQLiteDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;").implementation = function(selection, selectionArgs) {
        send({type: "sqlite", action: "rawQuery", query: selection, args: selectionArgs ? selectionArgs.join(",") : null});
        console.log("[SQL] rawQuery: " + selection);
        return this.rawQuery(selection, selectionArgs);
    };

    // Hook execSQL
    SQLiteDatabase.execSQL.overload("java.lang.String").implementation = function(sql) {
        send({type: "sqlite", action: "execSQL", query: sql});
        console.log("[SQL] execSQL: " + sql);
        return this.execSQL(sql);
    };

    SQLiteDatabase.execSQL.overload("java.lang.String", "[Ljava.lang.Object;").implementation = function(sql, bindArgs) {
        send({type: "sqlite", action: "execSQL_bound", query: sql, args: bindArgs ? bindArgs.join(",") : null});
        console.log("[SQL] execSQL: " + sql);
        return this.execSQL(sql, bindArgs);
    };

    // Hook insert
    SQLiteDatabase.insert.overload("java.lang.String", "java.lang.String", "android.content.ContentValues").implementation = function(table, nullColumnHack, values) {
        send({type: "sqlite", action: "insert", table: table, values: values ? values.toString() : null});
        console.log("[SQL] INSERT INTO " + table);
        return this.insert(table, nullColumnHack, values);
    };

    // Hook update
    SQLiteDatabase.update.overload("java.lang.String", "android.content.ContentValues", "java.lang.String", "[Ljava.lang.String;").implementation = function(table, values, whereClause, whereArgs) {
        send({type: "sqlite", action: "update", table: table, where: whereClause, args: whereArgs ? whereArgs.join(",") : null});
        console.log("[SQL] UPDATE " + table + (whereClause ? " WHERE " + whereClause : ""));
        return this.update(table, values, whereClause, whereArgs);
    };

    // Hook delete
    SQLiteDatabase.delete.overload("java.lang.String", "java.lang.String", "[Ljava.lang.String;").implementation = function(table, whereClause, whereArgs) {
        send({type: "sqlite", action: "delete", table: table, where: whereClause, args: whereArgs ? whereArgs.join(",") : null});
        console.log("[SQL] DELETE FROM " + table + (whereClause ? " WHERE " + whereClause : ""));
        return this.delete(table, whereClause, whereArgs);
    };

    // Hook compileStatement for raw operations
    try {
        var SQLiteStatement = Java.use("android.database.sqlite.SQLiteStatement");
        SQLiteStatement.executeInsert.implementation = function() {
            send({type: "sqlite", action: "executeInsert"});
            console.log("[SQL] executeInsert");
            return this.executeInsert();
        };

        SQLiteStatement.execute.implementation = function() {
            send({type: "sqlite", action: "execute"});
            return this.execute();
        };
    } catch(e) {}

    console.log("[*] SQLite hooks loaded");
});
