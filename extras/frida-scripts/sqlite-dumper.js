/**
 * sqlite-dumper.js
 * Dump all SQLite databases from the running app
 * Monitor database operations and extract sensitive data
 *
 * Usage: frida -U -f <package> -l sqlite-dumper.js --no-pause
 */

'use strict';

console.log('[sql] SQLite dumper loaded');

var databases = [];
var sqlLog = [];

Java.perform(function () {
    // ─── Database Open Tracking ────────────────────────
    try {
        var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');

        SQLiteDatabase.openOrCreateDatabase.overload('java.lang.String', 'android.database.sqlite.SQLiteDatabase$CursorFactory')
            .implementation = function (path, factory) {
                console.log('[sql] DB opened: ' + path);
                databases.push({ path: path, type: 'openOrCreate' });
                return this.openOrCreateDatabase(path, factory);
            };

        SQLiteDatabase.openOrCreateDatabase.overload('java.io.File', 'android.database.sqlite.SQLiteDatabase$CursorFactory')
            .implementation = function (file, factory) {
                var path = file.getAbsolutePath();
                console.log('[sql] DB opened: ' + path);
                databases.push({ path: path, type: 'openOrCreate' });
                return this.openOrCreateDatabase(file, factory);
            };

        SQLiteDatabase.openDatabase.overload('java.lang.String', 'android.database.sqlite.SQLiteDatabase$CursorFactory', 'int')
            .implementation = function (path, factory, flags) {
                console.log('[sql] DB opened: ' + path);
                databases.push({ path: path, type: 'open' });
                return this.openDatabase(path, factory, flags);
            };
    } catch (e) {}

    // ─── SQL Execution Tracking ────────────────────────
    try {
        var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');

        SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function (sql) {
            sqlLog.push({ sql: sql, timestamp: Date.now() });
            if (sql.toLowerCase().indexOf('insert') !== -1 ||
                sql.toLowerCase().indexOf('update') !== -1 ||
                sql.toLowerCase().indexOf('delete') !== -1) {
                console.log('[sql] WRITE: ' + sql.substring(0, 200));
            }
            return this.execSQL(sql);
        };

        SQLiteDatabase.execSQL.overload('java.lang.String', '[Ljava.lang.Object;').implementation = function (sql, bindArgs) {
            sqlLog.push({ sql: sql, args: bindArgs, timestamp: Date.now() });
            console.log('[sql] EXEC: ' + sql.substring(0, 200));
            return this.execSQL(sql, bindArgs);
        };

        SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function (sql, selectionArgs) {
            console.log('[sql] QUERY: ' + sql.substring(0, 200));
            sqlLog.push({ sql: sql, args: selectionArgs, timestamp: Date.now(), type: 'query' });
            return this.rawQuery(sql, selectionArgs);
        };

        SQLiteDatabase.rawQueryWithFactory.overload('android.database.sqlite.SQLiteDatabase$CursorFactory', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String')
            .implementation = function (factory, sql, selectionArgs, editTable) {
                console.log('[sql] QUERY (factory): ' + sql.substring(0, 200));
                return this.rawQueryWithFactory(factory, sql, selectionArgs, editTable);
            };

        SQLiteDatabase.compileStatement.overload('java.lang.String').implementation = function (sql) {
            console.log('[sql] COMPILE: ' + sql.substring(0, 200));
            return this.compileStatement(sql);
        };
    } catch (e) {}

    // ─── Content Provider Query Tracking ───────────────
    try {
        var ContentResolver = Java.use('android.content.ContentResolver');
        ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String')
            .implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
                console.log('[sql] CP query: ' + uri.toString());
                if (selection) console.log('[sql]   WHERE: ' + selection);
                return this.query(uri, projection, selection, selectionArgs, sortOrder);
            };
    } catch (e) {}

    console.log('[sql] All hooks installed');
});

/**
 * Dump a specific database file
 */
function dumpDatabase(dbPath) {
    console.log('\n[sql] === Dumping database: ' + dbPath + ' ===');
    try {
        var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
        var db = SQLiteDatabase.openOrCreateDatabase(dbPath, null);

        // Get all tables
        var cursor = db.rawQuery("SELECT name FROM sqlite_master WHERE type='table'", null);
        var tables = [];
        while (cursor.moveToNext()) {
            tables.push(cursor.getString(0));
        }
        cursor.close();

        console.log('[sql] Tables: ' + tables.join(', '));

        // Dump each table
        tables.forEach(function (table) {
            if (table === 'android_metadata' || table === 'sqlite_sequence') return;

            try {
                var countCursor = db.rawQuery("SELECT COUNT(*) FROM " + table, null);
                countCursor.moveToFirst();
                var count = countCursor.getInt(0);
                countCursor.close();

                console.log('\n[sql] Table: ' + table + ' (' + count + ' rows)');

                var dataCursor = db.rawQuery("SELECT * FROM " + table + " LIMIT 10", null);
                var columns = dataCursor.getColumnNames();
                console.log('[sql]   Columns: ' + columns.join(', '));

                var rows = 0;
                while (dataCursor.moveToNext() && rows < 10) {
                    var row = {};
                    columns.forEach(function (col, i) {
                        row[col] = dataCursor.getString(i);
                    });
                    console.log('[sql]   Row: ' + JSON.stringify(row));
                    rows++;
                }
                dataCursor.close();
            } catch (e) {
                console.log('[sql]   Error reading table ' + table + ': ' + e);
            }
        });

        db.close();
    } catch (e) {
        console.log('[sql] Error dumping database: ' + e);
    }
    console.log('[sql] === End dump ===\n');
}

/**
 * Dump all tracked databases
 */
function dumpAllDatabases() {
    console.log('[sql] === All Databases (' + databases.length + ') ===');
    databases.forEach(function (db) {
        console.log('[sql]   ' + db.path + ' (' + db.type + ')');
        dumpDatabase(db.path);
    });
}

function sqlStats() {
    console.log('[sql] === SQL Stats ===');
    console.log('[sql] Databases: ' + databases.length);
    console.log('[sql] SQL operations: ' + sqlLog.length);

    var types = {};
    sqlLog.forEach(function (entry) {
        var type = entry.sql.split(' ')[0].toUpperCase();
        if (!types[type]) types[type] = 0;
        types[type]++;
    });

    console.log('\n[sql] Operation types:');
    for (var type in types) {
        console.log('[sql]   ' + type + ': ' + types[type]);
    }
}

console.log('[sql] Functions: dumpDatabase(path), dumpAllDatabases(), sqlStats()');
console.log('[sql] Loaded');
