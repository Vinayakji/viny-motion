/**
 * location-leak-detector.js
 * Detect location data leakage in network requests and logs
 * Monitor GPS, network, and passive location providers
 *
 * Usage: frida -U -f <package> -l location-leak-detector.js --no-pause
 */

'use strict';

console.log('[loc] Location leak detector loaded');

var locationOps = [];

Java.perform(function () {
    // ─── LocationManager ───────────────────────────────
    try {
        var LocationManager = Java.use('android.location.LocationManager');

        LocationManager.getLastKnownLocation.overload('java.lang.String').implementation = function (provider) {
            var loc = this.getLastKnownLocation(provider);
            if (loc) {
                console.log('[loc] getLastKnownLocation(' + provider + '): ' +
                    loc.getLatitude() + ',' + loc.getLongitude());
                locationOps.push({
                    type: 'getLastKnown',
                    provider: provider,
                    lat: loc.getLatitude(),
                    lon: loc.getLongitude(),
                    timestamp: Date.now()
                });
            }
            return loc;
        };

        LocationManager.requestLocationUpdates.overload('java.lang.String', 'long', 'float', 'android.location.LocationListener')
            .implementation = function (provider, minTime, minDist, listener) {
                console.log('[loc] requestLocationUpdates: ' + provider +
                    ' (interval=' + minTime + 'ms, distance=' + minDist + 'm)');
                locationOps.push({ type: 'requestUpdates', provider: provider, interval: minTime });
                return this.requestLocationUpdates(provider, minTime, minDist, listener);
            };

        LocationManager.requestSingleUpdate.overload('java.lang.String', 'android.location.LocationListener', 'android.os.Looper')
            .implementation = function (provider, listener, looper) {
                console.log('[loc] requestSingleUpdate: ' + provider);
                locationOps.push({ type: 'singleUpdate', provider: provider });
                return this.requestSingleUpdate(provider, listener, looper);
            };
    } catch (e) {}

    // ─── FusedLocationProviderClient ───────────────────
    try {
        var FLP = Java.use('com.google.android.gms.location.FusedLocationProviderClient');
        FLP.getLastLocation.implementation = function () {
            console.log('[loc] FusedLocationProvider.getLastLocation');
            locationOps.push({ type: 'fusedLastLocation' });
            return this.getLastLocation();
        };

        FLP.requestLocationUpdates.overload('com.google.android.gms.location.LocationRequest', 'com.google.android.gms.location.LocationCallback', 'android.os.Looper')
            .implementation = function (request, callback, looper) {
                console.log('[loc] FusedLocationProvider.requestLocationUpdates');
                locationOps.push({ type: 'fusedRequestUpdates' });
                return this.requestLocationUpdates(request, callback, looper);
            };
    } catch (e) {}

    // ─── Geocoder ──────────────────────────────────────
    try {
        var Geocoder = Java.use('android.location.Geocoder');
        Geocoder.getFromLocation.overload('double', 'double', 'int').implementation = function (lat, lon, maxResults) {
            console.log('[loc] Geocoder: ' + lat + ',' + lon);
            locationOps.push({ type: 'geocode', lat: lat, lon: lon });
            return this.getFromLocation(lat, lon, maxResults);
        };
    } catch (e) {}

    // ─── Location in HTTP headers ──────────────────────
    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.setRequestProperty.overload('java.lang.String', 'java.lang.String')
            .implementation = function (key, value) {
                var lower = key.toLowerCase();
                if (lower.indexOf('location') !== -1 || lower.indexOf('gps') !== -1 ||
                    lower.indexOf('latitude') !== -1 || lower.indexOf('longitude') !== -1) {
                    console.log('[loc] ⚠️  Location in header: ' + key + '=' + value);
                }
                return this.setRequestProperty(key, value);
            };
    } catch (e) {}

    console.log('[loc] All hooks installed');
});

function locationLeakReport() {
    console.log('\n[loc] === Location Leak Report ===');
    console.log('[loc] Total location operations: ' + locationOps.length);

    var gpsOps = locationOps.filter(function (o) { return o.provider === 'gps'; });
    var networkOps = locationOps.filter(function (o) { return o.provider === 'network'; });

    console.log('[loc] GPS operations: ' + gpsOps.length);
    console.log('[loc] Network operations: ' + networkOps.length);

    locationOps.forEach(function (op) {
        console.log('[loc]   ' + op.type + ': ' + (op.provider || '') +
            (op.lat ? ' (' + op.lat + ',' + op.lon + ')' : ''));
    });
    console.log('[loc] === End ===\n');
}

console.log('[loc] Functions: locationLeakReport()');
console.log('[loc] Loaded');
