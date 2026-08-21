# Objection Commands Reference
# Usage: objection -g <package> explore

# =============================================
# SSL PINNING
# =============================================
android sslpinning disable

# For newer Android versions
android sslpinning disable --quiet

# =============================================
# ROOT DETECTION
# =============================================
android root disable

# Simulate non-rooted environment
android root simulate

# =============================================
# KEYCHAIN / KEYSTORE
# =============================================
# List all keychain entries
ios keychain list

# Android keystore
android keystore list

# Dump keychain
ios keychain dump

# =============================================
# SHARED PREFERENCES
# =============================================
# List all shared preferences files
android sharedpref list

# Read specific file
android sharedpref read <filename>

# =============================================
# MEMORY OPERATIONS
# =============================================
# Search for strings in memory
memory search "password"
memory search "token"
memory search "secret"
memory search "api_key"

# Dump all memory
memory dump all /tmp/memory_dump.bin

# Dump specific address range
memory dump range 0x10000000 0x10001000 /tmp/range_dump.bin

# =============================================
# SQL INJECTION TESTING
# =============================================
# List databases
android sqlite lists

# Execute SQL
android sqlite execute <database> "SELECT * FROM users"

# Test for SQL injection
android sqlite execute <database> "SELECT * FROM users WHERE id='1' OR '1'='1'"

# =============================================
# ACTIVITY / INTENT TESTING
# =============================================
# List activities
android hooking list activities

# Launch activity
android launch <activity>

# Start service
android service start <service>

# =============================================
# INTENT INJECTION
# =============================================
# Create and send intent
android intent create --component <package>/<activity>
android intent send

# With extras
android intent send --extra "key" "value"
android intent send --extra "key" "value" --type "text/plain"

# =============================================
# NETWORK OPERATIONS
# =============================================
# Make HTTP request
android http get <url>
android http post <url> --data "key=value"

# =============================================
# UI AUTOMATION
# =============================================
# Screenshot
android ui screenshot /tmp/screenshot.png

# List current activity
android hooking list current-activity

# =============================================
# FRIDA SCRIPTS
# =============================================
# Import and run Frida script
import /path/to/script.js

# =============================================
# BYPASS TECHNIQUES
# =============================================

# 1. SSL Unpinning (multiple methods)
android sslpinning disable
android root disable

# 2. Certificate validation bypass
android sslpinning disable --quiet

# 3. Hook specific method
android hooking watch class <class_name>
android hooking watch class_method <class_name>.<method_name>

# 4. Return value manipulation
android hooking watch class <class_name> --return-value true

# =============================================
# ENUMERATION
# =============================================
# List all classes
android hooking list classes

# List all methods in class
android hooking list class_methods <class_name>

# Search for classes
android hooking search classes <pattern>

# Search for methods
android hooking search methods <pattern>

# =============================================
# DATA EXTRACTION
# =============================================
# Read file
file cat /data/data/<package>/shared_prefs/config.xml

# Download file
file download /data/data/<package>/databases/app.db /tmp/app.db

# List directory
file ls /data/data/<package>/
