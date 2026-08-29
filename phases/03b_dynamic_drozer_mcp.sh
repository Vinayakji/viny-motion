#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 03b_dynamic_drozer_mcp.sh - Drozer via Genymotion MCP tools (when available)
# This is the "proper" version using the 208 MCP tools directly
PROFILE_PHASE="03b_dynamic_drozer_mcp"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
[ -z "$PKG" ] && { err "No package_name in config"; exit 1; }

cd "$RUN_DIR" || exit 1
info "Drozer MCP testing on $PKG"

DROZER_DIR="$RUN_DIR/drozer_mcp"
mkdir -p "$DROZER_DIR"

# ============================================================
# This script documents the MCP tool calls that SHOULD replace
# the shell-based drozer phase when running through opencode.
#
# To use: run these as opencode commands, not bash.
# ============================================================

cat > "$DROZER_DIR/MCP_COMMANDS.md" <<'EOF'
# Drozer MCP Commands for Genymotion Pipeline

## Setup
```
genymotion_drozer_server_start
genymotion_drozer_server_status
```

## Enumeration
```
genymotion_drozer_enumerate_app package=com.example.app
genymotion_drozer_console_command command="run app.package.manifest com.example.app"
genymotion_drozer_console_command command="run app.activity.info -a com.example.app"
genymotion_drozer_console_command command="run app.service.info -a com.example.app"
genymotion_drozer_console_command command="run app.provider.info -a com.example.app"
genymotion_drozer_console_command command="run app.broadcast.info -a com.example.app"
genymotion_drozer_console_command command="run app.provider.find -a com.example.app"
```

## Scanners
```
genymotion_drozer_console_command command="run scanner.provider.injection -a com.example.app"
genymotion_drozer_console_command command="run scanner.provider.traversal -a com.example.app"
genymotion_drozer_console_command command="run scanner.provider.file -a com.example.app"
genymotion_drozer_console_command command="run scanner.provider.blob -a com.example.app"
genymotion_drozer_console_command command="run app.package.debuggable com.example.app"
genymotion_drozer_console_command command="run app.package.backup com.example.app"
```

## Exploitation
```
genymotion_drozer_console_command command="run app.provider.query content://com.example.app/"
genymotion_drozer_console_command command="run app.provider.query content://com.example.app/ --where '1=1'"
genymotion_drozer_console_command command="run app.broadcast.send --component com.example.app --action android.intent.action.BOOT_COMPLETED"
genymotion_drozer_console_command command="run app.service.send --component com.example.app/.MainService --extra string password test"
```

## Payloads & Exploits
```
genymotion_drozer_exploit_list
genymotion_drozer_exploit_info exploit_name="exploit.remote.browser.addjavascriptinterface"
genymotion_drozer_exploit_build exploit_name="exploit.remote.browser.addjavascriptinterface"
genymotion_drozer_payload_generate payload_type="drozer" server="10.0.0.1" port="31415"
```

## SSL & Certs
```
genymotion_drozer_ssl_create ssl_type="ca"
genymotion_drozer_ssl_show
```

## Full Scan
```
genymotion_drozer_full_scan package="com.example.app" run_modules=true export_results=true
genymotion_drozer_run_all_modules package="com.example.app"
```

## Module Management
```
genymotion_drozer_module_search query="provider"
genymotion_drozer_module_list_categories
genymotion_drozer_module_install module_name="scanner.provider.injection"
```
EOF

info "MCP command reference written to $DROZER_DIR/MCP_COMMANDS.md"

# ---- If MCP tools are available via opencode, run them ----
# These would be called as opencode tool calls, not bash.
# The bash phase (03_dynamic_drozer.sh) handles the shell fallback.

info "For full drozer testing, run through opencode with Genymotion MCP tools"
info "See: $DROZER_DIR/MCP_COMMANDS.md"
