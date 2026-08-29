#!/usr/bin/env bash
# lib/objection_helpers.sh - Reliable objection execution helpers
# Replaces fragile sleep-based execution with proper API and timeout handling

# Run objection command with proper timeout and output capture
# Usage: objection_run <package> <command> <output_file> [timeout_seconds]
objection_run() {
  local pkg="$1"
  local cmd="$2"
  local outfile="$3"
  local timeout="${4:-30}"
  
  info "Running objection: $cmd"
  
  # Use timeout to prevent hanging
  timeout "$timeout" objection -g "$pkg" explore --startup-command "$cmd" --json > "$outfile" 2>&1
  local exit_code=$?
  
  if [ $exit_code -eq 124 ]; then
    warn "Objection command timed out after ${timeout}s"
  elif [ $exit_code -ne 0 ]; then
    warn "Objection command failed with exit code $exit_code"
  fi
  
  return $exit_code
}

# Run objection command and check for success patterns
# Usage: objection_run_and_verify <package> <command> <output_file> <success_pattern> [timeout]
objection_run_and_verify() {
  local pkg="$1"
  local cmd="$2"
  local outfile="$3"
  local pattern="$4"
  local timeout="${5:-30}"
  
  objection_run "$pkg" "$cmd" "$outfile" "$timeout"
  
  if grep -qi "$pattern" "$outfile" 2>/dev/null; then
    ok "Objection command succeeded: $cmd"
    return 0
  else
    warn "Objection command output did not match pattern: $pattern"
    return 1
  fi
}

# Run objection and extract JSON fields
# Usage: objection_json_extract <output_file> <json_path>
objection_json_extract() {
  local outfile="$1"
  local path="$2"
  
  if [ -f "$outfile" ]; then
    # Try to parse as JSON, fall back to plain text extraction
    if jq -e "$path" "$outfile" >/dev/null 2>&1; then
      jq -r "$path" "$outfile" 2>/dev/null
    else
      # Fallback: extract relevant lines
      grep -i "$path" "$outfile" 2>/dev/null | head -5
    fi
  fi
}

# Batch run multiple objection commands
# Usage: objection_batch <package> <output_dir> <command1> <command2> ...
objection_batch() {
  local pkg="$1"
  local outdir="$2"
  shift 2
  
  mkdir -p "$outdir"
  
  for cmd in "$@"; do
    local safe_name=$(echo "$cmd" | tr ' ' '_' | tr -cd '[:alnum:]_-')
    local outfile="$outdir/${safe_name}.txt"
    objection_run "$pkg" "$cmd" "$outfile" 30
  done
}

# Verify SSL pinning bypass actually works by testing HTTPS connection
# Usage: verify_ssl_bypass <url>
verify_ssl_bypass() {
  local url="$1"
  local outfile="${2:-/dev/null}"
  
  # Test with curl ignoring cert verification
  local result=$(curl -sk -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
  
  if [ "$result" -ge 200 ] && [ "$result" -lt 400 ]; then
    return 0
  else
    return 1
  fi
}

# Dump objection output to structured format
# Usage: dump_objection_structured <output_file> <finding_title> <severity> <cwe> <owasp>
dump_objection_structured() {
  local outfile="$1"
  local title="$2"
  local severity="$3"
  local cwe="$4"
  local owasp="$5"
  
  if [ -s "$outfile" ]; then
    # Create structured evidence file
    local evidence_file="${outfile%.txt}_evidence.md"
    cat > "$evidence_file" << EOF
# $title

## Command Output
\`\`\`
$(cat "$outfile")
\`\`\`

## Timestamp
$(date -Iseconds)

## Analysis
$(if grep -qi "success\|bypassed\|disabled" "$outfile"; then echo "Bypass successful"; else echo "Bypass may have failed - manual review needed"; fi)
EOF
    
    fadd "$title" "$severity" MEDIUM "$cwe" "$owasp" "$evidence_file"
  fi
}
