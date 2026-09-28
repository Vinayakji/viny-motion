#!/usr/bin/env bash
# lib/scope_gate.sh — script-level authorization gate (ENFORCED for automated runs).
# Wildcard authorization model: ONE operator-confirmed authorization statement is
# enough (target.authorization_ref in config/target.yaml). What to test specifically
# is decided during the engagement as time and context reveal the attack surface.

require_authorization() {
  local ref
  ref="$(tget target authorization_ref 2>/dev/null || echo "")"
  case "$ref" in
    "" | "TODO"* | "change me"* | "REPLACE"* | "FILL"*)
      echo ""
      echo "REFUSING TO RUN: no authorization recorded."
      echo "  This pipeline is authorization-gated (enforced for automated runs)."
      echo "  Set 'authorization_ref' under 'target:' in config/target.yaml to a single"
      echo "  wildcard authorization statement, e.g.:"
      echo '    authorization_ref: "Authorized to test <target set> until <date>, operator-confirmed"'
      echo "  One statement is enough — specific test scope is decided during the run."
      echo ""
      return 1
      ;;
  esac
  return 0
}