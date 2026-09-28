#!/usr/bin/env python3
"""
secrets_scanner.py — SAST secrets scanner (single source of truth).
Loads config/secrets-patterns.json (PRIMARY user regex runs FIRST, every scan,
then 38 curated additions). Used by:
  - mcp_server.extract_secrets (MCP tool)
  - pipeline_tools.sast_secrets_scan (MCP tool)
  - phases/01_static.sh + 16_code_analysis.sh (CLI)
  - any python: from secrets_scanner import scan_text, scan_paths

CLI:
  python3 secrets_scanner.py <path> [--json] [--dirs] [--min-severity SEV]
"""

import json
import re
import sys
from pathlib import Path

PATTERNS_FILE = Path(__file__).resolve().parent / "config" / "secrets-patterns.json"

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

_cache = None


def load_patterns():
    """Load + compile pattern set. Primary regex is ALWAYS first in the list."""
    global _cache
    if _cache is not None:
        return _cache
    raw = json.loads(PATTERNS_FILE.read_text())
    entries = [raw["primary"]] + raw.get("additions", [])
    compiled = []
    for e in entries:
        try:
            compiled.append((e, re.compile(e["regex"])))
        except re.error:
            continue  # skip uncompilable rather than fail the scan
    _cache = compiled
    return _cache


def _extract_match(m):
    """Pull the most secret-looking capture group (or full match)."""
    for g in reversed(m.groups()):
        if g and len(g) >= 6:
            return g
    return m.group(0)


def scan_text(text, origin="", min_severity="INFO", max_per_pattern=25):
    """Scan a text blob. Returns list of finding dicts sorted by severity."""
    if not text:
        return []
    floor = SEV_ORDER.get(min_severity.upper(), 4)
    findings = []
    seen = set()
    for entry, rx in load_patterns():
        if SEV_ORDER.get(entry["severity"].upper(), 4) > floor:
            continue
        hits = 0
        for m in rx.finditer(text):
            if hits >= max_per_pattern:
                break
            value = _extract_match(m)
            key = (entry["id"], value[:120])
            if key in seen:
                continue
            seen.add(key)
            hits += 1
            # line number for reporting
            line = text.count("\n", 0, m.start()) + 1
            findings.append({
                "pattern_id": entry["id"],
                "pattern": entry["name"],
                "severity": entry["severity"],
                "confidence": entry["confidence"],
                "cwe": entry.get("cwe", ""),
                "value": value[:200],
                "line": line,
                "origin": origin,
                "primary": entry["id"] == "SEC-PRIMARY-USER",
            })
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 4),
                                 not f["primary"]))
    return findings


def scan_paths(paths, min_severity="INFO", max_files=4000, max_file_kb=2048):
    """Scan files/dirs (decompiled sources, resources, native strings)."""
    all_findings = []
    files = []
    for p in paths:
        p = Path(p)
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            for f in p.rglob("*"):
                if f.is_file() and f.suffix.lower() in (
                        ".java", ".kt", ".xml", ".json", ".js", ".ts", ".smali",
                        ".properties", ".gradle", ".yml", ".yaml", ".txt", ".cfg",
                        ".ini", ".env", ".pem", ".key", ".p12", ".jks", ""):
                    files.append(f)
                if len(files) >= max_files:
                    break
    for f in files[:max_files]:
        try:
            if f.stat().st_size > max_file_kb * 1024:
                continue
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        all_findings.extend(scan_text(text, origin=str(f),
                                      min_severity=min_severity))
    # dedupe by (pattern, value)
    dedup, seen = [], set()
    for f in all_findings:
        k = (f["pattern_id"], f["value"][:120])
        if k in seen:
            continue
        seen.add(k)
        dedup.append(f)
    dedup.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 4), not f["primary"]))
    return dedup


def summarize(findings):
    sev = {}
    for f in findings:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    primary_hits = sum(1 for f in findings if f["primary"])
    return {
        "total": len(findings),
        "by_severity": {s: sev.get(s, 0) for s in
                        ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if sev.get(s)},
        "primary_regex_hits": primary_hits,
        "patterns_fired": sorted({f["pattern_id"] for f in findings}),
    }


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in sys.argv
    min_sev = "INFO"
    for i, a in enumerate(sys.argv):
        if a == "--min-severity" and i + 1 < len(sys.argv):
            min_sev = sys.argv[i + 1]
    if not args:
        print(__doc__)
        sys.exit(2)
    targets = []
    for a in args:
        p = Path(a)
        if p.is_dir():
            targets.extend([str(p)])
        else:
            targets.append(str(p))
    findings = scan_paths(targets, min_severity=min_sev)
    summary = summarize(findings)
    if as_json:
        print(json.dumps({"summary": summary, "findings": findings}, indent=2))
    else:
        print(f"=== SAST SECRETS SCAN ({summary['total']} findings) ===")
        print(f"    primary-user-regex hits: {summary['primary_regex_hits']}")
        print(f"    severity: {summary['by_severity']}")
        for f in findings:
            mark = " [PRIMARY]" if f["primary"] else ""
            print(f"  {f['severity']:8s} {f['pattern_id']:20s} L{f['line']:<6d} "
                  f"{f['value'][:90]}{mark}")
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
