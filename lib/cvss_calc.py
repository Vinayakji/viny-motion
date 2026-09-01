#!/usr/bin/env python3
"""
cvss_calc.py - CVSS 3.1 and 4.0 scoring engine
Usage:
  cvss_calc.py 3.1 "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  cvss_calc.py 4.0 "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
  cvss_calc.py severity 7.5
  cvss_calc.py build N L N N U H H H
  cvss_calc.py batch findings.json
"""

import sys
import json

try:
    from cvss import CVSS3, CVSS4
except ImportError:
    print("ERROR: cvss package not installed. Run: pip3 install --break-system-packages cvss", file=sys.stderr)
    sys.exit(1)


def calc_31(vector: str) -> dict:
    """Calculate CVSS 3.1 score from vector string."""
    # Add prefix if missing
    if not vector.startswith("CVSS:"):
        vector = "CVSS:3.1/" + vector
    v = CVSS3(vector)
    scores = v.scores()
    severities = v.severities()
    return {
        "score": scores[0],
        "severity": severities[0],
        "vector": v.vector,
    }


def calc_40(vector: str) -> dict:
    """Calculate CVSS 4.0 score from vector string."""
    # Add prefix if missing
    if not vector.startswith("CVSS:"):
        vector = "CVSS:4.0/" + vector
    v = CVSS4(vector)
    scores = v.scores()
    severities = v.severities()
    return {
        "score": scores[0],
        "severity": severities[0],
        "vector": v.vector,
    }


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    return "INFO"


def build_31(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"):
    return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"


def batch_score(findings_path: str):
    """Score all findings in a findings.json file."""
    with open(findings_path) as f:
        data = json.load(f)

    updated = 0
    for finding in data.get("findings", []):
        # Auto-compute CVSS if vector present but score missing/wrong
        vec = finding.get("cvss_vector", "")
        if vec and "3.1" in vec:
            result = calc_31(vec)
            finding["cvss"] = result["score"]
            finding["cvss_vector"] = result["vector"]
            finding["cvss_version"] = "3.1"
            finding["severity"] = result["severity"]
            updated += 1
        elif vec and "4.0" in vec:
            result = calc_40(vec)
            finding["cvss"] = result["score"]
            finding["cvss_vector"] = result["vector"]
            finding["cvss_version"] = "4.0"
            finding["severity"] = result["severity"]
            updated += 1

    # Write back
    with open(findings_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Updated {updated} findings with CVSS scores")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd in ("3.1", "31"):
        vector = sys.argv[2] if len(sys.argv) > 2 else "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        result = calc_31(vector)
        print(f"{result['score']:.1f}")

    elif cmd in ("4.0", "40"):
        vector = sys.argv[2] if len(sys.argv) > 2 else "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        result = calc_40(vector)
        print(f"{result['score']:.1f}")

    elif cmd == "severity":
        score = float(sys.argv[2]) if len(sys.argv) > 2 else 0.0
        print(severity_from_score(score))

    elif cmd == "build":
        args = sys.argv[2:]
        vector = build_31(*args)
        print(vector)

    elif cmd == "batch":
        path = sys.argv[2] if len(sys.argv) > 2 else "findings/findings.json"
        batch_score(path)

    elif cmd == "detail":
        vector = sys.argv[2]
        result = calc_31(vector)
        print(json.dumps(result, indent=2))

    else:
        print(__doc__)


if __name__ == "__main__":
    main()
