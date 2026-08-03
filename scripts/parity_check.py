"""Compare vulnpath's findings against pip-audit on the same fixture.

Parity with an established scanner is the floor this tool has to clear before its own
analysis means anything. Asserting a fixed count would rot the moment a new advisory
is published, so this compares *sets* of CVE identifiers and fails only on a miss — a
CVE pip-audit found that vulnpath did not.

Extra findings on vulnpath's side are reported but do not fail: the two tools can
legitimately diverge as OSV and pip-audit's own database drift apart, and the direction
that matters for a security tool is the one where we report less.

Usage:
    python scripts/parity_check.py <pip-audit.json> <vulnpath.json>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def cve_ids(identifiers: list[str]) -> set[str]:
    return {i for i in identifiers if i.startswith("CVE-")}


def from_pip_audit(payload: dict[str, Any]) -> tuple[set[str], set[str], int]:
    """Returns (cves, packages, raw advisory record count)."""
    cves: set[str] = set()
    packages: set[str] = set()
    records = 0
    for dependency in payload.get("dependencies", []):
        for vuln in dependency.get("vulns", []):
            records += 1
            packages.add(dependency["name"].lower().replace("_", "-"))
            cves |= cve_ids([vuln["id"], *vuln.get("aliases", [])])
    return cves, packages, records


def from_vulnpath(payload: dict[str, Any]) -> tuple[set[str], set[str]]:
    cves: set[str] = set()
    packages: set[str] = set()
    for finding in payload["findings"]:
        advisory = finding["advisory"]
        cves |= cve_ids([advisory["id"], *advisory["aliases"]])
        packages.add(finding["package"]["name"])
    return cves, packages


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2

    pip_audit_payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    vulnpath_payload = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))

    unqueried = vulnpath_payload.get("packages_unqueried", 0)
    if unqueried:
        # An incomplete scan cannot be compared against a complete one. Reporting a
        # mismatch here would blame the code for a network failure, so say so and stop
        # rather than manufacture a result either way.
        print(f"SKIPPED: {unqueried} package(s) could not be queried; OSV was unreachable.")
        print("Parity is unproven for this run, not disproven.")
        return 0

    expected, expected_packages, records = from_pip_audit(pip_audit_payload)
    actual, actual_packages = from_vulnpath(vulnpath_payload)

    missed = expected - actual
    extra = actual - expected

    print(
        f"pip-audit : {records} advisory records, {len(expected)} CVEs, "
        f"{len(expected_packages)} packages"
    )
    print(
        f"vulnpath  : {len(vulnpath_payload['findings'])} findings, {len(actual)} CVEs, "
        f"{len(actual_packages)} packages"
    )
    print()

    if extra:
        print(f"note: {len(extra)} CVE(s) found only by vulnpath: {sorted(extra)}")
    if expected_packages != actual_packages:
        print("note: package sets differ.")
        print(f"  only pip-audit: {sorted(expected_packages - actual_packages)}")
        print(f"  only vulnpath:  {sorted(actual_packages - expected_packages)}")

    if missed:
        print(f"FAIL: {len(missed)} CVE(s) reported by pip-audit and missed by vulnpath:")
        for cve in sorted(missed):
            print(f"  {cve}")
        print()
        print("A missed advisory is a false negative, which this project treats as the")
        print("one failure mode worse than useless. Investigate before merging.")
        return 1

    print(f"PASS: identical CVE set ({len(expected)}), nothing missed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
