"""Scan orchestration: lockfile in, findings out.

Kept apart from the CLI so the pipeline can be exercised without a parser, and so
``cli.py`` stays a description of the command surface rather than a place logic hides.
"""

from __future__ import annotations

from pathlib import Path

from vulnpath.environment import EnvironmentError_, find_site_packages, installed_distributions
from vulnpath.lockfile import load_lockfile
from vulnpath.models import Finding, ScanResult, Severity, severity_rank
from vulnpath.osv import OsvClient


def passes_severity_floor(severity: Severity, floor: Severity | None) -> bool:
    """``UNKNOWN`` always passes.

    Filtering out a finding whose severity was never published would hide a real
    vulnerability behind a data gap. Absent information is never treated as low risk.
    """
    if floor is None or severity is Severity.UNKNOWN:
        return True
    return severity_rank(severity) >= severity_rank(floor)


def environment_drift(project_path: Path, python: Path | None) -> list[str]:
    """Ways the installed environment disagrees with the lockfile.

    Advisory matching runs off the lockfile, so drift is a warning rather than an
    error — but a stale environment means later reachability analysis would read the
    wrong source, so it is worth saying out loud now.
    """
    try:
        site_packages = find_site_packages(project_path, python)
    except EnvironmentError_ as exc:
        return [str(exc).splitlines()[0]]

    installed = installed_distributions(site_packages)
    if not installed:
        return [f"{site_packages} contains no installed distributions."]

    graph = load_lockfile(project_path)
    drift: list[str] = []
    for package in graph.scannable:
        actual = installed.get(package.name)
        if actual is None:
            drift.append(f"{package.name} is in the lockfile but not installed.")
        elif actual != package.version:
            drift.append(f"{package.name}: lockfile says {package.version}, installed is {actual}.")
    return drift


def run_scan(
    project_path: Path,
    *,
    offline: bool = False,
    severity_floor: Severity | None = None,
    cache_dir: Path | None = None,
) -> ScanResult:
    """Resolve the project's packages and match them against OSV advisories."""
    graph = load_lockfile(project_path)
    packages = graph.scannable

    client = OsvClient(cache_dir, offline=offline)
    advisories = client.advisories_for(packages)

    findings: list[Finding] = []
    for package in packages:
        for advisory in advisories.get(package.name, []):
            if passes_severity_floor(advisory.severity, severity_floor):
                findings.append(Finding(package=package, advisory=advisory))

    return ScanResult(
        project_path=str(project_path),
        findings=findings,
        packages_scanned=len(packages),
        offline=offline,
        advisories_from_cache=client.cache_hits,
    )
