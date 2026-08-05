"""Scan orchestration: lockfile in, findings out.

Kept apart from the CLI so the pipeline can be exercised without a parser, and so
``cli.py`` stays a description of the command surface rather than a place logic hides.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from vulnpath.environment import EnvironmentError_, find_site_packages, installed_distributions
from vulnpath.fixshape import FixContext, classify
from vulnpath.lockfile import DependencyGraph, load_lockfile
from vulnpath.models import Advisory, Finding, Package, ScanResult, Severity, severity_rank
from vulnpath.osv import OsvClient
from vulnpath.pypi import PyPIClient, constraint_on
from vulnpath.versions import parse_specifier, parse_version, satisfies


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


def build_fix_context(
    graph: DependencyGraph,
    package: Package,
    advisory: Advisory,
    client: PyPIClient,
) -> FixContext:
    """Gather every fact classification needs. All of its I/O happens here.

    Parent constraints come from PyPI rather than the lockfile, because uv.lock
    records dependency edges without specifiers.
    """
    parents: dict[str, str] = {}

    for parent_name in sorted(graph.parents_of(package.name)):
        parent = graph.get(parent_name)
        if parent is None or parent.is_root:
            continue
        requires = client.requires_dist(parent.name, parent.version)
        if requires is None:
            continue
        constraint = constraint_on(requires, package.name)
        if constraint is not None:
            parents[parent.name] = constraint

    return FixContext(
        package=package,
        advisory=advisory,
        declared=graph.declared.get(package.name),
        parents=parents,
        released=client.releases(package.name),
    )


def find_parent_upgrades(
    package: Package,
    target: str,
    parents: dict[str, str],
    client: PyPIClient,
) -> dict[str, str]:
    """For each blocking parent, its newest release whose constraint permits ``target``.

    Only the newest release is checked. Walking every release of every parent would
    multiply the request count by the size of their release history to answer a
    question that is decided at the head.
    """
    wanted = parse_version(target)
    if wanted is None:
        return {}

    upgrades: dict[str, str] = {}
    for parent_name, raw_constraint in parents.items():
        specifier = parse_specifier(raw_constraint)
        if specifier is not None and satisfies(wanted, specifier):
            continue

        releases = client.releases(parent_name)
        if not releases:
            continue
        newest = max(
            (v for raw in releases if (v := parse_version(raw)) is not None),
            default=None,
        )
        if newest is None:
            continue

        requires = client.requires_dist(parent_name, str(newest))
        if requires is None:
            continue
        newest_constraint = constraint_on(requires, package.name)
        newest_specifier = parse_specifier(newest_constraint) if newest_constraint else None
        if satisfies(wanted, newest_specifier):
            upgrades[parent_name] = str(newest)
    return upgrades


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

    pypi = PyPIClient(cache_dir, offline=offline)

    findings: list[Finding] = []
    for package in packages:
        for advisory in advisories.get(package.name, []):
            if not passes_severity_floor(advisory.severity, severity_floor):
                continue

            context = build_fix_context(graph, package, advisory, pypi)
            fix = classify(context)

            # Parent upgrades cost a request each, so they are looked up only once a
            # parent is known to be blocking, then classification is redone with them.
            if fix.blocking_parents and fix.target_version:
                upgrades = find_parent_upgrades(package, fix.target_version, context.parents, pypi)
                if upgrades:
                    fix = classify(replace(context, parent_upgrades=upgrades))

            findings.append(Finding(package=package, advisory=advisory, fix=fix))

    return ScanResult(
        project_path=str(project_path),
        findings=findings,
        packages_scanned=len(packages),
        offline=offline,
        advisories_from_cache=client.cache_hits,
        packages_unqueried=client.packages_unqueried,
        fix_lookups_failed=pypi.lookups_failed,
    )
