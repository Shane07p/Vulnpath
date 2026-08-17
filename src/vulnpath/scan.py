"""Scan orchestration: lockfile in, findings out.

Kept apart from the CLI so the pipeline can be exercised without a parser, and so
``cli.py`` stays a description of the command surface rather than a place logic hides.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

from vulnpath.callgraph import build_call_graph
from vulnpath.environment import EnvironmentError_, find_site_packages, installed_distributions
from vulnpath.expand import expand_into_dependencies
from vulnpath.extract import SymbolExtractor
from vulnpath.fixshape import FixContext, classify
from vulnpath.installed import import_names
from vulnpath.lockfile import DependencyGraph, load_lockfile
from vulnpath.models import Advisory, Finding, Package, ScanResult, Severity, severity_rank
from vulnpath.osv import OsvClient
from vulnpath.patches import PatchFetcher
from vulnpath.pypi import PyPIClient, constraint_on
from vulnpath.reachability import ReachabilityIndex
from vulnpath.verify import Verification, verify_symbols
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


@dataclass(frozen=True)
class Analysis:
    """What reachability analysis produced, or an empty one if it could not run.

    ``site_packages`` rides along because symbol verification reads the same installed
    source the graph was built from. Verifying against a different environment than the
    one analysed would check a symbol's existence in code that was never traversed.
    """

    index: ReachabilityIndex | None = None
    import_names: dict[str, frozenset[str]] = field(default_factory=dict)
    site_packages: Path | None = None
    graph_nodes: int = 0
    dependency_modules_parsed: int = 0
    unparsed_files: int = 0


def analyse_reachability(project_path: Path, python: Path | None) -> Analysis:
    """Build the call graph and expand it into the project's installed dependencies.

    Returns nothing usable when there is no environment to read. That is a gap, not a
    clean result: without dependency source, no verdict about reaching into a package
    can be trusted, so callers leave every finding unknown rather than assuming safety.
    """
    try:
        site_packages = find_site_packages(project_path, python)
    except EnvironmentError_:
        return Analysis()

    call_graph = build_call_graph(project_path)
    expansion = expand_into_dependencies(call_graph, site_packages)

    return Analysis(
        index=ReachabilityIndex(call_graph.graph, expansion_complete=expansion.is_complete),
        import_names=import_names(site_packages),
        site_packages=site_packages,
        graph_nodes=call_graph.graph.number_of_nodes(),
        dependency_modules_parsed=expansion.modules_parsed,
        unparsed_files=len(call_graph.unparsed_files) + len(expansion.unparsed_files),
    )


def vulnerable_symbols(
    advisory: Advisory,
    package: Package,
    names: frozenset[str],
    extractor: SymbolExtractor,
    patches: PatchFetcher,
    site_packages: Path,
) -> Verification:
    """The symbols this advisory names, kept only where installed source has them.

    Extraction failing and an advisory naming nothing specific both arrive here as no
    symbols, and both mean the same thing downstream: there is nothing to narrow with, so
    the package-level verdict stands. Neither is evidence the advisory does not apply.
    """
    # The diff is fetched only when the model is actually going to be asked. A cached
    # extraction answers without it, and paying for a patch to feed a request that never
    # happens is a round trip for nothing.
    diff = patches.diff_for(advisory.fix_commits) if extractor.is_available else ""

    extracted = extractor.symbols_for(advisory, package.name, names, diff)
    if not extracted:
        return Verification(verified=(), dropped=())
    return verify_symbols(extracted, site_packages)


def run_scan(
    project_path: Path,
    *,
    offline: bool = False,
    severity_floor: Severity | None = None,
    cache_dir: Path | None = None,
    python: Path | None = None,
) -> ScanResult:
    """Resolve the project's packages and match them against OSV advisories."""
    graph = load_lockfile(project_path)
    packages = graph.scannable

    client = OsvClient(cache_dir, offline=offline)
    advisories = client.advisories_for(packages)

    pypi = PyPIClient(cache_dir, offline=offline)
    analysis = analyse_reachability(project_path, python)
    extractor = SymbolExtractor(cache_dir, offline=offline)
    patches = PatchFetcher(cache_dir, offline=offline)

    symbols_dropped = 0
    advisories_narrowed = 0

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

            finding = Finding(package=package, advisory=advisory, fix=fix)

            if analysis.index is not None:
                names = analysis.import_names.get(package.name, frozenset())

                # Symbol extraction is only worth its cost where a graph exists to match
                # against. Without one every verdict is unknown regardless, so asking a
                # model which function is vulnerable would answer a question nothing
                # downstream can use.
                symbols: tuple[str, ...] = ()
                if analysis.site_packages is not None:
                    verification = vulnerable_symbols(
                        advisory, package, names, extractor, patches, analysis.site_packages
                    )
                    symbols = verification.verified
                    symbols_dropped += len(verification.dropped)
                    advisories_narrowed += 1 if symbols else 0

                result = analysis.index.analyse_symbols(names, symbols)
                finding.vulnerable_symbols = symbols
                finding.verdict = result.verdict.value
                finding.confidence = result.confidence.value
                finding.reachability_reason = result.reason
                finding.path = result.path

            findings.append(finding)

    return ScanResult(
        project_path=str(project_path),
        findings=findings,
        packages_scanned=len(packages),
        offline=offline,
        advisories_from_cache=client.cache_hits,
        packages_unqueried=client.packages_unqueried,
        fix_lookups_failed=pypi.lookups_failed,
        reachability_analysed=analysis.index is not None,
        graph_nodes=analysis.graph_nodes,
        dependency_modules_parsed=analysis.dependency_modules_parsed,
        unparsed_source_files=analysis.unparsed_files,
        advisories_narrowed=advisories_narrowed,
        symbols_dropped=symbols_dropped,
        symbol_extraction_available=extractor.is_configured,
        extractions_failed=extractor.extractions_failed,
        quota_exhausted=extractor.quota_exhausted,
    )
