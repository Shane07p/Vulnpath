"""Domain models.

Everything crossing a stage boundary is one of these. OSV and PyPI responses are
parsed into them at the edge; no raw dicts travel further in.
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, Field

_NORMALISE = re.compile(r"[-_.]+")


def normalise(name: str) -> str:
    """PEP 503 normalised name. ``PyYAML``, ``py_yaml`` and ``Py.YAML`` are one package."""
    return _NORMALISE.sub("-", name).lower()


class Severity(StrEnum):
    """Severity of a finding.

    ``UNKNOWN`` is a real answer, not a placeholder. Many advisories carry no
    machine-readable severity at all, and guessing one would be inventing data.
    """

    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.UNKNOWN: -1,
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


def severity_rank(severity: Severity) -> int:
    """Sort key. ``UNKNOWN`` ranks below ``LOW`` for ordering only — never for filtering."""
    return _SEVERITY_ORDER[severity]


class Package(BaseModel):
    """One resolved package from the lockfile."""

    name: str
    """PEP 503 normalised."""

    version: str
    dependencies: tuple[str, ...] = ()
    """Normalised names of this package's own dependencies."""

    depth: int = 0
    """Hops from the root project. 0 is the project itself, 1 is a direct dependency."""

    is_root: bool = False

    @property
    def is_direct(self) -> bool:
        return self.depth == 1


class AffectedRange(BaseModel):
    """One interval of affected versions, as OSV expresses it.

    A range opens at ``introduced`` and closes at ``fixed`` (exclusive) or
    ``last_affected`` (inclusive). Without these, the only versions known to be safe
    are the ones an advisory explicitly names as fixed — which is not enough to tell
    whether some other release is affected.
    """

    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None


class Advisory(BaseModel):
    """One OSV advisory, reduced to the fields this tool uses."""

    id: str
    aliases: tuple[str, ...] = ()
    summary: str = ""
    details: str = ""
    severity: Severity = Severity.UNKNOWN
    fixed_versions: tuple[str, ...] = ()
    affected_ranges: tuple[AffectedRange, ...] = ()
    references: tuple[str, ...] = ()

    @property
    def display_id(self) -> str:
        """Prefer a CVE alias — it is what people search for and paste into tickets."""
        for alias in self.aliases:
            if alias.startswith("CVE-"):
                return alias
        return self.id


class FixShape(StrEnum):
    """What kind of change closes a finding.

    ``UNKNOWN`` is not a sixth kind of fix — it means classification could not be
    completed, usually because PyPI was unreachable. Reporting ``NO_FIX`` in that
    situation would state that no fix exists on the strength of a network failure.
    """

    DIRECT_BUMP = "direct_bump"
    OVERRIDE = "override"
    LOCKFILE_REFRESH = "lockfile_refresh"
    BACKPORT_EXISTS = "backport_exists"
    NO_FIX = "no_fix"
    UNKNOWN = "unknown"


class BlockingParent(BaseModel):
    """A dependency whose constraint forbids the fixed version."""

    name: str
    constraint: str

    upgrade_to: str | None = None
    """Newest release of this parent whose constraint permits the fix, if one exists.

    Upgrading the parent is nearly always better advice than forcing an override,
    because an override pins a version the parent never declared support for.
    """


class Fix(BaseModel):
    """How a finding can be resolved."""

    shape: FixShape
    target_version: str | None = None
    command: str | None = None
    reason: str = ""
    blocking_parents: tuple[BlockingParent, ...] = ()

    @property
    def is_actionable(self) -> bool:
        """True when the tool can name a specific version to move to."""
        return self.shape not in {FixShape.NO_FIX, FixShape.UNKNOWN}


_VERDICT_ORDER: dict[str, int] = {"reachable": 0, "unknown": 1, "not_reachable": 2}
"""Ranking, not severity. An unknown verdict sits between the two certainties, because
it needs looking at but has not been shown to matter."""


class Finding(BaseModel):
    """A package in this project matched against an advisory affecting it."""

    package: Package
    advisory: Advisory

    fix: Fix | None = None
    """Set by classification, which runs after advisory matching."""

    verdict: str = "unknown"
    """Whether the project's code reaches this package: reachable, not_reachable, unknown."""

    confidence: str = "low"
    reachability_reason: str = ""
    path: tuple[str, ...] = ()
    """The call path found, as evidence. Empty unless the verdict is reachable."""

    @property
    def is_suppressible(self) -> bool:
        """Whether this finding can be safely deprioritised.

        Only a proven negative qualifies. An unknown verdict never does — that is the
        whole point of keeping the two apart.
        """
        return self.verdict == "not_reachable"

    @property
    def sort_key(self) -> tuple[int, int, int, int, str]:
        """Ranked so the top of the list is actionable and the bottom is ignorable.

        Verdict outranks severity deliberately. A critical advisory in code nothing
        imports is less urgent than a medium one on a live call path, and sorting by
        severity first buries the finding that matters under the ones that do not —
        which is the alert fatigue this tool exists to remove.

        Within a reachable finding, one with a known fix comes before one without: both
        need attention, but only one can be acted on now.
        """
        return (
            _VERDICT_ORDER.get(self.verdict, _VERDICT_ORDER["unknown"]),
            0 if (self.fix is not None and self.fix.is_actionable) else 1,
            -severity_rank(self.advisory.severity),
            self.package.depth,
            self.advisory.id,
        )


class ScanResult(BaseModel):
    """Everything one scan produced."""

    project_path: str
    findings: list[Finding] = Field(default_factory=list)
    packages_scanned: int = 0
    offline: bool = False
    advisories_from_cache: int = 0

    packages_unqueried: int = 0
    """Packages whose advisories could not be retrieved.

    Zero findings and incomplete coverage are different results, and a machine reading
    ``--format json`` has no other way to tell them apart. Non-zero means this scan does
    not prove anything about those packages.
    """

    fix_lookups_failed: int = 0
    """PyPI lookups that could not be completed, leaving fixes classified UNKNOWN."""

    reachability_analysed: bool = False
    """Whether a call graph was built. False means every verdict is an unknown by default."""

    graph_nodes: int = 0
    dependency_modules_parsed: int = 0
    unparsed_source_files: int = 0
    """Files no analysis ran over. Any path through them is unproven, not absent."""

    @property
    def is_complete(self) -> bool:
        return self.packages_unqueried == 0

    @property
    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key)
