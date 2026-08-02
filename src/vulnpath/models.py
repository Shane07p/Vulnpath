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


class Advisory(BaseModel):
    """One OSV advisory, reduced to the fields this tool uses."""

    id: str
    aliases: tuple[str, ...] = ()
    summary: str = ""
    details: str = ""
    severity: Severity = Severity.UNKNOWN
    fixed_versions: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    @property
    def display_id(self) -> str:
        """Prefer a CVE alias — it is what people search for and paste into tickets."""
        for alias in self.aliases:
            if alias.startswith("CVE-"):
                return alias
        return self.id


class Finding(BaseModel):
    """A package in this project matched against an advisory affecting it."""

    package: Package
    advisory: Advisory

    @property
    def sort_key(self) -> tuple[int, int, str]:
        """Highest severity first, then shallowest, then stable by id."""
        return (-severity_rank(self.advisory.severity), self.package.depth, self.advisory.id)


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

    @property
    def is_complete(self) -> bool:
        return self.packages_unqueried == 0

    @property
    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key)
