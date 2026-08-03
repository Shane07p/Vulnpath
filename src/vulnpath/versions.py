"""PEP 440 version handling.

Every version comparison in this tool goes through here. Comparing versions as
strings gets ``1.0`` versus ``1.0.0`` wrong and orders ``1.10`` before ``1.9``, and
either mistake turns into wrong upgrade advice.

Parsing returns ``None`` instead of raising. Version strings arrive from OSV, PyPI
and lockfiles, and a malformed one — a commit SHA from a GIT range, say — must
degrade a single finding rather than end the scan.
"""

from __future__ import annotations

from collections.abc import Sequence

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

__all__ = [
    "SpecifierSet",
    "Version",
    "parse_specifier",
    "parse_version",
    "satisfies",
    "select_target",
]


def parse_version(raw: str) -> Version | None:
    try:
        return Version(raw)
    except InvalidVersion:
        return None


def parse_specifier(raw: str) -> SpecifierSet | None:
    try:
        return SpecifierSet(raw)
    except InvalidSpecifier:
        return None


def satisfies(version: Version, specifier: SpecifierSet | None) -> bool:
    """An absent specifier means unconstrained, so everything satisfies it."""
    if specifier is None:
        return True
    return specifier.contains(version, prereleases=True)


def select_target(installed: Version, candidates: Sequence[Version]) -> Version | None:
    """The version to upgrade to: lowest fix on the installed major line, else lowest fix.

    Staying on the installed major line matters more than being newest. A user on
    1.26.5 wants 1.26.17, not 2.0.6 — the backport closes the advisory without a major
    upgrade, and it is far less likely to collide with a parent's constraint.
    """
    upgrades = sorted(v for v in candidates if v > installed)
    if not upgrades:
        return None

    same_line = [v for v in upgrades if v.major == installed.major]
    return same_line[0] if same_line else upgrades[0]
