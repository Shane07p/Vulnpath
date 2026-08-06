"""What is installed in an environment, and where its source lives.

``environment.py`` answers where the environment is; this answers what is in it.

The mapping from a distribution to the names it can be imported under is not derivable
from the distribution name. ``PyYAML`` imports as ``yaml``, ``Pillow`` as ``PIL``,
``beautifulsoup4`` as ``bs4``. Only the installed metadata knows.
"""

from __future__ import annotations

import csv
from pathlib import Path, PurePosixPath

from vulnpath.models import normalise


def _names_from_record(dist_info: Path) -> set[str]:
    """Import names taken from the manifest of installed files.

    The reliable source. ``top_level.txt`` is optional and increasingly absent — of five
    packages checked in this project's own environment, only one still shipped it — but
    every wheel installation writes a RECORD.

    A path's first component is a package directory, and a lone top-level ``.py`` file is
    a single-module distribution. Entries for the ``.dist-info`` directory itself, and
    anything installed outside site-packages, are not import names.
    """
    record = dist_info / "RECORD"
    try:
        rows = csv.reader(record.read_text(encoding="utf-8").splitlines())
    except (OSError, UnicodeDecodeError):
        return set()

    names: set[str] = set()
    for row in rows:
        if not row or not row[0]:
            continue
        parts = PurePosixPath(row[0]).parts
        if not parts:
            continue
        first = parts[0]
        if first.endswith(".dist-info") or first == ".." or first.endswith(".data"):
            continue
        if len(parts) > 1:
            names.add(first)
        elif first.endswith(".py"):
            names.add(first.removesuffix(".py"))
    return names


def _names_from_top_level(dist_info: Path) -> set[str]:
    """The legacy declaration, used when a distribution still ships one."""
    top_level = dist_info / "top_level.txt"
    try:
        return {
            line.strip()
            for line in top_level.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
    except (OSError, UnicodeDecodeError):
        return set()


def import_names(site_packages: Path) -> dict[str, frozenset[str]]:
    """Normalised distribution name to the import names it installs."""
    mapping: dict[str, frozenset[str]] = {}
    for dist_info in sorted(site_packages.glob("*.dist-info")):
        distribution = dist_info.name.removesuffix(".dist-info").rsplit("-", 1)[0]
        names = _names_from_record(dist_info) or _names_from_top_level(dist_info)
        if names:
            mapping[normalise(distribution)] = frozenset(names)
    return mapping


def owning_distribution(module_fqn: str, names: dict[str, frozenset[str]]) -> str | None:
    """Which distribution provides a module, e.g. ``yaml.loader`` -> ``pyyaml``.

    Matched on the top-level import name, since that is what a distribution claims.
    """
    root = module_fqn.split(".", 1)[0]
    for distribution, provided in names.items():
        if root in provided:
            return distribution
    return None


def find_module_file(site_packages: Path, module_fqn: str) -> Path | None:
    """The file defining a module, or ``None`` if it is not importable from here.

    A missing file is an ordinary outcome rather than an error: the standard library and
    compiled extensions both land here, and both are genuine leaves for this analysis.
    """
    relative = Path(*module_fqn.split("."))

    module = site_packages / relative.with_suffix(".py")
    if module.is_file():
        return module

    package = site_packages / relative / "__init__.py"
    if package.is_file():
        return package

    return None
