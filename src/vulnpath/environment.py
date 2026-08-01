"""Locate the scanned project's installed packages.

Vulnpath runs inside its own virtual environment. The project being scanned has a
different one. Resolving against the wrong environment produces answers that are
confidently wrong, so this module never falls back to the interpreter running
vulnpath — it fails loudly instead.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


class EnvironmentError_(Exception):
    """No usable environment was found for the scanned project."""


def _site_packages_under(venv: Path) -> Path | None:
    """``<venv>/Lib/site-packages`` on Windows, ``<venv>/lib/pythonX.Y/site-packages`` elsewhere."""
    windows = venv / "Lib" / "site-packages"
    if windows.is_dir():
        return windows
    for candidate in sorted((venv / "lib").glob("python*/site-packages")):
        if candidate.is_dir():
            return candidate
    return None


def find_site_packages(project_path: Path, override: Path | None = None) -> Path:
    """Resolve the site-packages directory belonging to ``project_path``.

    Order:

    1. ``--python`` override, if given
    2. ``<project_path>/.venv`` — uv's convention, covers nearly every project
    3. ``$VIRTUAL_ENV``, but only when it lives inside the project being scanned

    Never the environment vulnpath itself is running in. A silent fallback there
    would resolve imports against this tool's dependencies and report reachability
    for code the user does not have.
    """
    if override is not None:
        resolved = _site_packages_under(override) or (
            override if override.name == "site-packages" and override.is_dir() else None
        )
        if resolved is None:
            raise EnvironmentError_(
                f"{override} is not a virtual environment or a site-packages directory."
            )
        return resolved

    project_venv = project_path / ".venv"
    if project_venv.is_dir():
        resolved = _site_packages_under(project_venv)
        if resolved is not None:
            return resolved

    active = os.environ.get("VIRTUAL_ENV")
    if active:
        active_path = Path(active).resolve()
        if active_path.is_relative_to(project_path.resolve()):
            resolved = _site_packages_under(active_path)
            if resolved is not None:
                return resolved

    raise EnvironmentError_(
        f"No virtual environment found for {project_path}.\n"
        f"Expected {project_venv}. Run `uv sync` there, or pass --python <path-to-venv>.\n"
        f"(Refusing to fall back to vulnpath's own environment at {sys.prefix} — "
        "results would describe the wrong project.)"
    )


def installed_distributions(site_packages: Path) -> dict[str, str]:
    """Map normalised package name to installed version, read from ``*.dist-info``.

    Used to confirm the lockfile matches what is on disk. A lockfile entry with no
    installed distribution means the environment is stale.
    """
    from vulnpath.models import normalise

    found: dict[str, str] = {}
    for dist_info in site_packages.glob("*.dist-info"):
        stem = dist_info.name.removesuffix(".dist-info")
        name, _, version = stem.rpartition("-")
        if name and version:
            found[normalise(name)] = version
    return found
