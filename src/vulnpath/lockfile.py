"""Parse ``uv.lock`` into a dependency graph.

The lockfile, never the manifest. ``pyproject.toml`` records what was asked for;
``uv.lock`` records what the resolver actually produced, which is what is installed
and therefore what can be vulnerable.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from vulnpath.models import Package, normalise

SUPPORTED_LOCK_VERSION = 1


class LockfileError(Exception):
    """The lockfile is missing, unreadable, or a format this build does not handle."""


@dataclass(frozen=True)
class DependencyGraph:
    """Resolved packages plus the edges between them.

    A plain dict of adjacency, not a graph library. The package graph is small and
    needs custom node data. The call graph this tool will build over source symbols is a
    different shape entirely, and is where a graph library earns its place.
    """

    packages: dict[str, Package]
    root: str | None
    _parents: dict[str, set[str]] = field(default_factory=dict)
    extra_versions: tuple[Package, ...] = ()
    """Additional resolved versions of a package already in ``packages``.

    A forked resolution — one lockfile covering several Python versions or platforms —
    emits multiple ``[[package]]`` entries for the same name at different versions.
    They are all installed somewhere, so they are all scanned. Keeping them out of
    ``packages`` leaves graph traversal keyed by name, which is what dependency edges
    reference.
    """

    def parents_of(self, name: str) -> set[str]:
        """Packages that depend on ``name``. Empty for the root project."""
        return self._parents.get(normalise(name), set())

    def get(self, name: str) -> Package | None:
        return self.packages.get(normalise(name))

    @property
    def scannable(self) -> list[Package]:
        """Every resolved package except the project itself, including forked versions."""
        return [p for p in self.packages.values() if not p.is_root] + list(self.extra_versions)


def _find_root(raw_packages: list[dict[str, object]]) -> str | None:
    """The project being scanned, identified by a local source rather than a registry."""
    for entry in raw_packages:
        source = entry.get("source")
        if isinstance(source, dict) and ({"virtual", "editable"} & source.keys()):
            name = entry.get("name")
            if isinstance(name, str):
                return normalise(name)
    return None


def _dependency_names(entry: dict[str, object]) -> tuple[str, ...]:
    raw = entry.get("dependencies")
    if not isinstance(raw, list):
        return ()
    names: list[str] = []
    for dep in raw:
        if isinstance(dep, dict):
            name = dep.get("name")
            if isinstance(name, str):
                names.append(normalise(name))
    return tuple(names)


def _assign_depths(packages: dict[str, Package], root: str | None) -> dict[str, Package]:
    """Breadth-first from the root, so depth is the shortest path to the project.

    A package reachable both directly and transitively is direct — the shortest path
    is the one that determines whether a direct version bump can fix it.
    """
    if root is None or root not in packages:
        return packages

    depths: dict[str, int] = {root: 0}
    queue: list[str] = [root]
    while queue:
        current = queue.pop(0)
        for dep in packages[current].dependencies:
            if dep in packages and dep not in depths:
                depths[dep] = depths[current] + 1
                queue.append(dep)

    return {
        name: pkg.model_copy(update={"depth": depths.get(name, -1)})
        for name, pkg in packages.items()
    }


def load_lockfile(project_path: Path) -> DependencyGraph:
    """Read ``<project_path>/uv.lock`` and build the dependency graph.

    Raises ``LockfileError`` with an actionable message rather than letting a
    ``KeyError`` escape — this is the first thing a new user hits.
    """
    lock_path = project_path / "uv.lock"
    if not lock_path.is_file():
        raise LockfileError(
            f"No uv.lock in {project_path}. "
            "Run `uv lock` there first, or point vulnpath at a project that has one."
        )

    try:
        raw = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise LockfileError(f"{lock_path} is not valid TOML: {exc}") from exc

    version = raw.get("version")
    if version != SUPPORTED_LOCK_VERSION:
        raise LockfileError(
            f"{lock_path} is lock version {version!r}; this build understands "
            f"version {SUPPORTED_LOCK_VERSION}."
        )

    raw_packages = raw.get("package")
    if not isinstance(raw_packages, list):
        raise LockfileError(f"{lock_path} has no [[package]] entries.")

    root = _find_root(raw_packages)

    packages: dict[str, Package] = {}
    forked: list[Package] = []
    for entry in raw_packages:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        raw_version = entry.get("version")
        if not isinstance(name, str) or not isinstance(raw_version, str):
            continue
        key = normalise(name)
        package = Package(
            name=key,
            version=raw_version,
            dependencies=_dependency_names(entry),
            is_root=key == root,
        )
        if key in packages:
            # A forked resolution lists the same package at several versions. Keeping
            # only the last one seen would drop a genuinely installed version from the
            # scan entirely — and it is often the older, vulnerable one.
            forked.append(package)
        else:
            packages[key] = package

    if not packages:
        raise LockfileError(f"{lock_path} contains no usable package entries.")

    packages = _assign_depths(packages, root)
    forked = [
        p.model_copy(update={"depth": packages[p.name].depth}) for p in forked if p.name in packages
    ]

    parents: dict[str, set[str]] = {}
    for pkg in packages.values():
        for dep in pkg.dependencies:
            parents.setdefault(dep, set()).add(pkg.name)

    return DependencyGraph(
        packages=packages,
        root=root,
        _parents=parents,
        extra_versions=tuple(forked),
    )
