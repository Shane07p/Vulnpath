"""Find the modules that belong to the scanned project.

Everything else keys on dotted module names, but errors and paths have to be printed
with file locations, so this module owns the mapping in both directions.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRECTORIES = frozenset(
    {".venv", "venv", "env", "site-packages", "build", "dist", "__pycache__", "node_modules"}
)
"""Never source, whatever they contain. Dot-directories are skipped separately."""

TEST_DIRECTORY_NAMES = frozenset({"test", "tests", "testing"})


@dataclass(frozen=True)
class SourceModule:
    """One Python file belonging to the project."""

    path: Path
    fqn: str


def is_test_path(path: Path) -> bool:
    """Whether a path is test code.

    Matched on whole path components, never substrings: ``latest.py`` and
    ``contest/`` are ordinary source and excluding them would silently drop real
    call paths.
    """
    if any(part in TEST_DIRECTORY_NAMES for part in path.parts[:-1]):
        return True
    name = path.name
    return name == "conftest.py" or name.startswith("test_") or name.endswith("_test.py")


def find_source_root(project_path: Path) -> Path:
    """Where dotted names start counting from.

    A ``src/`` layout roots at ``src``, so ``src/app/main.py`` is ``app.main`` rather
    than ``src.app.main`` — the latter is not importable and would never match an
    advisory.

    Pointing straight at a package roots at its *parent*, so ``sample_app/core.py``
    stays ``sample_app.core``. Rooting inside the package would name it ``core``,
    which no import statement anywhere would resolve to.
    """
    if (project_path / "__init__.py").is_file():
        return project_path.parent
    src = project_path / "src"
    return src if src.is_dir() else project_path


def module_fqn(path: Path, root: Path) -> str:
    """Dotted name for a file, relative to the source root."""
    relative = path.relative_to(root)
    parts = list(relative.parts)
    if parts[-1] == "__init__.py":
        parts.pop()
    else:
        parts[-1] = parts[-1].removesuffix(".py")
    return ".".join(parts)


def _is_skip_directory(name: str) -> bool:
    """A directory name that must never be descended into. Dot-directories included."""
    return name in SKIP_DIRECTORIES or name.startswith(".")


def _walk_python_files(start: Path) -> Iterator[Path]:
    """Every ``.py`` file under ``start``, pruning skip directories as we descend.

    ``rglob`` has no way to say "don't go in there" — it walks the entire tree and
    only lets you discard matches afterwards. For a project with a checked-in
    ``.venv`` or a vendored ``node_modules`` that difference is tens of thousands of
    files stat'd for nothing. Removing skipped names from ``dirnames`` in place, on
    a top-down walk, means they are never opened at all.
    """
    for dirpath, dirnames, filenames in start.walk():
        dirnames[:] = [name for name in dirnames if not _is_skip_directory(name)]
        for filename in filenames:
            if filename.endswith(".py"):
                yield dirpath / filename


def _discover_top_level_tests(project_path: Path, src_root: Path) -> Iterator[SourceModule]:
    """Top-level ``tests/`` alongside a ``src/`` layout.

    ``find_source_root`` roots a ``src/`` project at ``src``, so the walk that
    starts there structurally cannot see ``project_path/tests`` — it is not under
    ``src`` at all, so it is never filtered out either; it is simply never visited.
    This walks ``project_path`` separately, skipping ``src`` itself (already
    covered by the main walk) and the usual skip set, keeping only files
    ``is_test_path`` recognises.

    Dotted names here are counted from ``project_path``, not ``src_root``: these
    files live outside the source root, and ``module_fqn``'s ``relative_to`` would
    raise on a path that isn't below the root it's given.
    """
    for dirpath, dirnames, filenames in project_path.walk():
        dirnames[:] = [
            name
            for name in dirnames
            if not _is_skip_directory(name)
            and not (dirpath == project_path and name == src_root.name)
        ]
        for filename in filenames:
            if not filename.endswith(".py"):
                continue
            path = dirpath / filename
            relative = path.relative_to(project_path)
            if is_test_path(relative):
                yield SourceModule(path=path, fqn=module_fqn(path, project_path))


def discover_modules(project_path: Path, *, include_tests: bool = False) -> list[SourceModule]:
    """Every Python module belonging to the project, sorted by dotted name."""
    root = find_source_root(project_path)
    # Names are counted from ``root``, but only ``project_path`` is walked. When
    # pointed at a package the root is its parent, and walking that would sweep in
    # sibling directories that are not part of this project at all.
    walk_from = project_path if root == project_path.parent else root
    modules: list[SourceModule] = []

    for path in _walk_python_files(walk_from):
        relative = path.relative_to(root)
        if not include_tests and is_test_path(relative):
            continue
        modules.append(SourceModule(path=path, fqn=module_fqn(path, root)))

    # A src/ layout's root is src itself, which structurally excludes a
    # conventional top-level tests/ directory — it is never on this walk.
    if include_tests and root == project_path / "src":
        modules.extend(_discover_top_level_tests(project_path, root))

    return sorted(modules, key=lambda m: m.fqn)
