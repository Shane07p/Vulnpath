"""Find the modules that belong to the scanned project.

Everything else keys on dotted module names, but errors and paths have to be printed
with file locations, so this module owns the mapping in both directions.
"""

from __future__ import annotations

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


def _is_skipped(relative: Path) -> bool:
    return any(part in SKIP_DIRECTORIES or part.startswith(".") for part in relative.parts[:-1])


def discover_modules(project_path: Path, *, include_tests: bool = False) -> list[SourceModule]:
    """Every Python module belonging to the project, sorted by dotted name."""
    root = find_source_root(project_path)
    # Names are counted from ``root``, but only ``project_path`` is walked. When
    # pointed at a package the root is its parent, and walking that would sweep in
    # sibling directories that are not part of this project at all.
    walk_from = project_path if root == project_path.parent else root
    modules: list[SourceModule] = []

    for path in sorted(walk_from.rglob("*.py")):
        relative = path.relative_to(root)
        if _is_skipped(relative):
            continue
        if not include_tests and is_test_path(relative):
            continue
        modules.append(SourceModule(path=path, fqn=module_fqn(path, root)))

    return sorted(modules, key=lambda m: m.fqn)
