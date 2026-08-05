"""Resolve a module's import statements into a local-name-to-FQN table.

Most vulnerable symbols are reached through a package's public facade, so getting
``from x.y import z as w`` down to ``x.y.z`` is what makes a call site matchable
against a symbol an advisory names.
"""

from __future__ import annotations

from collections.abc import Sequence

from vulnpath.symbols import RawImport


def _package_of(module_fqn: str, level: int, *, is_package: bool) -> str | None:
    """The package a relative import counts back from.

    ``level=1`` is the module's own package, ``level=2`` its parent, and so on. A
    regular module's own package is everything but its last component; an
    ``__init__.py`` *is* its own package, so nothing gets stripped for it — that
    matches CPython's ``__package__`` in each case (verified against
    ``importlib.util.resolve_name``). Counting past the root returns ``None`` — an
    import that cannot be resolved is better dropped than turned into an FQN that
    matches nothing.
    """
    parts = module_fqn.split(".") if is_package else module_fqn.split(".")[:-1]
    if level > len(parts):
        return None
    remaining = parts[: len(parts) - (level - 1)]
    return ".".join(remaining)


def build_import_table(
    raw: Sequence[RawImport], module_fqn: str, *, is_package: bool = False
) -> dict[str, str]:
    """Local name to fully-qualified name for one module.

    Later bindings overwrite earlier ones, matching Python: the last import of a name
    is the one in effect. ``is_package`` must be set for a module discovered from an
    ``__init__.py`` — its relative-import boundary is one level deeper than a regular
    module of the same ``module_fqn`` would have.
    """
    table: dict[str, str] = {}

    for record in raw:
        if record.name == "*":
            # Binds an unknown set of names; nothing can be recorded.
            continue

        if record.module is None and record.level == 0:
            # `import a.b.c` binds only `a`, and binds it to `a`.
            root = record.name.split(".")[0]
            table[record.alias or root] = record.name if record.alias else root
            continue

        if record.level > 0:
            package = _package_of(module_fqn, record.level, is_package=is_package)
            if package is None:
                continue
            prefix = f"{package}.{record.module}" if record.module else package
        else:
            prefix = record.module or ""

        target = f"{prefix}.{record.name}" if prefix else record.name
        table[record.alias or record.name] = target

    return table
