"""Resolve a module's import statements into a local-name-to-FQN table.

Most vulnerable symbols are reached through a package's public facade, so getting
``from x.y import z as w`` down to ``x.y.z`` is what makes a call site matchable
against a symbol an advisory names.
"""

from __future__ import annotations

from collections.abc import Sequence

from vulnpath.symbols import RawImport


def _package_of(module_fqn: str, level: int) -> str | None:
    """The package a relative import counts back from.

    ``level=1`` is the module's own package, ``level=2`` its parent, and so on.
    Counting past the root returns ``None`` — an import that cannot be resolved is
    better dropped than turned into an FQN that matches nothing.
    """
    parts = module_fqn.split(".")[:-1]
    if level - 1 > len(parts):
        return None
    remaining = parts[: len(parts) - (level - 1)]
    return ".".join(remaining)


def build_import_table(raw: Sequence[RawImport], module_fqn: str) -> dict[str, str]:
    """Local name to fully-qualified name for one module.

    Later bindings overwrite earlier ones, matching Python: the last import of a name
    is the one in effect.
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
            package = _package_of(module_fqn, record.level)
            if package is None:
                continue
            prefix = f"{package}.{record.module}" if record.module else package
        else:
            prefix = record.module or ""

        target = f"{prefix}.{record.name}" if prefix else record.name
        table[record.alias or record.name] = target

    return table
