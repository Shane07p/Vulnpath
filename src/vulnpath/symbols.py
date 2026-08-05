"""What one file says: its definitions, its calls, its imports.

Purely syntactic and strictly per-file. Nothing here resolves a name — that needs
every module at once and lives in ``callgraph``. Keeping the two apart is what makes
this testable against a single file.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

DYNAMIC_BUILTINS = frozenset({"getattr", "setattr", "eval", "exec", "__import__", "compile"})
"""Calls whose target cannot be known statically."""

DYNAMIC_ATTRIBUTES = frozenset({"import_module", "__import__"})
"""Dotted calls with these tails, e.g. ``importlib.import_module``."""


@dataclass(frozen=True)
class Definition:
    """Something this module defines. ``kind`` is module, class, function or method."""

    fqn: str
    kind: str
    line: int


@dataclass(frozen=True)
class CallSite:
    """A call, attributed to the definition whose body contains it."""

    caller: str
    name: str
    """The dotted name exactly as written, e.g. ``yaml.load`` or ``read_settings``."""

    line: int


@dataclass(frozen=True)
class RawImport:
    """One imported name, unresolved.

    ``import yaml`` gives ``module=None, name="yaml"``. ``from json import loads as
    parse_json`` gives ``module="json", name="loads", alias="parse_json"``. ``level``
    counts the leading dots of a relative import.
    """

    module: str | None
    name: str
    alias: str | None = None
    level: int = 0


@dataclass(frozen=True)
class ModuleSymbols:
    """Everything one file contributes to the graph."""

    fqn: str
    path: Path
    definitions: tuple[Definition, ...]
    calls: tuple[CallSite, ...]
    imports: tuple[RawImport, ...]
    dynamic: frozenset[str]
    """FQNs of definitions containing constructs static analysis cannot follow."""

    bases: dict[str, tuple[str, ...]]
    """Class FQN to the base class names as written."""


def dotted_name(node: ast.expr) -> str | None:
    """``yaml.load`` from an attribute chain, or ``None`` if it is not a plain name.

    A call on a subscript or another call — ``handlers[key]()``, ``factory()()`` — has
    no static name and returns ``None``.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else None
    return None


class _Walker(ast.NodeVisitor):
    """Collects definitions, calls and imports, tracking the enclosing scope."""

    def __init__(self, module_fqn: str) -> None:
        self.module_fqn = module_fqn
        self.definitions: list[Definition] = [Definition(fqn=module_fqn, kind="module", line=1)]
        self.calls: list[CallSite] = []
        self.imports: list[RawImport] = []
        self.dynamic: set[str] = set()
        self.bases: dict[str, tuple[str, ...]] = {}
        self._scope: list[str] = [module_fqn]
        self._in_class = False

    @property
    def _current(self) -> str:
        return self._scope[-1]

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(RawImport(module=None, name=alias.name, alias=alias.asname))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            self.imports.append(
                RawImport(
                    module=node.module,
                    name=alias.name,
                    alias=alias.asname,
                    level=node.level,
                )
            )
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        fqn = f"{self._current}.{node.name}"
        self.definitions.append(Definition(fqn=fqn, kind="class", line=node.lineno))
        self.bases[fqn] = tuple(
            name for base in node.bases if (name := dotted_name(base)) is not None
        )

        self._scope.append(fqn)
        was_in_class, self._in_class = self._in_class, True
        for child in node.body:
            self.visit(child)
        self._in_class = was_in_class
        self._scope.pop()

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        fqn = f"{self._current}.{node.name}"
        kind = "method" if self._in_class else "function"
        self.definitions.append(Definition(fqn=fqn, kind=kind, line=node.lineno))

        self._scope.append(fqn)
        was_in_class, self._in_class = self._in_class, False
        for child in node.body:
            self.visit(child)
        self._in_class = was_in_class
        self._scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = dotted_name(node.func)
        if name is None:
            # A call with no static name at all — handlers[key](), factory()().
            self.dynamic.add(self._current)
        else:
            tail = name.rsplit(".", 1)[-1]
            if name in DYNAMIC_BUILTINS or tail in DYNAMIC_ATTRIBUTES:
                self.dynamic.add(self._current)
            self.calls.append(CallSite(caller=self._current, name=name, line=node.lineno))
        self.generic_visit(node)


def parse_module(path: Path, fqn: str) -> ModuleSymbols | None:
    """Extract one file's symbols, or ``None`` if it cannot be read or parsed.

    Returning ``None`` rather than raising keeps one bad file from ending a scan, but
    the caller must record it: a file that was never analysed has no paths through it,
    and silently treating that as "no path exists" is a false negative.
    """
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, SyntaxError, UnicodeDecodeError, ValueError):
        return None

    walker = _Walker(fqn)
    walker.visit(tree)
    return ModuleSymbols(
        fqn=fqn,
        path=path,
        definitions=tuple(walker.definitions),
        calls=tuple(walker.calls),
        imports=tuple(walker.imports),
        dynamic=frozenset(walker.dynamic),
        bases=walker.bases,
    )
