"""Follow the call graph past its boundary, into installed dependency source.

The graph built from project code stops at external nodes: ``read_settings -> yaml.load``
and no further. An advisory names a symbol deeper than that, so without this the two can
never meet.

Expansion is lazy. Parsing every installed distribution would mean tens of thousands of
files on a real project, almost none of them touched by the code under analysis, so the
worklist starts at the boundary the project actually reaches and grows only along edges
that exist.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

import networkx as nx

from vulnpath.callgraph import (
    CallGraph,
    Index,
    add_edge,
    add_node,
    owning_module,
    resolve_name,
)
from vulnpath.imports import build_import_table
from vulnpath.installed import find_module_file
from vulnpath.symbols import ModuleSymbols, parse_module

DEFAULT_MODULE_BUDGET = 2000
"""How many dependency modules one scan will parse.

A ceiling rather than a tuning knob. Speculative fan-out inside a large library can pull
in far more than expected, and a scan that never finishes is worse than one that says
plainly how far it got.
"""


@dataclass(frozen=True)
class Expansion:
    """What expansion managed to do, including what it did not."""

    modules_parsed: int = 0
    unexpanded: tuple[str, ...] = ()
    """Boundary nodes still unresolved when the budget ran out.

    A path through these is unproven, not absent. Anything consuming the graph must treat
    them as UNKNOWN rather than as evidence that no path exists.
    """

    unparsed_files: tuple[Path, ...] = ()
    budget_exhausted: bool = False

    @property
    def is_complete(self) -> bool:
        return not self.budget_exhausted and not self.unexpanded


def _module_candidates(fqn: str) -> list[str]:
    """Module names a dotted symbol might live in, longest first.

    ``yaml.loader.Loader.construct`` could be a module ``yaml.loader.Loader.construct``, or
    an attribute of module ``yaml.loader``, or a deeply nested attribute of ``yaml``. The
    string alone cannot say where the module path stops and the attribute path begins, so
    each split is tried until one resolves to a file.
    """
    parts = fqn.split(".")
    return [".".join(parts[:count]) for count in range(len(parts), 0, -1)]


def _external_nodes(graph: nx.DiGraph) -> list[str]:
    return [fqn for fqn, data in graph.nodes(data=True) if data.get("kind") == "external"]


def _record_module(graph: nx.DiGraph, index: Index, symbols: ModuleSymbols, path: Path) -> None:
    """Add a dependency module's definitions, exactly as project code is added."""
    for definition in symbols.definitions:
        index.add(definition.fqn, definition.kind)
        add_node(
            graph,
            definition.fqn,
            definition.kind,
            file=str(path),
            line=definition.line,
            dynamic=definition.fqn in symbols.dynamic,
        )


def _star_targets(symbols: ModuleSymbols, is_package: bool) -> list[str]:
    """Modules this one re-exports wholesale via ``from x import *``.

    Common in real facades — ``httpx/__init__.py`` is built almost entirely this way —
    and invisible to the ordinary import table, which cannot name what a star binds.
    """
    targets: list[str] = []
    for record in symbols.imports:
        if record.name != "*":
            continue
        resolved = build_import_table(
            [replace(record, name="__star__")], symbols.fqn, is_package=is_package
        )
        target = resolved.get("__star__")
        if target:
            targets.append(target.removesuffix(".__star__"))
    return targets


def _apply_star_reexports(graph: nx.DiGraph, index: Index, facade: str, source_module: str) -> None:
    """Alias every public name a star-imported module defines into the facade.

    ``from ._api import *`` in ``httpx/__init__.py`` makes ``httpx.get`` a real name, but
    only the source module knows what the star covers, so this runs once that module has
    been parsed. Underscore-prefixed names are skipped: a star import never binds them.
    """
    prefix = f"{source_module}."
    for fqn in list(index.definitions):
        if not fqn.startswith(prefix):
            continue
        local = fqn[len(prefix) :]
        if "." in local or local.startswith("_"):
            continue
        alias = f"{facade}.{local}"
        if alias == fqn:
            continue
        add_node(graph, alias, "external", dynamic=False)
        add_edge(graph, alias, fqn, "alias", speculative=False)


def _link_module(graph: nx.DiGraph, index: Index, symbols: ModuleSymbols, is_package: bool) -> None:
    """Resolve one dependency module's imports, aliases, bases and calls.

    Uses the same resolution as project code so behaviour cannot drift between the two —
    a dependency's calls are not a different kind of thing from the project's.
    """
    imports = build_import_table(symbols.imports, symbols.fqn, is_package=is_package)

    for local_name, target in imports.items():
        # A name bound at module level is reachable as <module>.<local name>. Without this
        # edge a facade dead-ends: `yaml/__init__.py` doing `from .loader import load`
        # leaves the caller's `yaml.load` pointing at a name that defines nothing, while
        # the symbol an advisory names sits one hop away, unreached.
        alias = f"{symbols.fqn}.{local_name}"
        if alias != target:
            add_node(graph, alias, "external", dynamic=False)
            add_edge(graph, alias, target, "alias", speculative=False)

        owner = owning_module(target, index.module_fqns)
        if owner is not None and owner != symbols.fqn:
            add_edge(graph, symbols.fqn, owner, "imports", speculative=False)
        elif target not in index.definitions:
            add_node(graph, target, "external", dynamic=False)

    for class_fqn, bases in symbols.bases.items():
        for base in bases:
            targets, speculative = resolve_name(base, class_fqn, symbols.fqn, imports, index)
            for base_fqn in targets:
                if base_fqn in index.definitions:
                    add_edge(graph, class_fqn, base_fqn, "inherits", speculative)

    for call in symbols.calls:
        targets, speculative = resolve_name(call.name, call.caller, symbols.fqn, imports, index)
        for target in targets:
            if target not in index.definitions:
                add_node(graph, target, "external", dynamic=False)
            if call.caller in graph:
                add_edge(graph, call.caller, target, "calls", speculative)


def _rebuild_index(graph: nx.DiGraph) -> Index:
    """Reconstruct the resolution index from a graph built earlier.

    The project pass discards its index, and expansion needs to resolve names against both
    project and dependency definitions at once.
    """
    index = Index()
    for fqn, data in graph.nodes(data=True):
        kind = str(data.get("kind", "external"))
        if kind != "external":
            index.add(fqn, kind)
    return index


def expand_into_dependencies(
    call_graph: CallGraph, site_packages: Path, *, budget: int = DEFAULT_MODULE_BUDGET
) -> Expansion:
    """Follow boundary nodes into installed source, in place.

    Mutates the graph rather than returning a new one: a copy per call buys nothing, and
    the caller already holds the object it wants extended.
    """
    graph = call_graph.graph
    index = _rebuild_index(graph)

    parsed_modules: set[str] = set()
    unparsed: list[Path] = []
    worklist = _external_nodes(graph)
    seen: set[str] = set(worklist)
    modules_parsed = 0

    # Facades that star-import a module, keyed by the module they pull from. A star
    # re-export can only be expanded once the source has been parsed, and the two can be
    # parsed in either order, so the pending relationship is recorded and applied from
    # whichever side arrives second.
    pending_stars: dict[str, list[str]] = {}

    while worklist:
        if modules_parsed >= budget:
            remaining = sorted(fqn for fqn in worklist if fqn not in parsed_modules)
            return Expansion(
                modules_parsed=modules_parsed,
                unexpanded=tuple(remaining),
                unparsed_files=tuple(unparsed),
                budget_exhausted=True,
            )

        node = worklist.pop()

        for candidate in _module_candidates(node):
            if candidate in parsed_modules:
                break
            path = find_module_file(site_packages, candidate)
            if path is None:
                continue

            parsed_modules.add(candidate)
            symbols = parse_module(path, candidate)
            if symbols is None:
                unparsed.append(path)
                break

            modules_parsed += 1
            is_package = path.name == "__init__.py"
            _record_module(graph, index, symbols, path)
            _link_module(graph, index, symbols, is_package=is_package)

            # This module star-imports others: alias what they already define, and note
            # the relationship so anything parsed later is aliased too.
            for source in _star_targets(symbols, is_package):
                _apply_star_reexports(graph, index, candidate, source)
                pending_stars.setdefault(source, []).append(candidate)
                if source not in seen:
                    seen.add(source)
                    add_node(graph, source, "external", dynamic=False)
                    worklist.append(source)

            # Other modules star-import this one: now that it is parsed, alias its names
            # into each of them.
            for facade in pending_stars.get(candidate, ()):
                _apply_star_reexports(graph, index, facade, candidate)

            for discovered in _external_nodes(graph):
                if discovered not in seen:
                    seen.add(discovered)
                    worklist.append(discovered)
            break

    return Expansion(
        modules_parsed=modules_parsed,
        unparsed_files=tuple(unparsed),
    )
