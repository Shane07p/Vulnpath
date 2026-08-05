"""Assemble a call graph from a project's own source.

Two passes. The first records every definition across every module, because a call
can target something defined later or in another file. The second resolves each call
site against that table plus the calling module's import table.

Resolution over-approximates on purpose. A call that cannot be narrowed to one target
fans out to every definition sharing its attribute name, and the edge is marked
speculative. A false REACHABLE is noise a user can dismiss; a false NOT_REACHABLE is
the tool lying about safety.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx

from vulnpath.imports import build_import_table
from vulnpath.sourcetree import SourceModule, discover_modules
from vulnpath.symbols import ModuleSymbols, parse_module


@dataclass(frozen=True)
class CallGraph:
    """Nodes are dotted symbol names; edges carry a kind and a speculative flag."""

    graph: nx.DiGraph
    unparsed_files: tuple[Path, ...] = ()
    """Files that could not be read or parsed.

    Reported rather than dropped: no analysis ran over them, so any verdict about a
    path through them is unproven rather than negative.
    """

    def nodes(self) -> list[str]:
        return list(self.graph.nodes)

    def edges_from(self, fqn: str) -> set[str]:
        if fqn not in self.graph:
            return set()
        return set(self.graph.successors(fqn))

    def is_dynamic(self, fqn: str) -> bool:
        """Whether this symbol contains a construct static analysis cannot follow."""
        node = self.graph.nodes.get(fqn)
        return bool(node and node.get("dynamic"))

    def summary(self) -> dict[str, int]:
        kinds = [data.get("kind") for _, data in self.graph.nodes(data=True)]
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "external": sum(1 for kind in kinds if kind == "external"),
            "dynamic": sum(1 for _, data in self.graph.nodes(data=True) if data.get("dynamic")),
            "unparsed": len(self.unparsed_files),
        }


@dataclass
class _Index:
    """Everything pass two needs to resolve a name."""

    definitions: dict[str, str] = field(default_factory=dict)
    """FQN to kind."""

    by_tail: dict[str, set[str]] = field(default_factory=dict)
    """Last FQN segment to every definition ending in it, for speculative fan-out."""

    module_fqns: set[str] = field(default_factory=set)

    def add(self, fqn: str, kind: str) -> None:
        self.definitions[fqn] = kind
        self.by_tail.setdefault(fqn.rsplit(".", 1)[-1], set()).add(fqn)
        if kind == "module":
            self.module_fqns.add(fqn)


def _resolve(
    name: str, caller: str, module_fqn: str, imports: dict[str, str], index: _Index
) -> tuple[set[str], bool]:
    """Targets for one call site, and whether the answer was speculative.

    Tried in order: an imported name, a sibling in the same module, a definition
    anywhere with that exact FQN. Failing all of those, every definition whose last
    segment matches — which is the over-approximation, and is flagged.
    """
    head, _, rest = name.partition(".")

    if head in imports:
        target = f"{imports[head]}.{rest}" if rest else imports[head]
        return {target}, False

    local = f"{module_fqn}.{name}"
    if local in index.definitions:
        return {local}, False

    if name in index.definitions:
        return {name}, False

    tail = name.rsplit(".", 1)[-1]
    candidates = index.by_tail.get(tail, set()) - {caller}
    if candidates:
        return set(candidates), True

    return set(), False


def _owning_module(fqn: str, module_fqns: set[str]) -> str | None:
    """The project module a name belongs to, if any.

    ``sample_app.core.Processor`` belongs to ``sample_app.core``. Checking only whether
    the whole name is a module would miss every ``from x import y`` form, which is most
    of them.
    """
    parts = fqn.split(".")
    for count in range(len(parts), 0, -1):
        candidate = ".".join(parts[:count])
        if candidate in module_fqns:
            return candidate
    return None


def _add_node(graph: nx.DiGraph, fqn: str, kind: str, **attrs: object) -> None:
    if fqn in graph:
        graph.nodes[fqn].update(attrs)
        return
    graph.add_node(fqn, kind=kind, **attrs)


def build_call_graph(project_path: Path, *, include_tests: bool = False) -> CallGraph:
    """Build the graph for one project's own source."""
    graph = nx.DiGraph()
    index = _Index()
    # The SourceModule is kept alongside its symbols because pass two needs
    # ``is_package`` to resolve relative imports, and ModuleSymbols does not carry it.
    parsed: list[tuple[SourceModule, ModuleSymbols]] = []
    unparsed: list[Path] = []

    # Pass one: every definition, so a call can target anything anywhere.
    for module in discover_modules(project_path, include_tests=include_tests):
        symbols = parse_module(module.path, module.fqn)
        if symbols is None:
            unparsed.append(module.path)
            continue
        parsed.append((module, symbols))
        for definition in symbols.definitions:
            index.add(definition.fqn, definition.kind)
            _add_node(
                graph,
                definition.fqn,
                definition.kind,
                file=str(module.path),
                line=definition.line,
                dynamic=definition.fqn in symbols.dynamic,
            )

    # Pass two: resolve call sites, imports and inheritance.
    for module, symbols in parsed:
        imports = build_import_table(symbols.imports, symbols.fqn, is_package=module.is_package)

        for target in imports.values():
            owner = _owning_module(target, index.module_fqns)
            if owner is not None:
                # Importing a module executes its top level, so this is a real edge.
                if owner != symbols.fqn:
                    graph.add_edge(symbols.fqn, owner, kind="imports", speculative=False)
            elif target not in index.definitions:
                _add_node(graph, target, "external", dynamic=False)

        for class_fqn, bases in symbols.bases.items():
            for base in bases:
                targets, speculative = _resolve(base, class_fqn, symbols.fqn, imports, index)
                for base_fqn in targets:
                    if base_fqn in index.definitions:
                        graph.add_edge(
                            class_fqn, base_fqn, kind="inherits", speculative=speculative
                        )

        for call in symbols.calls:
            targets, speculative = _resolve(call.name, call.caller, symbols.fqn, imports, index)
            for target in targets:
                if target not in index.definitions:
                    _add_node(graph, target, "external", dynamic=False)
                if call.caller in graph:
                    graph.add_edge(call.caller, target, kind="calls", speculative=speculative)

    return CallGraph(graph=graph, unparsed_files=tuple(unparsed))
