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
class Index:
    """Everything name resolution needs: what exists, and under what names.

    Public because dependency expansion resolves against project and dependency
    definitions together, using the same rules. Two resolvers would drift.
    """

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


def resolve_name(
    name: str, caller: str, module_fqn: str, imports: dict[str, str], index: Index
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


def owning_module(fqn: str, module_fqns: set[str]) -> str | None:
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


def add_node(graph: nx.DiGraph, fqn: str, kind: str, **attrs: object) -> None:
    """Add or update a node, promoting it out of ``external`` once its source is read.

    A name first seen as a call target is only known to be external. Parsing the module
    that defines it turns that guess into a fact, and the node has to say so — otherwise
    a module stays labelled external after being fully analysed, and any count or filter
    over kinds reports work that was done as work that was skipped.

    Promotion is one-way. Nothing learned later makes a known definition external again.
    """
    if fqn in graph:
        graph.nodes[fqn].update(attrs)
        if kind != "external":
            graph.nodes[fqn]["kind"] = kind
        return
    graph.add_node(fqn, kind=kind, **attrs)


EDGE_KIND_PRECEDENCE = ("calls", "inherits", "alias", "imports")
"""Strongest evidence of execution first, for when one pair has several relationships.

``alias`` outranks ``imports`` because a re-export says exactly which symbol a name
refers to, while an import only says a module's top level ran.
"""


def _kind_rank(kind: str) -> int:
    """Rank of an edge kind, with unknown kinds ranked last rather than raising.

    A new kind added elsewhere should weaken this merge, not crash a scan mid-way.
    """
    try:
        return EDGE_KIND_PRECEDENCE.index(kind)
    except ValueError:
        return len(EDGE_KIND_PRECEDENCE)


def add_edge(graph: nx.DiGraph, source: str, target: str, kind: str, speculative: bool) -> None:
    """Record a relationship, merging with whatever is already known about this pair.

    Two rules, both there to stop the label depending on statement order.

    ``speculative`` is sticky-false. One call site resolving exactly is proof the edge
    is real, and a later fuzzy match to the same target cannot take that back. Without
    this, the same two calls in the opposite order produced the opposite label.

    ``kind`` keeps the strongest evidence. A module that both imports another and calls
    into it is doing both, and the call is what matters when tracing execution.
    """
    existing = graph.edges.get((source, target))
    if existing is None:
        graph.add_edge(source, target, kind=kind, speculative=speculative)
        return

    existing["speculative"] = bool(existing.get("speculative", True)) and speculative
    if _kind_rank(kind) < _kind_rank(str(existing["kind"])):
        existing["kind"] = kind


def build_call_graph(project_path: Path, *, include_tests: bool = False) -> CallGraph:
    """Build the graph for one project's own source."""
    graph = nx.DiGraph()
    index = Index()
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
            add_node(
                graph,
                definition.fqn,
                definition.kind,
                file=str(module.path),
                line=definition.line,
                dynamic=definition.fqn in symbols.dynamic,
                origin="project",
            )

    # Pass two: resolve call sites, imports and inheritance.
    for module, symbols in parsed:
        imports = build_import_table(symbols.imports, symbols.fqn, is_package=module.is_package)

        for target in imports.values():
            owner = owning_module(target, index.module_fqns)
            if owner is not None:
                # Importing a module executes its top level, so this is a real edge.
                if owner != symbols.fqn:
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

            # An attribute call that resolved to nothing is a blind spot, not an absence.
            # `thing.danger()` on a receiver of unknown type could land anywhere, and
            # fan-out only covers definitions already known. A bare name resolving to
            # nothing is almost always a builtin, so it is not treated the same way —
            # marking those would make every function that calls len() a blind spot.
            if not targets and "." in call.name and call.caller in graph:
                graph.nodes[call.caller]["unresolved"] = True

            for target in targets:
                if target not in index.definitions:
                    add_node(graph, target, "external", dynamic=False)
                if call.caller in graph:
                    add_edge(graph, call.caller, target, "calls", speculative)

    return CallGraph(graph=graph, unparsed_files=tuple(unparsed))
