"""Does the project's own code reach a given package?

One traversal serves every finding. The graph does not change between advisories, so
the reachable set and its predecessors are computed once and every package is answered
against them.

Three verdicts, and the third carries the weight. ``UNKNOWN`` exists because static
analysis of Python cannot see through ``getattr``, dynamic imports or plugin registries,
and a tool that reported those as ``NOT_REACHABLE`` would be telling users they are safe
on the strength of its own blind spot.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import StrEnum

import networkx as nx


class Verdict(StrEnum):
    """What the analysis concluded about one package."""

    REACHABLE = "reachable"
    NOT_REACHABLE = "not_reachable"
    UNKNOWN = "unknown"


class Confidence(StrEnum):
    """How much the verdict rests on guesses."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class ReachabilityResult:
    """A verdict, why it was reached, and the evidence for it."""

    verdict: Verdict
    confidence: Confidence
    reason: str
    path: tuple[str, ...] = ()
    """The shortest call path found, from the project's code to the package.

    Empty unless the verdict is REACHABLE. This is the evidence a user checks when they
    do not believe the answer, so it is a path through real symbols rather than a claim.
    """

    @property
    def is_suppressible(self) -> bool:
        """Whether this finding can be safely deprioritised.

        Only a proven NOT_REACHABLE qualifies. UNKNOWN never does — that is the entire
        distinction the verdict exists to make.
        """
        return self.verdict is Verdict.NOT_REACHABLE


def _project_roots(graph: nx.DiGraph) -> list[str]:
    """Every definition belonging to the project under scan.

    All of them, not just entry points. A library has no ``__main__``, and picking only
    detected entry points would report most of its own public API as unreachable — a
    false negative at scale, which is worse than the noise of assuming any of the
    project's code might run.
    """
    return [fqn for fqn, data in graph.nodes(data=True) if data.get("origin") == "project"]


@dataclass(frozen=True)
class _Traversal:
    """One breadth-first sweep from the project's code, shared by every finding."""

    reachable: dict[str, int]
    """Node to its distance from the nearest root."""

    predecessor: dict[str, str]
    speculative_hops: frozenset[str]
    """Nodes first arrived at over a guessed edge."""

    blind_spot_reachable: bool
    """Whether any reachable code contains something the analysis could not follow.

    Two causes, both meaning the same thing for a verdict. A ``getattr`` or dynamic
    import can dispatch anywhere. So can an attribute call on a receiver whose type is
    unknown, when nothing in the graph matched the name.
    """


def _traverse(graph: nx.DiGraph, roots: list[str]) -> _Traversal:
    """Breadth-first from every root at once, recording how each node was first reached.

    Breadth-first rather than depth-first because the first path found is then the
    shortest, and the shortest path is what a user is shown as evidence.
    """
    reachable: dict[str, int] = {root: 0 for root in roots}
    predecessor: dict[str, str] = {}
    speculative: set[str] = set()

    def _is_blind(fqn: str) -> bool:
        node = graph.nodes[fqn]
        return bool(node.get("dynamic") or node.get("unresolved"))

    blind_seen = any(_is_blind(root) for root in roots)

    queue = deque(roots)
    while queue:
        current = queue.popleft()
        for successor in graph.successors(current):
            if successor in reachable:
                continue
            reachable[successor] = reachable[current] + 1
            predecessor[successor] = current
            if graph.edges[current, successor].get("speculative"):
                speculative.add(successor)
            if _is_blind(successor):
                blind_seen = True
            queue.append(successor)

    return _Traversal(
        reachable=reachable,
        predecessor=predecessor,
        speculative_hops=frozenset(speculative),
        blind_spot_reachable=blind_seen,
    )


class ReachabilityIndex:
    """Answers reachability for many packages from one traversal."""

    def __init__(self, graph: nx.DiGraph, *, expansion_complete: bool = True) -> None:
        self.graph = graph
        self.roots = _project_roots(graph)
        self.expansion_complete = expansion_complete
        """Whether every boundary node was followed into dependency source.

        False means analysis ran out of budget with work outstanding, so a symbol may be
        absent from the graph for want of parsing rather than for want of a caller. Only
        symbol-level negatives consult this: a package-level negative rests on nothing
        importing the package at all, which no amount of further expansion would change.
        """

        self._traversal = _traverse(graph, self.roots)

    @property
    def has_project_code(self) -> bool:
        return bool(self.roots)

    def _nodes_in(self, import_names: frozenset[str]) -> list[str]:
        """Every node belonging to one of these top-level import names."""
        prefixes = tuple(f"{name}." for name in import_names)
        return [fqn for fqn in self.graph.nodes if fqn in import_names or fqn.startswith(prefixes)]

    def _path_to(self, target: str) -> tuple[str, ...]:
        path = [target]
        while path[-1] in self._traversal.predecessor:
            path.append(self._traversal.predecessor[path[-1]])
        return tuple(reversed(path))

    def analyse(self, import_names: frozenset[str]) -> ReachabilityResult:
        """Whether the project's code reaches any symbol in these import names."""
        if not self.has_project_code:
            return ReachabilityResult(
                verdict=Verdict.UNKNOWN,
                confidence=Confidence.LOW,
                reason="No project source was analysed, so nothing can be concluded.",
            )

        if not import_names:
            return ReachabilityResult(
                verdict=Verdict.UNKNOWN,
                confidence=Confidence.LOW,
                reason="The import names this package installs could not be determined.",
            )

        owned = self._nodes_in(import_names)
        reached = [fqn for fqn in owned if fqn in self._traversal.reachable]

        if reached:
            nearest = min(reached, key=lambda fqn: self._traversal.reachable[fqn])
            path = self._path_to(nearest)
            guessed = any(hop in self._traversal.speculative_hops for hop in path)
            return ReachabilityResult(
                verdict=Verdict.REACHABLE,
                confidence=Confidence.MEDIUM if guessed else Confidence.HIGH,
                reason=(
                    "A call path reaches this package, though at least one hop was "
                    "resolved by name rather than exactly."
                    if guessed
                    else "A call path reaches this package."
                ),
                path=path,
            )

        # Nothing in the graph refers to this package at all. Dynamic dispatch cannot
        # reach a module that is never imported anywhere the project executes, so this
        # is the one case where a negative can be stated outright.
        if not owned:
            return ReachabilityResult(
                verdict=Verdict.NOT_REACHABLE,
                confidence=Confidence.HIGH,
                reason="No analysed code imports this package.",
            )

        if self._traversal.blind_spot_reachable:
            return ReachabilityResult(
                verdict=Verdict.UNKNOWN,
                confidence=Confidence.LOW,
                reason=(
                    "No call path was found, but reachable code dispatches in ways "
                    "static analysis cannot follow, so one may exist."
                ),
            )

        return ReachabilityResult(
            verdict=Verdict.NOT_REACHABLE,
            confidence=Confidence.HIGH,
            reason=(
                "The package is imported somewhere, but no call path from your code "
                "reaches it, and no dynamic dispatch could hide one."
            ),
        )

    def analyse_symbols(
        self, import_names: frozenset[str], symbols: tuple[str, ...]
    ) -> ReachabilityResult:
        """Narrow a package-level verdict to the specific symbols an advisory names.

        The narrowing is deliberately asymmetric. Finding a path to a named symbol is
        positive evidence and is safe to state from any starting verdict. Failing to find
        one is only safe to state when the analysis had nowhere to hide a path — so a
        negative requires a package-level verdict that was already confident, every named
        symbol present in the graph, expansion that finished, and no dynamic dispatch on
        reachable code.

        ``symbols`` must already be verified against installed source. Narrowing to a
        symbol that does not exist would find no path and report a real vulnerability as
        unreachable, which is the failure this tool exists not to produce.
        """
        package = self.analyse(import_names)

        # Nothing to narrow with, or nothing to narrow: a package no code reaches cannot
        # have one of its functions reached either.
        if not symbols or package.verdict is Verdict.NOT_REACHABLE:
            return package

        known = [symbol for symbol in symbols if symbol in self.graph]
        reached = [symbol for symbol in known if symbol in self._traversal.reachable]

        if reached:
            nearest = min(reached, key=lambda fqn: self._traversal.reachable[fqn])
            path = self._path_to(nearest)
            guessed = any(hop in self._traversal.speculative_hops for hop in path)
            return ReachabilityResult(
                verdict=Verdict.REACHABLE,
                confidence=Confidence.MEDIUM if guessed else Confidence.HIGH,
                reason=(
                    f"A call path reaches {nearest}, which this advisory names, though "
                    "at least one hop was resolved by name rather than exactly."
                    if guessed
                    else f"A call path reaches {nearest}, which this advisory names."
                ),
                path=path,
            )

        # From here every branch is a negative, and each guard is a way one could be wrong.
        if package.verdict is not Verdict.REACHABLE:
            return package

        if len(known) != len(symbols):
            # Expansion is demand-driven, so a symbol missing from the graph means its
            # module was never parsed — not that nothing calls it. Those are opposite
            # conclusions and the string alone cannot tell them apart.
            return ReachabilityResult(
                verdict=Verdict.UNKNOWN,
                confidence=Confidence.LOW,
                reason=(
                    "Your code reaches this package, but the symbols this advisory names "
                    "were never parsed, so whether you reach them is unknown."
                ),
            )

        if not self.expansion_complete:
            return ReachabilityResult(
                verdict=Verdict.UNKNOWN,
                confidence=Confidence.LOW,
                reason=(
                    "Your code reaches this package, but analysis ran out of budget "
                    "before it finished, so a path to the named symbols may exist."
                ),
            )

        if self._traversal.blind_spot_reachable:
            # The package is imported, so dynamic dispatch really could land on the
            # vulnerable symbol. This is stricter than the package-level rule, where a
            # negative rests on the package never being imported at all — something no
            # getattr can work around.
            return ReachabilityResult(
                verdict=Verdict.UNKNOWN,
                confidence=Confidence.LOW,
                reason=(
                    "Your code reaches this package but not the symbols this advisory "
                    "names, though reachable code dispatches in ways static analysis "
                    "cannot follow, so a path may exist."
                ),
            )

        named = ", ".join(symbols)
        return ReachabilityResult(
            verdict=Verdict.NOT_REACHABLE,
            confidence=Confidence.HIGH,
            reason=(
                f"Your code uses this package, but no call path reaches {named}, "
                "which is where this advisory is."
            ),
        )
