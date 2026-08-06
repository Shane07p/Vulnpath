"""Three verdicts over a call graph.

The rule under test throughout: NOT_REACHABLE is a claim, and a claim needs grounds.
Absence of evidence is UNKNOWN.
"""

from pathlib import Path

import networkx as nx

from vulnpath.callgraph import build_call_graph
from vulnpath.expand import expand_into_dependencies
from vulnpath.reachability import Confidence, ReachabilityIndex, Verdict


def _project(root: Path, body: str) -> Path:
    package = root / "app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "main.py").write_text(body, encoding="utf-8")
    return package


def _analyse(tmp_path: Path, body: str, deps: dict[str, str], package: str):  # type: ignore[no-untyped-def]
    """Build a project and its dependencies, expand, and analyse one package."""
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    for module, source in deps.items():
        (site_packages / f"{module}.py").write_text(source, encoding="utf-8")

    project = _project(tmp_path, body)
    graph = build_call_graph(project)
    expand_into_dependencies(graph, site_packages)
    return ReachabilityIndex(graph.graph).analyse(frozenset({package}))


def test_a_direct_call_into_a_package_is_reachable(tmp_path: Path) -> None:
    result = _analyse(
        tmp_path,
        "import risky\n\n\ndef go():\n    return risky.danger()\n",
        {"risky": "def danger():\n    return 1\n"},
        "risky",
    )
    assert result.verdict is Verdict.REACHABLE
    assert result.confidence is Confidence.HIGH


def test_a_reachable_verdict_carries_the_path_as_evidence(tmp_path: Path) -> None:
    """The path is what a user checks when they do not believe the answer."""
    result = _analyse(
        tmp_path,
        "import risky\n\n\ndef go():\n    return risky.danger()\n",
        {"risky": "def danger():\n    return 1\n"},
        "risky",
    )
    assert result.path[0].startswith("app")
    assert result.path[-1].startswith("risky")


def test_a_package_nobody_imports_is_not_reachable(tmp_path: Path) -> None:
    """The one negative that can be stated outright.

    Dynamic dispatch cannot reach a module that no analysed code ever imports, so this
    verdict does not depend on having seen through every construct.
    """
    result = _analyse(
        tmp_path,
        "def go():\n    return 1\n",
        {"risky": "def danger():\n    return 1\n"},
        "risky",
    )
    assert result.verdict is Verdict.NOT_REACHABLE
    assert result.confidence is Confidence.HIGH
    assert result.is_suppressible


def test_an_imported_but_uncalled_package_with_no_dynamic_code_is_not_reachable(
    tmp_path: Path,
) -> None:
    result = _analyse(
        tmp_path,
        "import risky\n\n\ndef go():\n    return 1\n",
        {"risky": "def danger():\n    return 1\n"},
        "risky",
    )
    assert result.verdict is Verdict.NOT_REACHABLE


def test_dynamic_dispatch_forces_unknown_rather_than_a_clean_negative(tmp_path: Path) -> None:
    """The verdict this project exists to be able to give.

    Nothing calls into the package, but the project dispatches through getattr, and a
    getattr can land anywhere. Reporting NOT_REACHABLE here would be a false claim of
    safety built on the analyser's own blind spot.
    """
    result = _analyse(
        tmp_path,
        "import risky\n\n\ndef go(obj, name):\n    return getattr(obj, name)()\n",
        {"risky": "def danger():\n    return 1\n"},
        "risky",
    )
    assert result.verdict is Verdict.UNKNOWN
    assert result.confidence is Confidence.LOW
    assert not result.is_suppressible


def test_unknown_is_never_suppressible(tmp_path: Path) -> None:
    """Suppression is the product, and it must never swallow an unproven case."""
    result = _analyse(
        tmp_path,
        "import risky\n\n\ndef go(obj, name):\n    return getattr(obj, name)()\n",
        {"risky": "def danger():\n    return 1\n"},
        "risky",
    )
    assert not result.is_suppressible


def test_a_path_through_an_intermediate_dependency_is_found(tmp_path: Path) -> None:
    """my code -> middle -> risky, where nothing calls risky directly."""
    result = _analyse(
        tmp_path,
        "import middle\n\n\ndef go():\n    return middle.hop()\n",
        {
            "risky": "def danger():\n    return 1\n",
            "middle": "import risky\n\n\ndef hop():\n    return risky.danger()\n",
        },
        "risky",
    )
    assert result.verdict is Verdict.REACHABLE
    assert "middle.hop" in result.path


def test_a_call_on_an_unknown_receiver_is_unknown_not_a_clean_negative(tmp_path: Path) -> None:
    """`thing.danger()` could be anything.

    Name-based fan-out only covers definitions already in the graph, and the project is
    analysed before any dependency is parsed, so a call like this cannot be matched to a
    dependency symbol even in principle. Saying NOT_REACHABLE would turn that limitation
    into a claim about the user's safety.
    """
    result = _analyse(
        tmp_path,
        "import risky\n\n\ndef go(thing):\n    return thing.danger()\n",
        {"risky": "def danger():\n    return 1\n"},
        "risky",
    )
    assert result.verdict is Verdict.UNKNOWN
    assert not result.is_suppressible


def test_the_shortest_path_wins_even_when_a_longer_guessed_one_exists(tmp_path: Path) -> None:
    """Every project definition is a root, so a method that calls the package directly
    gives a one-hop path. The user gets that rather than a longer, weaker route."""
    result = _analyse(
        tmp_path,
        "import risky\n\n\n"
        "class Runner:\n"
        "    def act(self):\n"
        "        return risky.danger()\n\n\n"
        "def go(thing):\n"
        "    return thing.act()\n",
        {"risky": "def danger():\n    return 1\n"},
        "risky",
    )
    assert result.verdict is Verdict.REACHABLE
    assert result.confidence is Confidence.HIGH
    assert len(result.path) == 2


def test_a_guessed_hop_lowers_confidence_without_changing_the_verdict() -> None:
    """Built as a graph rather than from source.

    Whether a real project produces a speculative-only path depends on what else happens
    to resolve, which makes it a poor way to test the confidence rule. The rule itself is
    simple: if the path taken crossed a guessed edge, say so.
    """
    graph = nx.DiGraph()
    graph.add_node("app.go", kind="function", origin="project", dynamic=False)
    graph.add_node("risky.danger", kind="function", origin="dependency", dynamic=False)
    graph.add_edge("app.go", "risky.danger", kind="calls", speculative=True)

    result = ReachabilityIndex(graph).analyse(frozenset({"risky"}))
    assert result.verdict is Verdict.REACHABLE
    assert result.confidence is Confidence.MEDIUM
    assert "resolved by name" in result.reason


def test_a_resolved_path_is_high_confidence() -> None:
    graph = nx.DiGraph()
    graph.add_node("app.go", kind="function", origin="project", dynamic=False)
    graph.add_node("risky.danger", kind="function", origin="dependency", dynamic=False)
    graph.add_edge("app.go", "risky.danger", kind="calls", speculative=False)

    result = ReachabilityIndex(graph).analyse(frozenset({"risky"}))
    assert result.confidence is Confidence.HIGH


def test_a_project_with_no_source_concludes_nothing(tmp_path: Path) -> None:
    """An empty analysis is not a clean bill of health."""
    empty = tmp_path / "empty"
    empty.mkdir()
    graph = build_call_graph(empty)
    result = ReachabilityIndex(graph.graph).analyse(frozenset({"risky"}))
    assert result.verdict is Verdict.UNKNOWN


def test_a_package_whose_import_names_are_unknown_concludes_nothing(tmp_path: Path) -> None:
    """Without knowing what a distribution imports as, nothing can be said about it."""
    project = _project(tmp_path, "def go():\n    return 1\n")
    graph = build_call_graph(project)
    result = ReachabilityIndex(graph.graph).analyse(frozenset())
    assert result.verdict is Verdict.UNKNOWN
