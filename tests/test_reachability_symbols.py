"""Narrowing a package-level verdict to the symbols an advisory names.

Every test here is about the asymmetry. Proving a path to a named symbol is safe from any
starting point; failing to find one is only safe when the analysis had nowhere to hide a
path. So the tests that matter most are the ones checking a negative is *refused* — each
one stands for a way this phase could invent a false negative, which is the single failure
this project treats as worse than useless.
"""

from pathlib import Path

import networkx as nx

from vulnpath.callgraph import build_call_graph
from vulnpath.expand import expand_into_dependencies
from vulnpath.reachability import ReachabilityIndex, Verdict

RISKY = frozenset({"risky"})


def _install(site_packages: Path, module: str, source: str) -> None:
    parts = module.split(".")
    if len(parts) == 1:
        (site_packages / f"{parts[0]}.py").write_text(source, encoding="utf-8")
        return
    directory = site_packages / Path(*parts[:-1])
    directory.mkdir(parents=True, exist_ok=True)
    for depth in range(1, len(parts)):
        init = site_packages / Path(*parts[:depth]) / "__init__.py"
        if not init.exists():
            init.write_text("", encoding="utf-8")
    (directory / f"{parts[-1]}.py").write_text(source, encoding="utf-8")


def _index(tmp_path: Path, body: str, dependency: str) -> ReachabilityIndex:
    """A real graph: project code expanded into a synthetic installed dependency."""
    package = tmp_path / "app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "main.py").write_text(body, encoding="utf-8")

    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    _install(site_packages, "risky", dependency)

    graph = build_call_graph(package)
    expansion = expand_into_dependencies(graph, site_packages)
    return ReachabilityIndex(graph.graph, expansion_complete=expansion.is_complete)


TWO_FUNCTIONS = "def danger(x):\n    return x\n\n\ndef safe(x):\n    return x\n"


# --- the payoff ---------------------------------------------------------------------


def test_using_a_package_but_not_the_vulnerable_function_is_not_reachable(tmp_path: Path) -> None:
    """The finding this phase exists to remove.

    The project calls ``risky.safe``. The advisory is about ``risky.danger``. Package-level
    analysis calls this reachable and always will; only the symbol makes it dismissible.
    """
    index = _index(
        tmp_path, "import risky\n\n\ndef go(x):\n    return risky.safe(x)\n", TWO_FUNCTIONS
    )

    assert index.analyse(RISKY).verdict is Verdict.REACHABLE

    narrowed = index.analyse_symbols(RISKY, ("risky.danger",))
    assert narrowed.verdict is Verdict.NOT_REACHABLE
    assert "risky.danger" in narrowed.reason


def test_reaching_the_vulnerable_function_stays_reachable_with_a_sharper_path(
    tmp_path: Path,
) -> None:
    """A narrowed positive is better evidence, not merely the same answer.

    The path now ends at the vulnerable function rather than anywhere in the package,
    which is what a reader checks when they do not believe the verdict.
    """
    index = _index(
        tmp_path, "import risky\n\n\ndef go(x):\n    return risky.danger(x)\n", TWO_FUNCTIONS
    )

    narrowed = index.analyse_symbols(RISKY, ("risky.danger",))

    assert narrowed.verdict is Verdict.REACHABLE
    assert narrowed.path[-1] == "risky.danger"
    assert "risky.danger" in narrowed.reason


def test_one_reached_symbol_among_several_is_enough(tmp_path: Path) -> None:
    """Advisories often name a family of functions. Reaching any one is reaching it."""
    index = _index(
        tmp_path, "import risky\n\n\ndef go(x):\n    return risky.danger(x)\n", TWO_FUNCTIONS
    )

    narrowed = index.analyse_symbols(RISKY, ("risky.safe", "risky.danger"))
    assert narrowed.verdict is Verdict.REACHABLE


# --- the guards, each a way a negative could be wrong --------------------------------


def test_a_symbol_never_parsed_forces_unknown(tmp_path: Path) -> None:
    """Absence from the graph is ambiguous, and the two readings are opposites.

    Expansion is demand-driven, so a missing node can mean "nothing calls it" or "that
    module was never read". Treating the second as the first is a false negative.
    """
    index = _index(
        tmp_path, "import risky\n\n\ndef go(x):\n    return risky.safe(x)\n", TWO_FUNCTIONS
    )

    narrowed = index.analyse_symbols(RISKY, ("risky.never_parsed",))

    assert narrowed.verdict is Verdict.UNKNOWN
    assert "never parsed" in narrowed.reason


def test_dynamic_dispatch_forces_unknown(tmp_path: Path) -> None:
    """Stricter than the package-level rule, and deliberately so.

    A package-level negative rests on nothing importing the package, which no getattr can
    work around. Here the package *is* imported, so a getattr really could land on the
    vulnerable function.
    """
    index = _index(
        tmp_path,
        "import risky\n\n\ndef go(x, name):\n    return getattr(risky, name)(x)\n",
        TWO_FUNCTIONS,
    )

    narrowed = index.analyse_symbols(RISKY, ("risky.danger",))

    assert narrowed.verdict is Verdict.UNKNOWN
    assert "cannot follow" in narrowed.reason


def test_incomplete_expansion_forces_unknown(tmp_path: Path) -> None:
    """Running out of budget is not a finding about the code."""
    index = _index(
        tmp_path, "import risky\n\n\ndef go(x):\n    return risky.safe(x)\n", TWO_FUNCTIONS
    )
    exhausted = ReachabilityIndex(index.graph, expansion_complete=False)

    narrowed = exhausted.analyse_symbols(RISKY, ("risky.danger",))

    assert narrowed.verdict is Verdict.UNKNOWN
    assert "budget" in narrowed.reason


# --- narrowing must not change what it has no business changing ----------------------


def test_no_symbols_leaves_the_package_verdict_alone(tmp_path: Path) -> None:
    """Nothing extracted, nothing named, nothing verified — all arrive here identically.

    None of them is evidence about the code, so none of them may move the verdict.
    """
    index = _index(
        tmp_path, "import risky\n\n\ndef go(x):\n    return risky.danger(x)\n", TWO_FUNCTIONS
    )

    package = index.analyse(RISKY)
    narrowed = index.analyse_symbols(RISKY, ())

    assert narrowed.verdict is package.verdict
    assert narrowed.reason == package.reason


def test_an_unreached_package_stays_not_reachable(tmp_path: Path) -> None:
    """A function of a package nothing reaches cannot itself be reached."""
    index = _index(tmp_path, "def go(x):\n    return x\n", TWO_FUNCTIONS)

    assert index.analyse_symbols(RISKY, ("risky.danger",)).verdict is Verdict.NOT_REACHABLE


def test_an_unknown_package_verdict_is_never_narrowed_to_a_negative(tmp_path: Path) -> None:
    """The rule this whole project is built around, applied one level down.

    If the package-level answer was already unsure, symbol analysis finding no path adds
    nothing — the same blind spot that produced the unknown could hide the symbol too.
    """
    graph = nx.DiGraph()
    graph.add_node("app.main.go", kind="function", origin="project", dynamic=True)
    graph.add_node("risky", kind="module", origin="dependency")
    graph.add_node("risky.danger", kind="function", origin="dependency")

    index = ReachabilityIndex(graph)
    assert index.analyse(RISKY).verdict is Verdict.UNKNOWN

    assert index.analyse_symbols(RISKY, ("risky.danger",)).verdict is Verdict.UNKNOWN


def test_an_unknown_package_verdict_can_still_be_proven_reachable() -> None:
    """A found path outranks a blind spot.

    Upgrading on positive evidence is always safe; it is only the negative direction that
    needs guarding.
    """
    graph = nx.DiGraph()
    graph.add_node("app.main.go", kind="function", origin="project", dynamic=True)
    graph.add_node("risky.danger", kind="function", origin="dependency")
    graph.add_edge("app.main.go", "risky.danger", kind="calls")

    narrowed = ReachabilityIndex(graph).analyse_symbols(RISKY, ("risky.danger",))

    assert narrowed.verdict is Verdict.REACHABLE
    assert narrowed.path == ("app.main.go", "risky.danger")
