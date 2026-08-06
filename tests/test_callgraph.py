"""Two-pass resolution: definitions first, then call sites."""

from pathlib import Path

from vulnpath.callgraph import build_call_graph

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE_APP = FIXTURES / "sample_app"


def test_internal_calls_become_edges() -> None:
    graph = build_call_graph(SAMPLE_APP)
    assert "sample_app.utils.read_settings" in graph.edges_from("sample_app.main.run")


def test_defining_a_function_creates_no_edge() -> None:
    """Otherwise every function is reachable the moment its file is imported."""
    graph = build_call_graph(SAMPLE_APP)
    assert "sample_app.main.run" not in graph.edges_from("sample_app.main")


def test_calls_into_dependencies_become_boundary_nodes() -> None:
    """The join point the cross-package phase attaches to."""
    graph = build_call_graph(SAMPLE_APP)
    assert "yaml.load" in graph.edges_from("sample_app.utils.read_settings")
    assert graph.graph.nodes["yaml.load"]["kind"] == "external"


def test_an_aliased_import_resolves_to_its_true_target() -> None:
    graph = build_call_graph(SAMPLE_APP)
    assert "json.loads" in graph.edges_from("sample_app.utils.read_json")


def test_instantiation_is_an_edge_to_the_class() -> None:
    graph = build_call_graph(SAMPLE_APP)
    assert "sample_app.core.Processor" in graph.edges_from("sample_app.main.run")


def test_method_calls_on_an_unknown_receiver_fan_out() -> None:
    """`processor.process(...)` has no type information, so it resolves by name."""
    graph = build_call_graph(SAMPLE_APP)
    targets = graph.edges_from("sample_app.main.run")
    assert "sample_app.core.Processor.process" in targets


def test_a_fanned_out_edge_is_marked_speculative() -> None:
    graph = build_call_graph(SAMPLE_APP)
    edge = graph.graph.edges["sample_app.main.run", "sample_app.core.Processor.process"]
    assert edge["speculative"] is True


def test_a_resolved_edge_is_not_speculative() -> None:
    graph = build_call_graph(SAMPLE_APP)
    edge = graph.graph.edges["sample_app.main.run", "sample_app.utils.read_settings"]
    assert edge["speculative"] is False


def test_importing_a_module_is_an_edge_because_its_top_level_runs() -> None:
    graph = build_call_graph(SAMPLE_APP)
    assert "sample_app.core" in graph.edges_from("sample_app.main")


def test_a_re_export_through_init_links_to_the_defining_module() -> None:
    """Most vulnerable symbols are reached through a package facade, not directly."""
    graph = build_call_graph(SAMPLE_APP)
    assert "sample_app.core" in graph.edges_from("sample_app")


def test_a_relative_import_inside_a_package_facade_resolves() -> None:
    """``__init__.py`` is its own package, so ``from .core import X`` counts back from
    ``app``, not from ``app``'s parent. Getting this wrong points every facade
    re-export at a module that does not exist, and the package facade is the main way
    a project reaches a dependency's public API.
    """
    graph = build_call_graph(FIXTURES / "relative_app")
    assert "relative_app.core" in graph.edges_from("relative_app")


def test_dynamic_dispatch_marks_the_node() -> None:
    """The flag a later phase turns into UNKNOWN rather than NOT_REACHABLE."""
    graph = build_call_graph(SAMPLE_APP)
    assert graph.is_dynamic("sample_app.dynamic.dispatch")
    assert not graph.is_dynamic("sample_app.core.Processor.process")


def test_inheritance_is_recorded() -> None:
    graph = build_call_graph(SAMPLE_APP)
    edge = graph.graph.edges["sample_app.core.Processor", "sample_app.core.Base"]
    assert edge["kind"] == "inherits"


def test_tests_are_not_part_of_the_graph_by_default() -> None:
    graph = build_call_graph(SAMPLE_APP)
    assert not any("test_core" in node for node in graph.nodes())


def test_an_unparseable_file_is_reported_not_swallowed(tmp_path: Path) -> None:
    """A file that was never analysed has no paths through it.

    Treating that as "no path exists" is exactly the false negative this project
    refuses to produce, so the count has to reach the caller.
    """
    package = tmp_path / "app"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "good.py").write_text("def f():\n    pass\n", encoding="utf-8")
    (package / "bad.py").write_text("def oops(:\n", encoding="utf-8")

    graph = build_call_graph(tmp_path)
    assert [p.name for p in graph.unparsed_files] == ["bad.py"]
    assert "app.good.f" in graph.nodes()


def test_a_clean_project_reports_no_unparsed_files() -> None:
    assert build_call_graph(SAMPLE_APP).unparsed_files == ()


def test_summary_counts_nodes_and_edges() -> None:
    summary = build_call_graph(SAMPLE_APP).summary()
    assert summary["nodes"] > 0
    assert summary["edges"] > 0
    assert summary["external"] >= 2


# --- edge merging -------------------------------------------------------------------
# One pair of symbols can be related several ways. Whatever is recorded must not depend
# on the order the source happens to mention them in.


def _two_call_project(root: Path, body: str) -> Path:
    package = root / "app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "core.py").write_text("def helper():\n    pass\n", encoding="utf-8")
    (package / "main.py").write_text(
        f"from app.core import helper\n\n\ndef go(thing):\n{body}\n", encoding="utf-8"
    )
    return package


def test_a_resolved_call_stays_resolved_when_a_fuzzy_one_follows(tmp_path: Path) -> None:
    """`helper()` names its target exactly. A later `thing.helper()` cannot unprove that."""
    package = _two_call_project(tmp_path, "    helper()\n    thing.helper()")
    graph = build_call_graph(package)
    assert graph.graph.edges["app.main.go", "app.core.helper"]["speculative"] is False


def test_the_speculative_label_does_not_depend_on_statement_order(tmp_path: Path) -> None:
    """The regression this exists for.

    The same two calls in opposite orders previously produced opposite labels, because
    each edge write overwrote the last. A definite call is definite either way.
    """
    first = build_call_graph(_two_call_project(tmp_path / "a", "    helper()\n    thing.helper()"))
    second = build_call_graph(_two_call_project(tmp_path / "b", "    thing.helper()\n    helper()"))

    assert (
        first.graph.edges["app.main.go", "app.core.helper"]["speculative"]
        is second.graph.edges["app.main.go", "app.core.helper"]["speculative"]
    )


def test_a_call_edge_outranks_an_inherits_edge_between_the_same_pair(tmp_path: Path) -> None:
    """A class that both inherits Base and calls it in its body is doing both.

    The call is what matters when tracing execution, so it is the kind that survives.
    """
    package = tmp_path / "app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "core.py").write_text(
        "class Base:\n    pass\n\n\nclass Child(Base):\n    default = Base()\n",
        encoding="utf-8",
    )

    graph = build_call_graph(package)
    assert graph.graph.edges["app.core.Child", "app.core.Base"]["kind"] == "calls"
