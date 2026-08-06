"""Following the graph past its boundary into dependency source.

Most tests build a synthetic site-packages, because what is under test is resolution
across a package boundary rather than any particular library's contents. One test runs
against this project's own installed environment, since a synthetic tree cannot show
whether the thing survives real code.
"""

from pathlib import Path

from vulnpath.callgraph import build_call_graph
from vulnpath.expand import expand_into_dependencies


def _project(root: Path, body: str) -> Path:
    """A one-module project whose code is ``body``."""
    package = root / "app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "main.py").write_text(body, encoding="utf-8")
    return package


def _install(site_packages: Path, module: str, source: str) -> None:
    """Write a module into a synthetic site-packages, creating packages as needed."""
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


def test_a_facade_re_export_is_followed_to_the_defining_module(tmp_path: Path) -> None:
    """The case this phase exists for.

    A caller writes `yaml.load(...)`. That name is not defined in the facade — it is
    bound there by a re-export. Without an alias edge the path stops at the facade while
    the symbol an advisory names sits one hop further on, unreached.
    """
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    (site_packages / "yaml").mkdir()
    (site_packages / "yaml" / "__init__.py").write_text(
        "from yaml.loader import load\n", encoding="utf-8"
    )
    _install(site_packages, "yaml.loader", "def load(stream):\n    return stream\n")

    package = _project(tmp_path, "import yaml\n\n\ndef go(text):\n    return yaml.load(text)\n")
    graph = build_call_graph(package)
    expand_into_dependencies(graph, site_packages)

    assert "yaml.load" in graph.edges_from("app.main.go")
    assert "yaml.loader.load" in graph.edges_from("yaml.load")


def test_an_intermediate_dependency_hop_is_found(tmp_path: Path) -> None:
    """Project -> requests -> urllib3: the hop that only lazy expansion can see."""
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    _install(site_packages, "urllib3", "def urlopen(url):\n    return url\n")
    _install(
        site_packages,
        "requests",
        "import urllib3\n\n\ndef get(url):\n    return urllib3.urlopen(url)\n",
    )

    package = _project(
        tmp_path, "import requests\n\n\ndef go(url):\n    return requests.get(url)\n"
    )
    graph = build_call_graph(package)
    expand_into_dependencies(graph, site_packages)

    assert "requests.get" in graph.edges_from("app.main.go")
    assert "urllib3.urlopen" in graph.edges_from("requests.get")


def test_a_module_that_is_not_installed_stays_external(tmp_path: Path) -> None:
    """Standard library and compiled extensions are genuine leaves, not errors."""
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()

    package = _project(tmp_path, "import os\n\n\ndef go():\n    return os.getcwd()\n")
    graph = build_call_graph(package)
    result = expand_into_dependencies(graph, site_packages)

    assert graph.graph.nodes["os.getcwd"]["kind"] == "external"
    assert result.modules_parsed == 0


def test_an_import_cycle_between_dependencies_terminates(tmp_path: Path) -> None:
    """Cycles are ordinary in real packages and must not hang a scan."""
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    _install(site_packages, "alpha", "import beta\n\n\ndef a():\n    return beta.b()\n")
    _install(site_packages, "beta", "import alpha\n\n\ndef b():\n    return alpha.a()\n")

    package = _project(tmp_path, "import alpha\n\n\ndef go():\n    return alpha.a()\n")
    graph = build_call_graph(package)
    result = expand_into_dependencies(graph, site_packages)

    assert result.modules_parsed == 2
    assert "beta.b" in graph.edges_from("alpha.a")


def test_a_spent_budget_reports_what_was_left_rather_than_pretending(tmp_path: Path) -> None:
    """An exhausted budget is a gap in analysis, and downstream must be able to see it."""
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    _install(site_packages, "alpha", "import beta\n\n\ndef a():\n    return beta.b()\n")
    _install(site_packages, "beta", "def b():\n    return 1\n")

    package = _project(tmp_path, "import alpha\n\n\ndef go():\n    return alpha.a()\n")
    graph = build_call_graph(package)
    result = expand_into_dependencies(graph, site_packages, budget=1)

    assert result.budget_exhausted
    assert result.unexpanded
    assert not result.is_complete


def test_a_complete_expansion_says_so(tmp_path: Path) -> None:
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    _install(site_packages, "alpha", "def a():\n    return 1\n")

    package = _project(tmp_path, "import alpha\n\n\ndef go():\n    return alpha.a()\n")
    graph = build_call_graph(package)
    assert expand_into_dependencies(graph, site_packages).is_complete


def test_expansion_is_idempotent(tmp_path: Path) -> None:
    """Running twice must not double edges or re-parse settled modules."""
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    _install(site_packages, "alpha", "def a():\n    return 1\n")

    package = _project(tmp_path, "import alpha\n\n\ndef go():\n    return alpha.a()\n")
    graph = build_call_graph(package)

    expand_into_dependencies(graph, site_packages)
    before = (graph.graph.number_of_nodes(), graph.graph.number_of_edges())
    expand_into_dependencies(graph, site_packages)

    assert (graph.graph.number_of_nodes(), graph.graph.number_of_edges()) == before


def test_a_dependency_module_that_will_not_parse_is_recorded(tmp_path: Path) -> None:
    """Never silently skipped: no analysis ran over it, so paths through it are unproven."""
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    _install(site_packages, "broken", "def oops(:\n")

    package = _project(tmp_path, "import broken\n\n\ndef go():\n    return broken.oops()\n")
    graph = build_call_graph(package)
    result = expand_into_dependencies(graph, site_packages)

    assert [p.name for p in result.unparsed_files] == ["broken.py"]


def test_expansion_survives_this_projects_own_environment() -> None:
    """A synthetic tree cannot show whether this holds up against real library code."""
    site_packages = Path(".venv/Lib/site-packages")
    if not site_packages.is_dir():  # pragma: no cover - POSIX layout
        candidates = sorted(Path(".venv/lib").glob("python*/site-packages"))
        if not candidates:
            return
        site_packages = candidates[0]

    graph = build_call_graph(Path("."))
    before = graph.graph.number_of_nodes()
    result = expand_into_dependencies(graph, site_packages, budget=40)

    assert result.modules_parsed > 0
    assert graph.graph.number_of_nodes() > before


# --- star re-exports ----------------------------------------------------------------
# Real facades are often built with `from ._impl import *` — httpx/__init__.py is almost
# entirely this — and an ordinary import table cannot say what a star binds.


def _star_facade(site_packages: Path) -> None:
    (site_packages / "lib").mkdir()
    (site_packages / "lib" / "__init__.py").write_text("from lib._api import *\n", encoding="utf-8")
    _install(
        site_packages,
        "lib._api",
        "def get(url):\n    return url\n\n\ndef _private():\n    return 1\n",
    )


def test_a_star_re_export_aliases_the_names_it_covers(tmp_path: Path) -> None:
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    _star_facade(site_packages)

    package = _project(tmp_path, "import lib\n\n\ndef go(url):\n    return lib.get(url)\n")
    graph = build_call_graph(package)
    expand_into_dependencies(graph, site_packages)

    assert "lib._api.get" in graph.edges_from("lib.get")


def test_a_star_re_export_does_not_alias_private_names(tmp_path: Path) -> None:
    """A star import never binds an underscore-prefixed name, so neither does this."""
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    _star_facade(site_packages)

    package = _project(tmp_path, "import lib\n\n\ndef go(url):\n    return lib.get(url)\n")
    graph = build_call_graph(package)
    expand_into_dependencies(graph, site_packages)

    assert "lib._private" not in graph.graph
