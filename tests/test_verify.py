"""Verifying extracted symbols against installed source.

This is the check that makes the LLM stage safe to have, so the tests that matter most
are the ones proving a name the model could plausibly invent gets dropped. Most build a
synthetic site-packages, because what is under test is name resolution across a package
boundary rather than any library's contents. Two run against this project's own installed
environment, since a tree written by the test cannot show whether the thing survives real
packaging.
"""

from pathlib import Path

from vulnpath.environment import find_site_packages
from vulnpath.verify import MAX_REEXPORT_DEPTH, module_splits, verify_symbols


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


def _package(site_packages: Path, name: str, source: str) -> None:
    """Write a package's ``__init__.py``."""
    (site_packages / name).mkdir(parents=True, exist_ok=True)
    (site_packages / name / "__init__.py").write_text(source, encoding="utf-8")


def _site_packages(tmp_path: Path) -> Path:
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    return site_packages


# --- the point of the module --------------------------------------------------------


def test_a_symbol_that_does_not_exist_is_dropped(tmp_path: Path) -> None:
    """The failure this whole stage is defended against.

    ``yaml.safe_load_unsafe`` is exactly the shape of thing a model produces: right
    package, right naming convention, entirely invented. Narrowing a verdict to it would
    find no call path and report the finding unreachable — a false negative caused by the
    tool's own hallucination.
    """
    site_packages = _site_packages(tmp_path)
    _package(site_packages, "yaml", "def load(stream):\n    return stream\n")

    result = verify_symbols(("yaml.load", "yaml.safe_load_unsafe"), site_packages)

    assert result.verified == ("yaml.load",)
    assert result.dropped == ("yaml.safe_load_unsafe",)


def test_nothing_verified_is_not_usable(tmp_path: Path) -> None:
    """Zero survivors means fall back to package level, not "no symbols are affected"."""
    site_packages = _site_packages(tmp_path)
    _package(site_packages, "yaml", "def load(stream):\n    return stream\n")

    result = verify_symbols(("yaml.invented", "yaml.also_invented"), site_packages)

    assert result.verified == ()
    assert not result.is_usable


def test_a_symbol_from_a_package_that_is_not_installed_is_dropped(tmp_path: Path) -> None:
    """No source to check against is not the same as confirmed."""
    result = verify_symbols(("yaml.load",), _site_packages(tmp_path))
    assert result.dropped == ("yaml.load",)


# --- how real packages are actually shaped ------------------------------------------


def test_a_facade_re_export_verifies(tmp_path: Path) -> None:
    """Advisories name the symbol the way a user imports it.

    ``yaml.load`` is what an advisory says and what a caller writes, but PyYAML's
    ``__init__`` binds it by re-export. Checking definitions alone would drop the most
    common correct answer there is.

    What comes back is the defining location, not the name asked about. The call graph is
    keyed by where a definition lives, and a project reaching the function through any
    alias reaches that node — so resolving to it matches a direct call as well as a
    facade one.
    """
    site_packages = _site_packages(tmp_path)
    _package(site_packages, "yaml", "from yaml.loader import load\n")
    _install(site_packages, "yaml.loader", "def load(stream):\n    return stream\n")

    assert verify_symbols(("yaml.load",), site_packages).verified == ("yaml.loader.load",)


def test_a_star_re_export_verifies(tmp_path: Path) -> None:
    """How most real facades are built — httpx's ``__init__`` among them.

    An import table cannot enumerate what a star binds, so the module it pulls from has
    to be read.
    """
    site_packages = _site_packages(tmp_path)
    _package(site_packages, "httpx", "from httpx._api import *\n")
    _install(site_packages, "httpx._api", "def get(url):\n    return url\n")

    assert verify_symbols(("httpx.get",), site_packages).verified == ("httpx._api.get",)


def test_a_re_export_of_something_absent_is_still_dropped(tmp_path: Path) -> None:
    """Following a re-export must not become a way to confirm anything.

    The facade names ``load``, so the import table has an entry for it — but the module it
    points at never defines it. A check that stopped at "the facade mentions this name"
    would verify a symbol that does not exist.
    """
    site_packages = _site_packages(tmp_path)
    _package(site_packages, "yaml", "from yaml.loader import load\n")
    _install(site_packages, "yaml.loader", "def something_else(stream):\n    return stream\n")

    assert verify_symbols(("yaml.load",), site_packages).dropped == ("yaml.load",)


def test_a_method_on_a_class_verifies(tmp_path: Path) -> None:
    """Advisories often name a method, not a free function."""
    site_packages = _site_packages(tmp_path)
    _install(
        site_packages,
        "yaml.loader",
        "class Loader:\n    def construct(self, node):\n        return node\n",
    )
    _package(site_packages, "yaml", "")

    result = verify_symbols(
        ("yaml.loader.Loader.construct", "yaml.loader.Loader.nope"), site_packages
    )

    assert result.verified == ("yaml.loader.Loader.construct",)
    assert result.dropped == ("yaml.loader.Loader.nope",)


def test_a_single_module_distribution_verifies(tmp_path: Path) -> None:
    """Not every distribution installs a package directory."""
    site_packages = _site_packages(tmp_path)
    _install(site_packages, "six", "def reraise(tp, value):\n    return value\n")

    assert verify_symbols(("six.reraise",), site_packages).verified == ("six.reraise",)


# --- termination --------------------------------------------------------------------


def test_mutually_importing_modules_terminate(tmp_path: Path) -> None:
    """Two modules importing from each other is ordinary, and must not hang."""
    site_packages = _site_packages(tmp_path)
    _package(site_packages, "loop", "from loop.other import thing\n")
    _install(site_packages, "loop.other", "from loop import thing\n")

    assert verify_symbols(("loop.thing",), site_packages).dropped == ("loop.thing",)


def test_a_chain_longer_than_the_limit_is_dropped_rather_than_followed(tmp_path: Path) -> None:
    """Giving up is a fallback to package level, which is the safe direction.

    Reporting the symbol unverified loses precision. Following an unbounded chain risks
    not finishing at all, and a scan that never returns is worse than one that says less.
    """
    site_packages = _site_packages(tmp_path)
    _package(site_packages, "deep", "from deep.a import thing\n")
    hops = MAX_REEXPORT_DEPTH + 2
    for index in range(hops):
        _install(
            site_packages,
            f"deep.{chr(ord('a') + index)}",
            f"from deep.{chr(ord('a') + index + 1)} import thing\n",
        )
    _install(site_packages, f"deep.{chr(ord('a') + hops)}", "def thing():\n    return 1\n")

    assert verify_symbols(("deep.thing",), site_packages).dropped == ("deep.thing",)


# --- splitting ----------------------------------------------------------------------


def test_module_splits_tries_the_longest_module_first() -> None:
    """A dotted string does not say where the module ends and the attribute begins."""
    assert module_splits("yaml.loader.Loader.construct") == [
        ("yaml.loader.Loader", "construct"),
        ("yaml.loader", "Loader.construct"),
        ("yaml", "loader.Loader.construct"),
    ]


def test_module_splits_never_proposes_an_empty_module() -> None:
    assert module_splits("yaml.load") == [("yaml", "load")]


# --- against a real environment -----------------------------------------------------


def test_a_real_installed_symbol_verifies() -> None:
    """A synthetic tree proves resolution; only real packaging proves this works.

    ``httpx.get`` is reached through the star-import facade this project already depends
    on, so it exercises the hardest path against source nobody wrote for a test.
    """
    site_packages = find_site_packages(Path.cwd(), None)

    result = verify_symbols(("httpx.get", "httpx.request"), site_packages)

    assert result.verified == ("httpx._api.get", "httpx._api.request")


def test_a_hallucination_is_caught_against_a_real_environment() -> None:
    """The number the evaluation reports, measured against source nobody wrote for a test."""
    site_packages = find_site_packages(Path.cwd(), None)

    result = verify_symbols(
        ("httpx.get", "httpx.fetch_url_unsafe", "httpx.Client.send_raw"), site_packages
    )

    assert result.verified == ("httpx._api.get",)
    assert result.dropped == ("httpx.fetch_url_unsafe", "httpx.Client.send_raw")
