"""Finding the project's own modules, and mapping paths to dotted names."""

from pathlib import Path

import pytest

from vulnpath.sourcetree import discover_modules, is_test_path, module_fqn

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE_APP = FIXTURES / "sample_app"


def _fqns(project: Path, *, include_tests: bool = False) -> set[str]:
    return {m.fqn for m in discover_modules(project, include_tests=include_tests)}


def test_discovers_every_module_in_the_package() -> None:
    found = _fqns(SAMPLE_APP)
    assert "sample_app.core" in found
    assert "sample_app.utils" in found
    assert "sample_app.main" in found
    assert "sample_app.dynamic" in found


def test_package_init_maps_to_the_package_itself() -> None:
    """`sample_app/__init__.py` is `sample_app`, not `sample_app.__init__`."""
    assert "sample_app" in _fqns(SAMPLE_APP)
    assert "sample_app.__init__" not in _fqns(SAMPLE_APP)


def test_tests_are_excluded_by_default() -> None:
    """A test suite imports nearly everything, so counting it destroys suppression."""
    assert not any("test" in fqn for fqn in _fqns(SAMPLE_APP))


def test_tests_can_be_opted_back_in() -> None:
    found = _fqns(SAMPLE_APP, include_tests=True)
    assert any("test_core" in fqn for fqn in found)


@pytest.mark.parametrize(
    "path",
    [
        Path("tests/test_thing.py"),
        Path("app/tests/helpers.py"),
        Path("test/conftest.py"),
        Path("src/app/conftest.py"),
        Path("src/app/thing_test.py"),
        Path("src/app/test_thing.py"),
    ],
)
def test_test_paths_are_recognised(path: Path) -> None:
    assert is_test_path(path)


@pytest.mark.parametrize(
    "path",
    [Path("src/app/main.py"), Path("app/latest.py"), Path("src/contest/run.py")],
)
def test_ordinary_paths_are_not_mistaken_for_tests(path: Path) -> None:
    """`latest.py` contains "test" as a substring and must not be excluded."""
    assert not is_test_path(path)


def test_virtualenvs_and_build_output_are_never_source(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "__init__.py").write_text("", encoding="utf-8")
    for junk in (".venv", "build", "dist", "__pycache__"):
        directory = tmp_path / junk / "pkg"
        directory.mkdir(parents=True)
        (directory / "__init__.py").write_text("", encoding="utf-8")

    found = _fqns(tmp_path)
    assert found == {"app"}


def test_src_layout_is_rooted_at_src(tmp_path: Path) -> None:
    """A src/ layout must produce `app.main`, never `src.app.main`."""
    package = tmp_path / "src" / "app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "main.py").write_text("", encoding="utf-8")

    assert _fqns(tmp_path) == {"app", "app.main"}


def test_module_fqn_uses_dots(tmp_path: Path) -> None:
    assert module_fqn(tmp_path / "app" / "sub" / "thing.py", tmp_path) == "app.sub.thing"


def test_a_project_with_no_python_yields_nothing(tmp_path: Path) -> None:
    assert discover_modules(tmp_path) == []
