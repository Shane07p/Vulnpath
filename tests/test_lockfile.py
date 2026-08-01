"""Lockfile parsing, against real resolver output."""

from pathlib import Path

import pytest

from vulnpath.lockfile import LockfileError, load_lockfile
from vulnpath.models import normalise

SAMPLE_PROJECT = Path(__file__).parent / "fixtures" / "sample_project"


def test_parses_every_package_in_the_fixture() -> None:
    graph = load_lockfile(SAMPLE_PROJECT)
    assert set(graph.packages) == {
        "sample-project",
        "pyyaml",
        "urllib3",
        "jinja2",
        "requests",
        "certifi",
        "chardet",
        "idna",
        "markupsafe",
    }


def test_root_is_the_project_not_a_dependency() -> None:
    graph = load_lockfile(SAMPLE_PROJECT)
    assert graph.root == "sample-project"
    assert graph.packages["sample-project"].is_root
    assert not graph.packages["pyyaml"].is_root


def test_scannable_excludes_the_project_itself() -> None:
    graph = load_lockfile(SAMPLE_PROJECT)
    names = {p.name for p in graph.scannable}
    assert "sample-project" not in names
    assert len(names) == len(graph.packages) - 1


@pytest.mark.parametrize("package", ["pyyaml", "urllib3", "jinja2", "requests"])
def test_declared_dependencies_are_depth_one(package: str) -> None:
    graph = load_lockfile(SAMPLE_PROJECT)
    assert graph.packages[package].depth == 1
    assert graph.packages[package].is_direct


@pytest.mark.parametrize("package", ["certifi", "chardet", "markupsafe"])
def test_transitive_dependencies_are_deeper(package: str) -> None:
    graph = load_lockfile(SAMPLE_PROJECT)
    assert graph.packages[package].depth == 2
    assert not graph.packages[package].is_direct


def test_urllib3_is_direct_despite_also_being_reachable_through_requests() -> None:
    """Shortest path wins: it is what decides whether a direct bump can fix it."""
    graph = load_lockfile(SAMPLE_PROJECT)
    assert "urllib3" in graph.packages["requests"].dependencies
    assert graph.packages["urllib3"].depth == 1


def test_parents_are_recorded_for_blocking_parent_analysis() -> None:
    graph = load_lockfile(SAMPLE_PROJECT)
    assert graph.parents_of("markupsafe") == {"jinja2"}
    assert graph.parents_of("certifi") == {"requests"}
    assert graph.parents_of("urllib3") == {"requests", "sample-project"}


def test_versions_come_from_the_lockfile() -> None:
    graph = load_lockfile(SAMPLE_PROJECT)
    assert graph.packages["pyyaml"].version == "5.3.1"
    assert graph.packages["urllib3"].version == "1.26.5"


def test_lookup_normalises_the_name() -> None:
    graph = load_lockfile(SAMPLE_PROJECT)
    assert normalise("PyYAML") == "pyyaml"
    got = graph.get("PyYAML")
    assert got is not None and got.version == "5.3.1"


def test_missing_lockfile_says_what_to_do(tmp_path: Path) -> None:
    with pytest.raises(LockfileError, match="uv lock"):
        load_lockfile(tmp_path)


def test_malformed_lockfile_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text("this is not = valid = toml", encoding="utf-8")
    with pytest.raises(LockfileError, match="not valid TOML"):
        load_lockfile(tmp_path)


def test_unsupported_lock_version_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text('version = 99\n[[package]]\nname="x"\n', encoding="utf-8")
    with pytest.raises(LockfileError, match="lock version"):
        load_lockfile(tmp_path)
