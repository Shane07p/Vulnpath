"""Scan orchestration: the functions that gather facts and hand them to the pure rules.

All the network in this project lives here, so all of it is mocked. What is under test
is whether the right facts reach the classifier, not whether OSV and PyPI respond.
"""

from pathlib import Path
from unittest import mock

import pytest

from vulnpath.lockfile import load_lockfile
from vulnpath.models import Advisory, Severity
from vulnpath.pypi import PyPIClient
from vulnpath.scan import (
    build_fix_context,
    environment_drift,
    find_parent_upgrades,
    run_scan,
)

SAMPLE_PROJECT = Path(__file__).parent / "fixtures" / "sample_project"


@pytest.fixture
def graph():  # type: ignore[no-untyped-def]
    return load_lockfile(SAMPLE_PROJECT)


# --- gathering the facts classification needs ---------------------------------------


def test_the_root_constraint_comes_from_the_lockfile(graph, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """uv.lock carries the root's own specifiers even though it omits every other one."""
    client = PyPIClient(tmp_path, offline=True)
    context = build_fix_context(graph, graph.packages["pyyaml"], Advisory(id="CVE-1"), client)
    assert context.declared == "==5.3.1"


def test_parent_constraints_come_from_pypi_not_the_lockfile(graph, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """uv.lock records dependency edges without specifiers, so the parent's constraint
    on a package cannot be read from it at all."""
    client = PyPIClient(tmp_path, offline=True)
    with (
        mock.patch.object(PyPIClient, "requires_dist", return_value=("urllib3<1.27,>=1.21.1",)),
        mock.patch.object(PyPIClient, "releases", return_value=("1.26.5",)),
    ):
        context = build_fix_context(graph, graph.packages["urllib3"], Advisory(id="CVE-1"), client)

    assert context.parents["requests"] == "<1.27,>=1.21.1"


def test_a_parent_whose_metadata_is_unavailable_is_simply_absent(graph, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """An unreadable constraint must not become a permissive one.

    Leaving it out of the map is what lets the classifier answer UNKNOWN rather than
    assuming the parent allows the fix.
    """
    client = PyPIClient(tmp_path, offline=True)
    with (
        mock.patch.object(PyPIClient, "requires_dist", return_value=None),
        mock.patch.object(PyPIClient, "releases", return_value=("1.26.5",)),
    ):
        context = build_fix_context(graph, graph.packages["urllib3"], Advisory(id="CVE-1"), client)

    assert "requests" not in context.parents


def test_the_root_project_is_never_treated_as_a_blocking_parent(graph, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """It has no release on PyPI, and its constraint is already handled as `declared`."""
    client = PyPIClient(tmp_path, offline=True)
    with (
        mock.patch.object(PyPIClient, "requires_dist", return_value=("urllib3<1.27",)),
        mock.patch.object(PyPIClient, "releases", return_value=("1.26.5",)),
    ):
        context = build_fix_context(graph, graph.packages["urllib3"], Advisory(id="CVE-1"), client)

    assert "sample-project" not in context.parents


# --- parent upgrades ----------------------------------------------------------------


def test_a_parent_that_already_permits_the_target_is_not_looked_up(tmp_path: Path) -> None:
    """Upgrading it would achieve nothing, and the lookup costs a request."""
    client = PyPIClient(tmp_path, offline=True)
    with mock.patch.object(PyPIClient, "releases", side_effect=AssertionError("no lookup")):
        upgrades = find_parent_upgrades(
            _package("urllib3", "1.26.5"), "1.26.17", {"requests": ">=1.21.1"}, client
        )
    assert upgrades == {}


def test_a_parent_whose_newest_release_lifts_the_constraint_is_reported(tmp_path: Path) -> None:
    client = PyPIClient(tmp_path, offline=True)
    with (
        mock.patch.object(PyPIClient, "releases", return_value=("2.25.1", "2.32.5")),
        mock.patch.object(PyPIClient, "requires_dist", return_value=("urllib3>=1.21.1",)),
    ):
        upgrades = find_parent_upgrades(
            _package("urllib3", "1.26.5"), "2.0.6", {"requests": "<1.27"}, client
        )
    assert upgrades == {"requests": "2.32.5"}


def test_a_parent_still_blocking_at_its_newest_release_offers_no_upgrade(tmp_path: Path) -> None:
    client = PyPIClient(tmp_path, offline=True)
    with (
        mock.patch.object(PyPIClient, "releases", return_value=("2.25.1", "2.32.5")),
        mock.patch.object(PyPIClient, "requires_dist", return_value=("urllib3<1.27",)),
    ):
        upgrades = find_parent_upgrades(
            _package("urllib3", "1.26.5"), "2.0.6", {"requests": "<1.27"}, client
        )
    assert upgrades == {}


def test_an_unparseable_target_yields_no_upgrades(tmp_path: Path) -> None:
    client = PyPIClient(tmp_path, offline=True)
    assert find_parent_upgrades(_package("x", "1.0"), "not-a-version", {"p": "<1"}, client) == {}


def _package(name: str, version: str):  # type: ignore[no-untyped-def]
    from vulnpath.models import Package

    return Package(name=name, version=version, depth=1)


# --- environment drift --------------------------------------------------------------


def test_a_missing_environment_is_reported_rather_than_raising(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        'version = 1\n\n[[package]]\nname = "solo"\nversion = "1.0.0"\n', encoding="utf-8"
    )
    messages = environment_drift(tmp_path, None)
    assert messages
    assert "virtual environment" in messages[0]


def test_a_version_mismatch_between_lockfile_and_installed_is_named(tmp_path: Path) -> None:
    """Advisory matching runs off the lockfile, so drift is a warning — but reachability
    reads the installed source, and would be reading different code."""
    (tmp_path / "uv.lock").write_text(
        "version = 1\n\n"
        '[[package]]\nname = "root"\nversion = "0.1.0"\nsource = { virtual = "." }\n'
        'dependencies = [{ name = "urllib3" }]\n\n'
        '[[package]]\nname = "urllib3"\nversion = "1.26.5"\n',
        encoding="utf-8",
    )
    site_packages = tmp_path / ".venv" / "Lib" / "site-packages"
    (site_packages / "urllib3-2.0.0.dist-info").mkdir(parents=True)

    messages = environment_drift(tmp_path, None)
    assert any("lockfile says 1.26.5, installed is 2.0.0" in message for message in messages)


# --- the whole pipeline -------------------------------------------------------------


def test_without_an_environment_every_finding_stays_unknown(tmp_path: Path) -> None:
    """A scan that could not trace anything must not leave findings looking cleared."""
    result = run_scan(SAMPLE_PROJECT, offline=True, cache_dir=tmp_path)
    assert result.reachability_analysed is False
    assert all(finding.verdict == "unknown" for finding in result.findings)


def test_the_severity_floor_is_applied_before_classification(tmp_path: Path) -> None:
    result = run_scan(
        SAMPLE_PROJECT, offline=True, severity_floor=Severity.CRITICAL, cache_dir=tmp_path
    )
    assert result.findings == []
