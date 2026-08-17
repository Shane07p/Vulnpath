"""Scan orchestration: the functions that gather facts and hand them to the pure rules.

All the network in this project lives here, so all of it is mocked. What is under test
is whether the right facts reach the classifier, not whether OSV and PyPI respond.
"""

from pathlib import Path
from unittest import mock

import pytest

from vulnpath.extract import SymbolExtractor
from vulnpath.lockfile import load_lockfile
from vulnpath.models import Advisory, Severity
from vulnpath.osv import OsvClient
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


# --- symbol extraction, wired ---------------------------------------------------------
# The rules are tested in test_reachability_symbols; what is tested here is that the
# pipeline actually applies them, and that a model's output never reaches a verdict
# without passing verification on the way.


def _project_using(root: Path, body: str) -> Path:
    """A scannable project: lockfile, source, and an environment holding one dependency."""
    (root / "uv.lock").write_text(
        "version = 1\n\n"
        '[[package]]\nname = "root"\nversion = "0.1.0"\nsource = { virtual = "." }\n'
        'dependencies = [{ name = "risky" }]\n\n'
        '[[package]]\nname = "risky"\nversion = "1.0.0"\n',
        encoding="utf-8",
    )

    app = root / "app"
    app.mkdir()
    (app / "__init__.py").write_text("", encoding="utf-8")
    (app / "main.py").write_text(body, encoding="utf-8")

    site_packages = root / ".venv" / "Lib" / "site-packages"
    site_packages.mkdir(parents=True)
    (site_packages / "risky.py").write_text(
        "def danger(x):\n    return x\n\n\ndef safe(x):\n    return x\n", encoding="utf-8"
    )
    dist_info = site_packages / "risky-1.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "RECORD").write_text("risky.py,,\n", encoding="utf-8")
    return root


def _advisory_for_risky() -> dict[str, list[Advisory]]:
    return {"risky": [Advisory(id="CVE-1", summary="danger() is unsafe", severity=Severity.HIGH)]}


def test_a_package_used_but_not_its_vulnerable_function_is_narrowed_away(tmp_path: Path) -> None:
    """The end-to-end payoff, through the real pipeline.

    The project calls ``risky.safe``; the advisory is about ``risky.danger``. Without
    symbols this is reachable and stays on the list forever.
    """
    project = _project_using(tmp_path, "import risky\n\n\ndef go(x):\n    return risky.safe(x)\n")

    with (
        mock.patch.object(OsvClient, "advisories_for", return_value=_advisory_for_risky()),
        mock.patch.object(SymbolExtractor, "symbols_for", return_value=("risky.danger",)),
    ):
        result = run_scan(project, cache_dir=tmp_path / "cache")

    (finding,) = result.findings
    assert finding.verdict == "not_reachable"
    assert finding.vulnerable_symbols == ("risky.danger",)
    assert result.advisories_narrowed == 1


def test_reaching_the_vulnerable_function_survives_narrowing(tmp_path: Path) -> None:
    project = _project_using(tmp_path, "import risky\n\n\ndef go(x):\n    return risky.danger(x)\n")

    with (
        mock.patch.object(OsvClient, "advisories_for", return_value=_advisory_for_risky()),
        mock.patch.object(SymbolExtractor, "symbols_for", return_value=("risky.danger",)),
    ):
        result = run_scan(project, cache_dir=tmp_path / "cache")

    (finding,) = result.findings
    assert finding.verdict == "reachable"
    assert finding.path[-1] == "risky.danger"


def test_a_hallucinated_symbol_never_reaches_a_verdict(tmp_path: Path) -> None:
    """The safety property, asserted on the pipeline rather than on the verifier alone.

    ``risky.danger_unsafe`` does not exist. Narrowing to it would find no path and report
    a real advisory as unreachable. Verification must drop it first, leaving the
    package-level verdict standing.
    """
    project = _project_using(tmp_path, "import risky\n\n\ndef go(x):\n    return risky.danger(x)\n")

    with (
        mock.patch.object(OsvClient, "advisories_for", return_value=_advisory_for_risky()),
        mock.patch.object(SymbolExtractor, "symbols_for", return_value=("risky.danger_unsafe",)),
    ):
        result = run_scan(project, cache_dir=tmp_path / "cache")

    (finding,) = result.findings
    assert finding.vulnerable_symbols == ()
    assert finding.verdict == "reachable"
    assert result.symbols_dropped == 1
    assert result.advisories_narrowed == 0


def test_a_failed_extraction_leaves_the_package_verdict_alone(tmp_path: Path) -> None:
    """``None`` from the extractor must not read as "this advisory names nothing"."""
    project = _project_using(tmp_path, "import risky\n\n\ndef go(x):\n    return risky.safe(x)\n")

    with (
        mock.patch.object(OsvClient, "advisories_for", return_value=_advisory_for_risky()),
        mock.patch.object(SymbolExtractor, "symbols_for", return_value=None),
    ):
        result = run_scan(project, cache_dir=tmp_path / "cache")

    (finding,) = result.findings
    assert finding.vulnerable_symbols == ()
    assert finding.verdict == "reachable"


def test_an_offline_scan_reports_that_verdicts_are_package_level(tmp_path: Path) -> None:
    """--offline must degrade and say so, not fail."""
    result = run_scan(SAMPLE_PROJECT, offline=True, cache_dir=tmp_path)
    assert result.symbol_extraction_available is False
