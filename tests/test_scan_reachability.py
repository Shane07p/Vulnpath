"""The wiring between the scan pipeline and reachability analysis.

Covered separately from the reachability rules themselves, because the failure mode here
is different: the rules can be perfect while the pipeline forgets to apply them, and the
result still looks like a working scan.
"""

from pathlib import Path

from vulnpath.models import Advisory, Finding, Package, ScanResult, Severity
from vulnpath.scan import analyse_reachability


def _project_with_env(root: Path, body: str, dependency: str) -> Path:
    """A project with a real .venv layout, so environment discovery finds it."""
    package = root / "app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "main.py").write_text(body, encoding="utf-8")

    site_packages = root / ".venv" / "Lib" / "site-packages"
    site_packages.mkdir(parents=True)
    (site_packages / f"{dependency}.py").write_text(
        "def danger():\n    return 1\n", encoding="utf-8"
    )

    dist_info = site_packages / f"{dependency}-1.0.dist-info"
    dist_info.mkdir()
    (dist_info / "RECORD").write_text(f"{dependency}.py,,\n", encoding="utf-8")
    return root


def test_no_environment_means_no_analysis_rather_than_a_clean_result(tmp_path: Path) -> None:
    """A scan that could not look is not a scan that found nothing.

    Without dependency source there is no basis for any verdict, so the pipeline reports
    that it did not analyse rather than leaving findings looking cleared.
    """
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "__init__.py").write_text("", encoding="utf-8")

    index, imports, stats = analyse_reachability(tmp_path, None)
    assert index is None
    assert imports == {}
    assert stats["graph_nodes"] == 0


def test_an_environment_is_analysed_and_its_import_names_returned(tmp_path: Path) -> None:
    project = _project_with_env(
        tmp_path, "import risky\n\n\ndef go():\n    return risky.danger()\n", "risky"
    )
    index, imports, stats = analyse_reachability(project, None)

    assert index is not None
    assert imports["risky"] == frozenset({"risky"})
    assert stats["graph_nodes"] > 0
    assert stats["dependency_modules_parsed"] >= 1


def test_a_reachable_package_is_reported_as_such(tmp_path: Path) -> None:
    project = _project_with_env(
        tmp_path, "import risky\n\n\ndef go():\n    return risky.danger()\n", "risky"
    )
    index, imports, _ = analyse_reachability(project, None)
    assert index is not None

    result = index.analyse(imports["risky"])
    assert result.verdict.value == "reachable"
    assert result.path


def test_an_unimported_package_is_reported_as_not_reachable(tmp_path: Path) -> None:
    project = _project_with_env(tmp_path, "def go():\n    return 1\n", "risky")
    index, imports, _ = analyse_reachability(project, None)
    assert index is not None

    assert index.analyse(imports["risky"]).verdict.value == "not_reachable"


# --- what a verdict means downstream ------------------------------------------------


def _finding(verdict: str) -> Finding:
    return Finding(
        package=Package(name="risky", version="1.0", depth=1),
        advisory=Advisory(id="CVE-1", severity=Severity.HIGH),
        verdict=verdict,
    )


def test_only_a_proven_negative_is_suppressible() -> None:
    assert _finding("not_reachable").is_suppressible


def test_an_unknown_verdict_is_never_suppressible() -> None:
    """Hiding it would turn the analyser's blind spot into a claim that nothing is there."""
    assert not _finding("unknown").is_suppressible


def test_a_reachable_verdict_is_never_suppressible() -> None:
    assert not _finding("reachable").is_suppressible


def test_a_finding_defaults_to_unknown_before_analysis_runs() -> None:
    """The safe default. A finding nobody analysed is not a finding nobody needs."""
    finding = Finding(
        package=Package(name="risky", version="1.0", depth=1),
        advisory=Advisory(id="CVE-1"),
    )
    assert finding.verdict == "unknown"
    assert not finding.is_suppressible


def test_a_scan_records_whether_reachability_ran() -> None:
    """--format json consumers need to tell "nothing reachable" from "nothing analysed"."""
    assert ScanResult(project_path=".").reachability_analysed is False
