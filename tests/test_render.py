"""Output rendering.

The JSON test is the important one: it is a regression guard for colour escapes
leaking into machine-readable output.
"""

import json

from vulnpath.console import console
from vulnpath.models import Advisory, Finding, Package, ScanResult, Severity
from vulnpath.render import (
    SCAN_OPTIONS,
    group_by_package,
    render_guide,
    render_json,
    render_table,
    totals_line,
)


def _finding(package: str, advisory_id: str, severity: Severity, depth: int = 1) -> Finding:
    return Finding(
        package=Package(name=package, version="1.0.0", depth=depth),
        advisory=Advisory(
            id=advisory_id,
            aliases=(advisory_id,),
            summary=f"Something wrong in {package}",
            severity=severity,
            fixed_versions=("2.0.0",),
        ),
    )


def _result(*findings: Finding) -> ScanResult:
    return ScanResult(project_path="proj", findings=list(findings), packages_scanned=9)


def test_findings_are_grouped_one_entry_per_package() -> None:
    result = _result(
        _finding("urllib3", "CVE-1", Severity.MEDIUM),
        _finding("urllib3", "CVE-2", Severity.HIGH),
        _finding("pyyaml", "CVE-3", Severity.CRITICAL),
    )
    groups = group_by_package(result)
    assert [package.name for package, _ in groups] == ["pyyaml", "urllib3"]

    by_name = {package.name: advisories for package, advisories in groups}
    assert len(by_name["urllib3"]) == 2
    assert len(by_name["pyyaml"]) == 1


def test_worst_affected_package_comes_first() -> None:
    result = _result(
        _finding("urllib3", "CVE-1", Severity.MEDIUM),
        _finding("pyyaml", "CVE-2", Severity.CRITICAL),
    )
    assert group_by_package(result)[0][0].name == "pyyaml"


def test_advisories_within_a_package_are_worst_first() -> None:
    result = _result(
        _finding("urllib3", "CVE-low", Severity.LOW),
        _finding("urllib3", "CVE-high", Severity.HIGH),
    )
    _, advisories = group_by_package(result)[0]
    assert [a.severity for a in advisories] == [Severity.HIGH, Severity.LOW]


def test_unknown_severity_packages_still_appear() -> None:
    result = _result(_finding("idna", "PYSEC-1", Severity.UNKNOWN))
    assert [p.name for p, _ in group_by_package(result)] == ["idna"]


def test_json_output_is_parseable() -> None:
    """Guards the bug where Rich injected colour escapes inside printed values."""
    result = _result(_finding("pyyaml", "CVE-2020-14343", Severity.CRITICAL))
    with console.capture() as capture:
        render_json(result)

    payload = json.loads(capture.get())
    assert payload["findings"][0]["advisory"]["id"] == "CVE-2020-14343"
    assert payload["findings"][0]["package"]["name"] == "pyyaml"


def test_json_survives_characters_the_console_cannot_encode() -> None:
    finding = _finding("pyyaml", "CVE-1", Severity.HIGH)
    finding.advisory.summary = "redirect → leak, naïve parsing"
    with console.capture() as capture:
        render_json(_result(finding))

    assert json.loads(capture.get())["findings"][0]["advisory"]["summary"].startswith("redirect")


def test_table_renders_findings_without_crashing() -> None:
    result = _result(
        _finding("pyyaml", "CVE-2020-14343", Severity.CRITICAL),
        _finding("markupsafe", "CVE-2", Severity.UNKNOWN, depth=2),
    )
    with console.capture() as capture:
        render_table(result)

    assert "pyyaml" in capture.get()


def test_totals_count_findings_and_affected_packages() -> None:
    """Asserted against the Text object, not the rendered output.

    ``totals_line`` styles its two halves differently, so the rendered string carries
    escape codes between them and a substring match on the capture would fail.
    """
    result = _result(
        _finding("pyyaml", "CVE-2020-14343", Severity.CRITICAL),
        _finding("markupsafe", "CVE-2", Severity.UNKNOWN, depth=2),
    )
    assert totals_line(result).plain.strip() == "2 findings in 2 of 9 packages"


def test_clean_project_says_so_rather_than_printing_an_empty_table() -> None:
    with console.capture() as capture:
        render_table(ScanResult(project_path="proj", packages_scanned=4))
    assert "No known advisories" in capture.get()


def test_transitive_depth_is_shown() -> None:
    with console.capture() as capture:
        render_table(_result(_finding("markupsafe", "CVE-1", Severity.LOW, depth=3)))
    assert "depth 3" in capture.get()


# --- guide ------------------------------------------------------------------------


def test_guide_lists_every_command() -> None:
    with console.capture() as capture:
        render_guide()
    output = capture.get()
    for command in ("scan", "explain", "guide"):
        assert command in output


def test_guide_marks_unimplemented_features_rather_than_hiding_them() -> None:
    """A guide that lists a dead flag beside a working one is worse than no guide."""
    with console.capture() as capture:
        render_guide()
    output = capture.get()
    assert "planned" in output


def test_every_declared_scan_option_appears_in_the_guide() -> None:
    """Catches a flag being added to the CLI and never documented."""
    import typer.main
    from typer.core import TyperGroup

    from vulnpath.cli import app

    group = typer.main.get_command(app)
    assert isinstance(group, TyperGroup)
    declared = {
        opt for param in group.commands["scan"].params for opt in param.opts if opt.startswith("--")
    }
    documented = {name.split()[0] for name, _, _ in SCAN_OPTIONS}
    assert declared - documented == set()
