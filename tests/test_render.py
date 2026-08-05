"""Output rendering.

The JSON test is the important one: it is a regression guard for colour escapes
leaking into machine-readable output.
"""

import json

from vulnpath.console import console
from vulnpath.models import (
    Advisory,
    BlockingParent,
    Finding,
    Fix,
    FixShape,
    Package,
    ScanResult,
    Severity,
)
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
    _, findings = group_by_package(result)[0]
    assert [f.advisory.severity for f in findings] == [Severity.HIGH, Severity.LOW]


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


# --- fixes -------------------------------------------------------------------------


def _fixed_finding(shape: FixShape, command: str | None, reason: str) -> Finding:
    finding = _finding("urllib3", "CVE-1", Severity.HIGH)
    finding.fix = Fix(shape=shape, target_version="1.26.17", command=command, reason=reason)
    return finding


def test_the_fix_command_is_shown() -> None:
    finding = _fixed_finding(
        FixShape.DIRECT_BUMP, 'uv add "urllib3>=1.26.17"', "Your pin forbids it."
    )
    with console.capture() as capture:
        render_table(_result(finding))
    assert 'uv add "urllib3>=1.26.17"' in capture.get()


def test_the_shape_is_named() -> None:
    finding = _fixed_finding(FixShape.LOCKFILE_REFRESH, "uv lock", "Stale lockfile.")
    with console.capture() as capture:
        render_table(_result(finding))
    assert "LOCKFILE_REFRESH" in capture.get()


def test_no_fix_says_so_without_offering_a_command() -> None:
    finding = _fixed_finding(FixShape.NO_FIX, None, "No released version fixes this.")
    with console.capture() as capture:
        render_table(_result(finding))
    output = capture.get()
    assert "NO_FIX" in output
    assert "uv add" not in output


def test_unknown_fix_reads_as_unproven_not_as_safe() -> None:
    """A user must not read UNKNOWN as "nothing to do here"."""
    finding = _fixed_finding(FixShape.UNKNOWN, None, "Could not reach PyPI.")
    with console.capture() as capture:
        render_table(_result(finding))
    output = capture.get()
    assert "UNKNOWN" in output
    assert "Could not reach PyPI" in output


def test_a_blocking_parent_and_its_upgrade_are_named() -> None:
    finding = _finding("urllib3", "CVE-1", Severity.HIGH)
    finding.fix = Fix(
        shape=FixShape.OVERRIDE,
        target_version="2.0.6",
        command='uv add "requests>=2.32.5"',
        reason="requests blocks it.",
        blocking_parents=(
            BlockingParent(name="requests", constraint="<1.27", upgrade_to="2.32.5"),
        ),
    )
    with console.capture() as capture:
        render_table(_result(finding))
    output = capture.get()
    assert "blocked by" in output
    assert "requests" in output


def test_a_finding_without_a_fix_still_renders() -> None:
    """Classification is optional; the renderer must not require it."""
    with console.capture() as capture:
        render_table(_result(_finding("urllib3", "CVE-1", Severity.HIGH)))
    assert "urllib3" in capture.get()
