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
    package_heading,
    render_guide,
    render_json,
    render_table,
    shorten_path,
    split_by_relevance,
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


def test_totals_lead_with_the_reachable_count() -> None:
    """The line someone screenshots.

    Every scanner prints a finding count; the reachable count is the reason to install
    this one, so it appears first and the two negatives follow. Asserted against the
    Text object because the segments are styled differently, and a substring match on
    rendered output would trip over the escape codes between them.
    """
    reachable = _finding("pyyaml", "CVE-2020-14343", Severity.CRITICAL)
    reachable.verdict = "reachable"
    ignorable = _finding("markupsafe", "CVE-2", Severity.UNKNOWN, depth=2)
    ignorable.verdict = "not_reachable"

    plain = totals_line(_result(reachable, ignorable)).plain
    assert "2 findings" in plain
    assert "1 reachable" in plain
    assert "1 not reachable" in plain
    assert plain.index("reachable") < plain.index("not reachable")


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


# --- ranking and collapsing ---------------------------------------------------------
# SPEC: reachable+fixable -> reachable+no-fix -> unknown -> not-reachable, severity as
# tiebreak. Verdict outranks severity, so a critical finding in unreachable code sorts
# below a medium one on a live path.


def _verdict_finding(
    package: str, severity: Severity, verdict: str, *, fixable: bool = True
) -> Finding:
    finding = _finding(package, f"CVE-{package}", severity)
    finding.verdict = verdict
    finding.reachability_reason = "because"
    finding.fix = Fix(
        shape=FixShape.DIRECT_BUMP if fixable else FixShape.NO_FIX,
        target_version="2.0.0" if fixable else None,
        command='uv add "x>=2.0.0"' if fixable else None,
        reason="reason",
    )
    return finding


def test_a_reachable_medium_outranks_an_unreachable_critical() -> None:
    """The ordering that makes the tool worth reading.

    Sorting by severity first puts a critical nothing imports above a medium on a live
    call path, which buries the finding that matters under the one that does not.
    """
    unreachable = _verdict_finding("gitpython", Severity.CRITICAL, "not_reachable")
    reachable = _verdict_finding("jinja2", Severity.MEDIUM, "reachable")

    ordered = ScanResult(project_path="p", findings=[unreachable, reachable]).sorted_findings
    assert [f.package.name for f in ordered] == ["jinja2", "gitpython"]


def test_unknown_sorts_between_the_two_certainties() -> None:
    findings = [
        _verdict_finding("c", Severity.HIGH, "not_reachable"),
        _verdict_finding("a", Severity.HIGH, "reachable"),
        _verdict_finding("b", Severity.HIGH, "unknown"),
    ]
    ordered = ScanResult(project_path="p", findings=findings).sorted_findings
    assert [f.verdict for f in ordered] == ["reachable", "unknown", "not_reachable"]


def test_a_fixable_finding_outranks_one_with_no_fix_at_equal_verdict() -> None:
    """Both need attention; only one can be acted on now."""
    findings = [
        _verdict_finding("nofix", Severity.HIGH, "reachable", fixable=False),
        _verdict_finding("fixable", Severity.HIGH, "reachable"),
    ]
    ordered = ScanResult(project_path="p", findings=findings).sorted_findings
    assert [f.package.name for f in ordered] == ["fixable", "nofix"]


def test_severity_still_breaks_ties_within_a_verdict() -> None:
    findings = [
        _verdict_finding("low", Severity.LOW, "reachable"),
        _verdict_finding("crit", Severity.CRITICAL, "reachable"),
    ]
    ordered = ScanResult(project_path="p", findings=findings).sorted_findings
    assert [f.package.name for f in ordered] == ["crit", "low"]


def test_packages_with_nothing_reachable_are_split_out() -> None:
    result = _result(
        _verdict_finding("jinja2", Severity.MEDIUM, "reachable"),
        _verdict_finding("gitpython", Severity.CRITICAL, "not_reachable"),
    )
    relevant, ignorable = split_by_relevance(group_by_package(result))

    assert [p.name for p, _ in relevant] == ["jinja2"]
    assert [p.name for p, _ in ignorable] == ["gitpython"]


def test_a_package_with_one_unknown_among_negatives_is_not_collapsed() -> None:
    """Collapsing is per package, and an unknown anywhere in it is still worth reading."""
    unknown = _verdict_finding("urllib3", Severity.HIGH, "unknown")
    negative = _finding("urllib3", "CVE-other", Severity.LOW)
    negative.verdict = "not_reachable"

    relevant, ignorable = split_by_relevance(group_by_package(_result(unknown, negative)))
    assert [p.name for p, _ in relevant] == ["urllib3"]
    assert ignorable == []


def test_collapsed_packages_are_still_named_and_counted() -> None:
    """Silent suppression is how a scanner loses trust, and the totals must reconcile."""
    result = _result(
        _verdict_finding("jinja2", Severity.MEDIUM, "reachable"),
        _verdict_finding("gitpython", Severity.CRITICAL, "not_reachable"),
    )
    with console.capture() as capture:
        render_table(result)

    output = capture.get()
    assert "gitpython" in output
    assert "nothing reaches these" in output
    assert "--show-all" in output


def test_show_all_expands_the_collapsed_packages() -> None:
    result = _result(_verdict_finding("gitpython", Severity.CRITICAL, "not_reachable"))
    with console.capture() as capture:
        render_table(result, show_all=True)
    assert "nothing reaches these" not in capture.get()


def test_the_verdict_appears_once_on_the_package_heading() -> None:
    """It is a property of the package, not of each advisory in it."""
    first = _verdict_finding("jinja2", Severity.HIGH, "reachable")
    second = _finding("jinja2", "CVE-second", Severity.MEDIUM)
    second.verdict = "reachable"
    second.reachability_reason = "because"

    heading = package_heading(*group_by_package(_result(first, second))[0])
    assert "REACHABLE" in heading.plain
    assert "2 advisories" in heading.plain


def test_a_long_project_path_keeps_its_tail() -> None:
    """The last components identify the project; the leading temp directory does not."""
    shortened = shorten_path("/home/x/.cache/tmp/deep/nested/dirs/my-project", 30)
    assert shortened.endswith("my-project")
    assert len(shortened) == 30
    assert shortened.startswith("...")


def test_a_short_path_is_left_alone() -> None:
    assert shorten_path("./my-project") == "./my-project"
