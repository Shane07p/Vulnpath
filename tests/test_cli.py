"""CLI contract tests.

These lock the flag surface. Filling in behaviour later must not silently rename or
drop a flag — that breaks anyone's CI invocation.
"""

from pathlib import Path
from unittest import mock

import typer.main
from typer.core import TyperGroup
from typer.testing import CliRunner

from vulnpath import __version__
from vulnpath.cli import app
from vulnpath.models import Advisory, Finding, Package, ScanResult, Severity

runner = CliRunner()


def declared_options(command_name: str) -> set[str]:
    """Every option string the parser will accept for a subcommand.

    Introspects the parser instead of scraping ``--help``. Help text is rendered by
    Rich, and whether it carries colour escapes depends on the terminal — so
    substring assertions against it pass locally and fail in CI.
    """
    group = typer.main.get_command(app)
    assert isinstance(group, TyperGroup)
    return {opt for param in group.commands[command_name].params for opt in param.opts}


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_scan_on_a_directory_without_a_lockfile_explains_itself(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 2
    assert "uv lock" in result.output


def test_scan_rejects_a_missing_path() -> None:
    result = runner.invoke(app, ["scan", "no/such/directory"])
    assert result.exit_code != 0


def test_scan_declares_the_full_flag_surface() -> None:
    options = declared_options("scan")
    for flag in (
        "--format",
        "--offline",
        "--only-reachable",
        "--min-severity",
        "--fail-on",
        "--python",
    ):
        assert flag in options


def test_min_severity_accepts_four_levels_and_not_unknown() -> None:
    """``unknown`` is a severity a finding can have, not a floor you can ask for."""
    group = typer.main.get_command(app)
    assert isinstance(group, TyperGroup)
    (param,) = [p for p in group.commands["scan"].params if "--min-severity" in p.opts]
    choices = getattr(param.type, "choices", None)
    assert choices is not None
    assert set(choices) == {"low", "medium", "high", "critical"}


def test_sarif_is_declared_but_reports_that_it_is_unimplemented(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "sarif"])
    assert result.exit_code == 2


def test_scan_help_renders() -> None:
    assert runner.invoke(app, ["scan", "--help"]).exit_code == 0


def test_scan_rejects_an_unknown_format() -> None:
    result = runner.invoke(app, ["scan", ".", "--format", "yaml"])
    assert result.exit_code != 0


def test_explain_takes_an_advisory_id() -> None:
    result = runner.invoke(app, ["explain", "CVE-2020-14343"])
    assert result.exit_code == 0
    assert "CVE-2020-14343" in result.output


def test_a_directory_without_a_lockfile_fails_whatever_flags_are_passed(tmp_path: Path) -> None:
    """Exit 2 for a usage problem, distinct from exit 1 for findings.

    A CI job must be able to tell "your gate tripped" from "the tool could not run".
    """
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "reachable"])
    assert result.exit_code == 2
    assert "uv lock" in result.output


# --- verdict-driven flags -----------------------------------------------------------
# These were declared in the first commit and inert until reachability landed. The risk
# now is the opposite of before: they run, so a wrong filter silently hides real findings.


def _scan_result_with(verdicts: list[str]) -> ScanResult:
    return ScanResult(
        project_path="proj",
        packages_scanned=3,
        reachability_analysed=True,
        findings=[
            Finding(
                package=Package(name=f"pkg{i}", version="1.0", depth=1),
                advisory=Advisory(id=f"CVE-{i}", severity=Severity.HIGH),
                verdict=verdict,
            )
            for i, verdict in enumerate(verdicts)
        ],
    )


def test_only_reachable_drops_proven_negatives(tmp_path: Path) -> None:
    result = _scan_result_with(["reachable", "not_reachable"])
    with mock.patch("vulnpath.cli.run_scan", return_value=result):
        invocation = runner.invoke(app, ["scan", str(tmp_path), "--only-reachable"])

    assert invocation.exit_code == 0
    assert len(result.findings) == 1
    assert result.findings[0].verdict == "reachable"


def test_only_reachable_keeps_unknowns(tmp_path: Path) -> None:
    """The whole point of the third verdict.

    Dropping an unknown alongside a proven negative would turn "we could not tell" into
    "there is nothing here", which is the claim this project refuses to make.
    """
    result = _scan_result_with(["unknown", "not_reachable"])
    with mock.patch("vulnpath.cli.run_scan", return_value=result):
        runner.invoke(app, ["scan", str(tmp_path), "--only-reachable"])

    assert [f.verdict for f in result.findings] == ["unknown"]


def test_fail_on_reachable_exits_non_zero_when_a_path_was_found(tmp_path: Path) -> None:
    with mock.patch("vulnpath.cli.run_scan", return_value=_scan_result_with(["reachable"])):
        assert runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "reachable"]).exit_code == 1


def test_fail_on_reachable_passes_when_nothing_is_reached(tmp_path: Path) -> None:
    """The gate a team will leave switched on: it does not fail a build over a CVE in
    code nobody calls."""
    result = _scan_result_with(["not_reachable", "unknown"])
    with mock.patch("vulnpath.cli.run_scan", return_value=result):
        assert runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "reachable"]).exit_code == 0


def test_fail_on_any_still_gates_on_every_finding(tmp_path: Path) -> None:
    with mock.patch("vulnpath.cli.run_scan", return_value=_scan_result_with(["not_reachable"])):
        assert runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "any"]).exit_code == 1


def test_a_scan_with_no_environment_says_the_verdicts_are_unproven(tmp_path: Path) -> None:
    result = _scan_result_with(["unknown"])
    result.reachability_analysed = False
    with mock.patch("vulnpath.cli.run_scan", return_value=result):
        invocation = runner.invoke(app, ["scan", str(tmp_path)])

    assert "no call paths could be traced" in invocation.output
