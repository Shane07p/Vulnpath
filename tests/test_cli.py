"""CLI contract tests.

These lock the flag surface. A later phase filling in behaviour must not silently
rename or drop a flag — that breaks anyone's CI invocation.
"""

from pathlib import Path

import typer.main
from typer.core import TyperGroup
from typer.testing import CliRunner

from vulnpath import __version__
from vulnpath.cli import app

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


def test_fail_on_reachable_refuses_rather_than_passing_silently(tmp_path: Path) -> None:
    """A gate that cannot gate must fail loudly.

    Warning and exiting 0 would leave a CI job configured with this flag green on
    every build, which is worse than having no gate configured at all.
    """
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "reachable"])
    assert result.exit_code == 2
