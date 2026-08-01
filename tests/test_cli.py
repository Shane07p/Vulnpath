"""CLI contract tests.

These lock the flag surface. A later phase filling in behaviour must not silently
rename or drop a flag — that breaks anyone's CI invocation.
"""

from pathlib import Path

from typer.testing import CliRunner

from vulnpath import __version__
from vulnpath.cli import app

runner = CliRunner()


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_scan_runs_on_a_directory(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0


def test_scan_rejects_a_missing_path() -> None:
    result = runner.invoke(app, ["scan", "no/such/directory"])
    assert result.exit_code != 0


def test_scan_declares_the_full_flag_surface() -> None:
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    for flag in ("--format", "--offline", "--only-reachable", "--min-severity", "--fail-on"):
        assert flag in result.output


def test_scan_rejects_an_unknown_format() -> None:
    result = runner.invoke(app, ["scan", ".", "--format", "yaml"])
    assert result.exit_code != 0


def test_explain_takes_an_advisory_id() -> None:
    result = runner.invoke(app, ["explain", "CVE-2020-14343"])
    assert result.exit_code == 0
    assert "CVE-2020-14343" in result.output
