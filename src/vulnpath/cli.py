"""CLI surface.

The flag set is declared in full from the start so later phases fill in behaviour
instead of renegotiating names. Everything here is currently inert.
"""

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from vulnpath import __version__
from vulnpath.console import console


class OutputFormat(StrEnum):
    """How findings are rendered."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


class Severity(StrEnum):
    """Advisory severity floor."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FailOn(StrEnum):
    """What makes the process exit non-zero, for CI gating."""

    NEVER = "never"
    REACHABLE = "reachable"
    ANY = "any"


app = typer.Typer(
    name="vulnpath",
    help="Which CVEs does your code actually reach, and what shape of fix does each need?",
    no_args_is_help=True,
    add_completion=True,
)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"vulnpath {__version__}")
        raise typer.Exit


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """Reachability-aware dependency triage for Python."""


@app.command()
def scan(
    path: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False, help="Project root containing uv.lock."),
    ] = Path(),
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Output format.")
    ] = OutputFormat.TABLE,
    offline: Annotated[
        bool, typer.Option("--offline", help="No network. Degrades to import-level reachability.")
    ] = False,
    only_reachable: Annotated[
        bool, typer.Option("--only-reachable", help="Hide NOT_REACHABLE findings.")
    ] = False,
    min_severity: Annotated[
        Severity, typer.Option("--min-severity", help="Drop findings below this severity.")
    ] = Severity.LOW,
    fail_on: Annotated[
        FailOn, typer.Option("--fail-on", help="Exit non-zero on findings of this class.")
    ] = FailOn.NEVER,
) -> None:
    """Scan a project for reachable vulnerabilities."""
    console.print("[yellow]scan: not implemented yet (phase 0 skeleton)[/yellow]")


@app.command()
def explain(
    advisory_id: Annotated[str, typer.Argument(help="Advisory ID, e.g. CVE-2020-14343.")],
) -> None:
    """Show the full reachability path and fix reasoning for one finding."""
    console.print(f"[yellow]explain {advisory_id}: not implemented yet (phase 0 skeleton)[/yellow]")
