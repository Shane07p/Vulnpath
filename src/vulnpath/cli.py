"""CLI surface.

The flag set is declared in full from the start so later phases fill in behaviour
instead of renegotiating names. Everything here is currently inert.
"""

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from vulnpath import __version__, render
from vulnpath.console import console
from vulnpath.environment import EnvironmentError_
from vulnpath.lockfile import LockfileError
from vulnpath.models import Severity
from vulnpath.scan import environment_drift, run_scan


class OutputFormat(StrEnum):
    """How findings are rendered."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


class SeverityFloor(StrEnum):
    """Accepted values for ``--min-severity``.

    Four values, not five: ``unknown`` is a severity a *finding* can have, but asking
    for "unknown and above" is meaningless. Findings with unknown severity bypass this
    filter entirely rather than being hidden by it — see ``scan.passes_severity_floor``.
    """

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
        SeverityFloor | None,
        typer.Option("--min-severity", help="Drop findings below this severity."),
    ] = None,
    fail_on: Annotated[
        FailOn, typer.Option("--fail-on", help="Exit non-zero on findings of this class.")
    ] = FailOn.NEVER,
    python: Annotated[
        Path | None,
        typer.Option("--python", help="Virtualenv of the project being scanned."),
    ] = None,
) -> None:
    """Scan a project for reachable vulnerabilities."""
    if output_format is OutputFormat.SARIF:
        render.error("SARIF output is not implemented yet.")
        raise typer.Exit(2)
    if fail_on is FailOn.REACHABLE:
        # Exit rather than warn. A CI gate configured with this flag would otherwise
        # pass every build while printing a warning nobody reads into stderr, which is
        # worse than having no gate at all.
        render.error("--fail-on reachable cannot gate yet; reachability analysis is not built.")
        raise typer.Exit(2)
    if only_reachable:
        render.warn("--only-reachable has no effect yet; reachability analysis is not built.")

    floor = Severity(min_severity.value) if min_severity is not None else None

    try:
        with render.working("Resolving lockfile and querying OSV..."):
            result = run_scan(path, offline=offline, severity_floor=floor)
    except (LockfileError, EnvironmentError_) as exc:
        render.error(str(exc))
        raise typer.Exit(2) from exc

    if output_format is OutputFormat.JSON:
        render.render_json(result)
    else:
        render.render_table(result)
        for message in environment_drift(path, python):
            render.warn(message)

    if not result.is_complete:
        render.warn(
            f"{result.packages_unqueried} package(s) could not be checked "
            f"{'(offline, not cached)' if offline else '(OSV unreachable)'}. "
            "This scan does not prove those are clean."
        )

    if fail_on is FailOn.ANY and result.findings:
        raise typer.Exit(1)


@app.command()
def guide() -> None:
    """List every command and option, what each is for, and what is built yet."""
    render.render_guide()


@app.command()
def explain(
    advisory_id: Annotated[str, typer.Argument(help="Advisory ID, e.g. CVE-2020-14343.")],
) -> None:
    """Show the full reachability path and fix reasoning for one finding."""
    console.print(f"[yellow]explain {advisory_id}: not implemented yet (phase 0 skeleton)[/yellow]")
