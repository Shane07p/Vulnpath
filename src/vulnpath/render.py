"""Output rendering. The only module allowed to write to the terminal.

Two audiences, two shapes: a table for a human deciding what to fix, and JSON for a
script. Nothing here computes anything — if a value needs deriving, it belongs upstream.
"""

from __future__ import annotations

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vulnpath.console import console, err_console
from vulnpath.models import Finding, ScanResult, Severity

SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.UNKNOWN: "dim",
}

SEVERITY_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MED ",
    Severity.LOW: "LOW ",
    Severity.UNKNOWN: " ?  ",
}
"""Padded to equal width so the column never reflows. Four characters survives an
80-column terminal, which a full word does not."""


def _severity_badge(severity: Severity) -> Text:
    return Text(f" {SEVERITY_LABEL[severity]} ", style=SEVERITY_STYLE[severity])


def _package_cell(finding: Finding) -> Text:
    package = finding.package
    text = Text(package.name, style="bold")
    text.append(f"\n{package.version}", style="dim")
    if not package.is_direct:
        text.append(f"\ndepth {package.depth}", style="dim italic")
    return text


def _fix_cell(finding: Finding) -> Text:
    fixed = finding.advisory.fixed_versions
    if not fixed:
        return Text("none", style="bold magenta")
    text = Text(fixed[0], style="green")
    if len(fixed) > 1:
        text.append(f"\n+{len(fixed) - 1} more", style="dim")
    return text


def _summary_cell(finding: Finding) -> Text:
    advisory = finding.advisory
    summary = advisory.summary or advisory.details.split("\n", 1)[0] or "(no summary)"
    return Text(summary.strip())


def header(result: ScanResult) -> Panel:
    title = Text("vulnpath", style="bold cyan")
    title.append("  ")
    title.append(result.project_path, style="white")

    subtitle = Text(f"{result.packages_scanned} packages resolved", style="dim")
    if result.offline:
        subtitle.append("  ·  ", style="dim")
        subtitle.append("offline", style="bold yellow")

    body = Text.assemble(title, "\n", subtitle)
    return Panel(body, box=box.ROUNDED, border_style="cyan", padding=(0, 2))


def findings_table(result: ScanResult) -> Table:
    table = Table(
        box=box.SIMPLE,
        header_style="bold dim",
        show_lines=True,
        pad_edge=False,
        expand=True,
    )
    # Fixed widths on everything except the summary. Without them Rich divides the
    # space evenly and every column loses to the prose one, which is how a 5-column
    # table turns into unreadable one-character stripes at 80 columns.
    table.add_column("", width=6, no_wrap=True)
    table.add_column("ADVISORY", width=20, no_wrap=True)
    table.add_column("PACKAGE", width=14, overflow="fold")
    table.add_column("FIX", width=10, overflow="fold")
    table.add_column("SUMMARY", ratio=1, overflow="fold", min_width=20)

    for finding in result.sorted_findings:
        table.add_row(
            _severity_badge(finding.advisory.severity),
            Text(finding.advisory.display_id, style="bold"),
            _package_cell(finding),
            _fix_cell(finding),
            _summary_cell(finding),
        )
    return table


def counts_line(result: ScanResult) -> Text:
    tally: dict[Severity, int] = {}
    for finding in result.findings:
        tally[finding.advisory.severity] = tally.get(finding.advisory.severity, 0) + 1

    line = Text()
    line.append(f"{len(result.findings)} findings", style="bold")
    line.append(f" across {result.packages_scanned} packages", style="dim")

    for severity in (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.UNKNOWN,
    ):
        count = tally.get(severity)
        if count:
            line.append("  ·  ", style="dim")
            line.append(f"{count} {severity.value}", style=SEVERITY_STYLE[severity])
    return line


def render_table(result: ScanResult) -> None:
    console.print()
    console.print(header(result))

    if not result.findings:
        console.print()
        console.print(Text("  No known advisories for the resolved packages.", style="bold green"))
        console.print()
        return

    console.print(findings_table(result))
    console.print(counts_line(result))
    console.print()


def render_json(result: ScanResult) -> None:
    """Machine output. Plain, unstyled, and the only thing on stdout."""
    console.print(result.model_dump_json(indent=2), soft_wrap=True, markup=False)


def warn(message: str) -> None:
    """Diagnostics go to stderr so ``--format json`` stays parseable."""
    err_console.print(Text(f"warning: {message}", style="yellow"))


def error(message: str) -> None:
    err_console.print(Text(f"error: {message}", style="bold red"))
