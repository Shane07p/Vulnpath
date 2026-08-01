"""Output rendering. The only module allowed to write to the terminal.

Two audiences, two shapes: grouped output for a human deciding what to fix, and JSON
for a script. Nothing here computes anything — if a value needs deriving, it belongs
upstream.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager

from rich import box
from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vulnpath.console import console, err_console
from vulnpath.models import Advisory, Package, ScanResult, Severity, severity_rank

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
80-column terminal, which a spelled-out word does not."""

BAR_GLYPH = "█"


def _severity_badge(severity: Severity) -> Text:
    return Text(f" {SEVERITY_LABEL[severity]} ", style=SEVERITY_STYLE[severity])


def _summary_of(advisory: Advisory) -> str:
    summary = advisory.summary or advisory.details.split("\n", 1)[0] or "(no summary)"
    return summary.strip()


# --- grouping ---------------------------------------------------------------------


def group_by_package(result: ScanResult) -> list[tuple[Package, list[Advisory]]]:
    """One entry per affected package, worst-affected first.

    Findings arrive one row per advisory, and a single package can carry a dozen.
    Repeating its name and version on every row buries the thing being decided about,
    which is the package, not the advisory.
    """
    grouped: dict[str, tuple[Package, list[Advisory]]] = {}
    for finding in result.findings:
        entry = grouped.setdefault(finding.package.name, (finding.package, []))
        entry[1].append(finding.advisory)

    for _, advisories in grouped.values():
        advisories.sort(key=lambda a: (-severity_rank(a.severity), a.display_id))

    def worst(item: tuple[Package, list[Advisory]]) -> tuple[int, int, str]:
        package, advisories = item
        top = max(severity_rank(a.severity) for a in advisories)
        return (-top, package.depth, package.name)

    return sorted(grouped.values(), key=worst)


# --- pieces -----------------------------------------------------------------------


def header(result: ScanResult) -> Panel:
    title = Text("vulnpath", style="bold cyan")
    title.append("  ")
    title.append(result.project_path, style="white")

    subtitle = Text(f"{result.packages_scanned} packages resolved", style="dim")
    if result.advisories_from_cache:
        subtitle.append(f"  ·  {result.advisories_from_cache} from cache", style="dim")
    if result.offline:
        subtitle.append("  ·  ", style="dim")
        subtitle.append("offline", style="bold yellow")

    return Panel(
        Text.assemble(title, "\n", subtitle),
        box=box.ROUNDED,
        border_style="cyan",
        padding=(0, 2),
    )


def package_heading(package: Package, advisories: list[Advisory]) -> Text:
    heading = Text("  ")
    heading.append(package.name, style="bold white")
    heading.append(f" {package.version}", style="white")
    heading.append("  ·  ", style="dim")
    heading.append(
        "direct" if package.is_direct else f"transitive · depth {package.depth}",
        style="cyan" if package.is_direct else "dim",
    )
    heading.append(f"  ·  {len(advisories)} advisor{'y' if len(advisories) == 1 else 'ies'}", "dim")
    return heading


def advisory_rows(advisories: list[Advisory]) -> Table:
    """Borderless grid. Widths are pinned so the prose column cannot starve the rest."""
    table = Table(box=None, show_header=False, expand=True, pad_edge=False, padding=(0, 1))
    table.add_column(width=8, no_wrap=True)
    table.add_column(width=20, no_wrap=True)
    table.add_column(width=12, overflow="fold")
    table.add_column(ratio=1, overflow="fold", min_width=20)

    for advisory in advisories:
        fixed = advisory.fixed_versions
        if fixed:
            fix = Text(fixed[0], style="green")
            if len(fixed) > 1:
                fix.append(f" +{len(fixed) - 1}", style="dim")
        else:
            fix = Text("no fix", style="bold magenta")

        table.add_row(
            _severity_badge(advisory.severity),
            Text(advisory.display_id, style="bold"),
            fix,
            Text(_summary_of(advisory), style="dim"),
        )
    return table


def severity_bars(result: ScanResult) -> Table:
    """A count is a number; a bar is a shape. The shape is what gets read at a glance."""
    tally: dict[Severity, int] = {}
    for finding in result.findings:
        tally[finding.advisory.severity] = tally.get(finding.advisory.severity, 0) + 1

    present = [s for s in Severity if tally.get(s)]
    widest = max((tally[s] for s in present), default=1)

    table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 1))
    table.add_column(width=8, no_wrap=True)
    table.add_column(width=24, no_wrap=True)
    table.add_column(no_wrap=True)

    for severity in sorted(present, key=severity_rank, reverse=True):
        count = tally[severity]
        filled = max(1, round(count / widest * 20))
        table.add_row(
            Text(f"  {SEVERITY_LABEL[severity].strip()}", style=SEVERITY_STYLE[severity]),
            Text(BAR_GLYPH * filled, style=SEVERITY_STYLE[severity]),
            Text(str(count), style="bold"),
        )
    return table


def totals_line(result: ScanResult) -> Text:
    affected = len({f.package.name for f in result.findings})
    line = Text("  ")
    line.append(f"{len(result.findings)} findings", style="bold")
    line.append(f" in {affected} of {result.packages_scanned} packages", style="dim")
    return line


# --- entry points -----------------------------------------------------------------


def render_table(result: ScanResult) -> None:
    console.print()
    console.print(header(result))

    if not result.findings:
        console.print()
        console.print(Text("  No known advisories for the resolved packages.", style="bold green"))
        console.print()
        return

    blocks: list[RenderableType] = [Text()]
    for package, advisories in group_by_package(result):
        blocks.append(package_heading(package, advisories))
        # One column of left padding so the severity badges line up under the package
        # name rather than hanging off its left edge.
        blocks.append(Padding(advisory_rows(advisories), (0, 0, 0, 1)))
        blocks.append(Text())

    console.print(Group(*blocks))
    console.rule(style="dim")
    console.print()
    console.print(totals_line(result))
    console.print()
    console.print(severity_bars(result))
    console.print()


def render_json(result: ScanResult) -> None:
    """Machine output. Plain, unstyled, and the only thing on stdout."""
    console.print(result.model_dump_json(indent=2), soft_wrap=True, markup=False)


# --- guide ------------------------------------------------------------------------
# Most of this tool is not built yet. A guide that quietly lists unimplemented flags
# alongside working ones would be worse than no guide, so every entry carries status.

READY = "ready"

COMMANDS: list[tuple[str, str, str]] = [
    ("scan [PATH]", READY, "Resolve the lockfile, match advisories, print findings."),
    ("explain <ID>", "phase 4", "Everything known about one advisory: path, fix, evidence."),
    ("guide", READY, "This page."),
]

SCAN_OPTIONS: list[tuple[str, str, str]] = [
    ("--format table", READY, "Grouped, colourised output for reading."),
    ("--format json", READY, "Machine-readable. Warnings stay on stderr so pipes stay clean."),
    ("--format sarif", "phase 7", "GitHub's Security tab ingests this."),
    ("--min-severity", READY, "Threshold, not a single level: high means high and critical."),
    ("--offline", READY, "No network. Serves cached advisories only."),
    ("--python", READY, "Point at the scanned project's virtualenv explicitly."),
    ("--only-reachable", "phase 4", "Hide findings your code provably cannot reach."),
    ("--fail-on", "partial", "any works now; reachable needs the call graph."),
]

CONCEPTS: list[tuple[str, str]] = [
    (
        "Severity",
        "critical, high, medium, low, or unknown. Unknown means no severity was ever "
        "published, and those findings are never hidden by --min-severity: a data gap "
        "is not evidence of low risk.",
    ),
    (
        "Direct vs transitive",
        "Depth from your project. Direct dependencies can be fixed with a version bump; "
        "transitive ones may need an override or a lockfile refresh.",
    ),
    (
        "Fix shape",
        "How a finding can actually be fixed: DIRECT_BUMP, OVERRIDE, LOCKFILE_REFRESH, "
        "BACKPORT_EXISTS, or NO_FIX. Landing in phase 2.",
    ),
    (
        "Reachability",
        "Whether a call path exists from your code to the vulnerable symbol. Three "
        "verdicts: REACHABLE, NOT_REACHABLE, and UNKNOWN. Landing in phase 4.",
    ),
    (
        "UNKNOWN is not safe",
        "When dynamic dispatch sits on any partial path, the verdict is UNKNOWN, never "
        "NOT_REACHABLE. A false 'you are safe' is the one error that makes a security "
        "tool worse than useless.",
    ),
]


def _status_style(status: str) -> str:
    return {READY: "green", "partial": "yellow"}.get(status, "dim")


def _entry_table(rows: list[tuple[str, str, str]]) -> Table:
    table = Table(box=None, show_header=False, expand=True, pad_edge=False, padding=(0, 1))
    table.add_column(width=18, no_wrap=True)
    table.add_column(width=9, no_wrap=True)
    table.add_column(ratio=1, overflow="fold")

    for name, status, description in rows:
        table.add_row(
            Text(f" {name}", style="bold cyan"),
            Text(status, style=_status_style(status)),
            Text(description, style="dim" if status != READY else ""),
        )
    return table


def _section(title: str) -> Text:
    return Text(f"\n  {title}", style="bold white")


def render_guide() -> None:
    console.print()
    console.print(
        Panel(
            Text.assemble(
                Text("vulnpath", style="bold cyan"),
                Text("  reachability-aware dependency triage for Python\n", style="white"),
                Text(
                    "Every scanner tells you which packages have CVEs. This one is being "
                    "built to tell you which ones your code actually reaches, and what "
                    "shape of fix each needs.",
                    style="dim",
                ),
            ),
            box=box.ROUNDED,
            border_style="cyan",
            padding=(0, 2),
        )
    )

    console.print(_section("COMMANDS"))
    console.print(_entry_table(COMMANDS))

    console.print(_section("SCAN OPTIONS"))
    console.print(_entry_table(SCAN_OPTIONS))

    console.print(_section("CONCEPTS"))
    concepts = Table(box=None, show_header=False, expand=True, pad_edge=False, padding=(0, 1))
    concepts.add_column(width=24, overflow="fold")
    concepts.add_column(ratio=1, overflow="fold")
    for term, meaning in CONCEPTS:
        concepts.add_row(Text(f" {term}", style="bold"), Text(meaning, style="dim"))
    console.print(concepts)

    console.print(_section("EXAMPLES"))
    examples = Table(box=None, show_header=False, expand=True, pad_edge=False, padding=(0, 1))
    examples.add_column(width=42, overflow="fold")
    examples.add_column(ratio=1, overflow="fold")
    for example, why in [
        ("vulnpath scan .", "everything in this project"),
        ("vulnpath scan . --min-severity high", "only what is worth today"),
        ("vulnpath scan . --format json | jq", "feed a script"),
        ("vulnpath scan . --fail-on any", "gate a CI build"),
        ("vulnpath scan . --offline", "no network, no key"),
        ("vulnpath scan ../other-project", "any path, not just here"),
    ]:
        examples.add_row(Text(f" $ {example}", style="green"), Text(why, style="dim"))
    console.print(examples)
    console.print()


@contextmanager
def working(message: str) -> Generator[None]:
    """Spinner while the network is being waited on.

    Written to stderr, so it never lands in piped ``--format json`` output. Rich
    suppresses it automatically when the stream is not a terminal.
    """
    with err_console.status(Text(message, style="cyan"), spinner="dots"):
        yield


def warn(message: str) -> None:
    """Diagnostics go to stderr so ``--format json`` stays parseable."""
    err_console.print(Text(f"warning: {message}", style="yellow"))


def error(message: str) -> None:
    err_console.print(Text(f"error: {message}", style="bold red"))
