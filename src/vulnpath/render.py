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
from vulnpath.models import (
    Advisory,
    Finding,
    Fix,
    FixShape,
    Package,
    ScanResult,
    Severity,
    severity_rank,
)

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

FIX_STYLE: dict[FixShape, str] = {
    FixShape.DIRECT_BUMP: "green",
    FixShape.LOCKFILE_REFRESH: "green",
    FixShape.BACKPORT_EXISTS: "cyan",
    FixShape.OVERRIDE: "yellow",
    FixShape.NO_FIX: "bold magenta",
    FixShape.UNKNOWN: "dim",
}

VERDICT_STYLE: dict[str, str] = {
    "reachable": "bold red",
    "unknown": "bold yellow",
    "not_reachable": "dim",
}

VERDICT_LABEL: dict[str, str] = {
    "reachable": "REACHABLE",
    "unknown": "UNKNOWN",
    "not_reachable": "NOT REACHABLE",
}

BAR_GLYPH = "█"


def _severity_badge(severity: Severity) -> Text:
    return Text(f" {SEVERITY_LABEL[severity]} ", style=SEVERITY_STYLE[severity])


def _summary_of(advisory: Advisory) -> str:
    summary = advisory.summary or advisory.details.split("\n", 1)[0] or "(no summary)"
    return summary.strip()


# --- grouping ---------------------------------------------------------------------


def group_by_package(result: ScanResult) -> list[tuple[Package, list[Finding]]]:
    """One entry per affected package, worst-affected first.

    Findings arrive one row per advisory, and a single package can carry a dozen.
    Repeating its name and version on every row buries the thing being decided about,
    which is the package, not the advisory.
    """
    grouped: dict[str, tuple[Package, list[Finding]]] = {}
    for finding in result.findings:
        entry = grouped.setdefault(finding.package.name, (finding.package, []))
        entry[1].append(finding)

    for _, findings in grouped.values():
        findings.sort(key=lambda f: f.sort_key)

    def rank(item: tuple[Package, list[Finding]]) -> tuple[int, int, int, int, str]:
        """A package ranks by its most urgent finding, since that is why it is listed."""
        _, findings = item
        return min(finding.sort_key for finding in findings)

    return sorted(grouped.values(), key=rank)


def split_by_relevance(
    groups: list[tuple[Package, list[Finding]]],
) -> tuple[list[tuple[Package, list[Finding]]], list[tuple[Package, list[Finding]]]]:
    """Packages worth reading, and packages worth only counting.

    A package where every finding is a proven negative has nothing a reader can act on,
    and printing all of them in full is the alert fatigue this tool exists to remove. It
    is still listed and counted — silent suppression is how a scanner loses trust, and
    the totals have to reconcile against another scanner's.
    """
    relevant: list[tuple[Package, list[Finding]]] = []
    ignorable: list[tuple[Package, list[Finding]]] = []
    for group in groups:
        target = ignorable if all(f.is_suppressible for f in group[1]) else relevant
        target.append(group)
    return relevant, ignorable


# --- pieces -----------------------------------------------------------------------


MAX_PATH_WIDTH = 60
"""Longest project path shown before the head is dropped."""


def shorten_path(path: str, limit: int = MAX_PATH_WIDTH) -> str:
    """Keep the tail of a long path, not the head.

    The last components name the project; the leading ones are whatever temp or home
    directory it happens to sit under. Wrapping the whole thing across two panel lines
    spends the header on the least identifying part of it.
    """
    if len(path) <= limit:
        return path
    return f"...{path[-(limit - 3) :]}"


def header(result: ScanResult) -> Panel:
    title = Text("vulnpath", style="bold cyan")
    title.append("  ")
    title.append(shorten_path(result.project_path), style="white")

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


def package_heading(package: Package, findings: list[Finding]) -> Text:
    """Name, version, depth, verdict, count — the whole package in one line.

    The verdict belongs here rather than on each advisory. Reachability is answered per
    package, so repeating it under every finding printed the same sentence twenty-six
    times for one GitPython block while telling the reader nothing new.
    """
    verdict = findings[0].verdict
    heading = Text("  ")
    heading.append(package.name, style="bold white")
    heading.append(f" {package.version}", style="white")
    heading.append("  ·  ", style="dim")
    heading.append(
        "direct" if package.is_direct else f"transitive · depth {package.depth}",
        style="cyan" if package.is_direct else "dim",
    )
    heading.append("  ·  ", style="dim")
    heading.append(
        VERDICT_LABEL.get(verdict, verdict.upper()), style=VERDICT_STYLE.get(verdict, "dim")
    )
    heading.append(f"  ·  {len(findings)} advisor{'y' if len(findings) == 1 else 'ies'}", "dim")
    return heading


def ignored_line(package: Package, findings: list[Finding]) -> Text:
    """One line for a package with nothing actionable in it."""
    line = Text("  ")
    line.append(f"{package.name} {package.version}", style="dim")
    count = len(findings)
    line.append(f"   {count} advisor{'y' if count == 1 else 'ies'}", style="dim")
    line.append(f"   {findings[0].reachability_reason}", style="dim")
    return line


def verdict_lines(finding: Finding) -> list[Text]:
    """Why the verdict was reached, and the call path that proves it.

    The verdict word itself is on the package heading. What stays here is the part that
    differs between findings: the reasoning, and the path when there is one.
    """
    lines = [Text(f"{finding.confidence} confidence — {finding.reachability_reason}", "dim")]

    # Named explicitly rather than left implicit in the reason. A reader deciding whether
    # to trust a narrowed verdict needs to see which symbol it was narrowed to, since
    # that is the one thing in the chain a model had a hand in choosing.
    if finding.vulnerable_symbols:
        symbols = Text("   vulnerable: ", style="dim")
        symbols.append(", ".join(finding.vulnerable_symbols), style="yellow")
        lines.append(symbols)

    for depth, hop in enumerate(finding.path):
        lines.append(Text("  " * depth + ("-> " if depth else "   ") + hop, style="cyan"))
    return lines


def fix_lines(fix: Fix) -> list[Text]:
    """The shape, why, and the command — one line each.

    Shapes with no command print their reason too. NO_FIX and UNKNOWN must not read as
    "nothing to do here": one means no fix has been released, the other means the
    lookup did not complete, and those call for opposite responses.
    """
    style = FIX_STYLE[fix.shape]
    headline = Text(f"{fix.shape.value.upper()}  ", style=f"bold {style}")
    headline.append(fix.reason, style="dim")
    lines = [headline]

    for parent in fix.blocking_parents:
        detail = Text("  blocked by ", style="dim")
        detail.append(f"{parent.name} {parent.constraint}", style="yellow")
        if parent.upgrade_to:
            detail.append(f" — {parent.name} {parent.upgrade_to} lifts it", style="dim")
        lines.append(detail)

    if fix.command:
        lines.extend(Text(f"  $ {line}", style="bold green") for line in fix.command.splitlines())
    return lines


def advisory_row(finding: Finding) -> Table:
    """One advisory as a single aligned row.

    Widths are pinned so the prose column cannot starve the rest, and so rows line up
    across findings even though each is rendered separately.
    """
    table = Table(box=None, show_header=False, expand=True, pad_edge=False, padding=(0, 1))
    table.add_column(width=8, no_wrap=True)
    table.add_column(width=20, no_wrap=True)
    table.add_column(width=12, overflow="fold")
    table.add_column(ratio=1, overflow="fold", min_width=20)

    advisory = finding.advisory

    # The version this finding should move to, not an arbitrary entry from the
    # advisory's list. OSV serialises fixed versions in no useful order, so showing
    # the first one points at 2.0.6 while the recommended fix is 1.26.17.
    if finding.fix is not None and finding.fix.target_version:
        fix_cell = Text(finding.fix.target_version, style="green")
    elif advisory.fixed_versions:
        fix_cell = Text(advisory.fixed_versions[0], style="green")
        if len(advisory.fixed_versions) > 1:
            fix_cell.append(f" +{len(advisory.fixed_versions) - 1}", style="dim")
    else:
        fix_cell = Text("no fix", style="bold magenta")

    table.add_row(
        _severity_badge(advisory.severity),
        Text(advisory.display_id, style="bold"),
        fix_cell,
        Text(_summary_of(advisory), style="dim"),
    )
    return table


def finding_block(finding: Finding) -> RenderableType:
    """An advisory row, with its fix beneath it at full width.

    The fix deliberately sits outside the table. A shell command folded into a
    twelve-character column is a command nobody can copy, and copying it is the entire
    point of printing it.
    """
    parts: list[RenderableType] = [advisory_row(finding)]
    parts.extend(Padding(line, (0, 0, 0, 9)) for line in verdict_lines(finding))
    if finding.fix is not None:
        parts.extend(Padding(line, (0, 0, 0, 9)) for line in fix_lines(finding.fix))
        parts.append(Text())
    return Group(*parts)


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
    """The line someone screenshots.

    "12 findings" is what every scanner prints. "2 reachable" is the reason to install
    this one, so it leads.
    """
    counts = {verdict: 0 for verdict in ("reachable", "unknown", "not_reachable")}
    for finding in result.findings:
        counts[finding.verdict] = counts.get(finding.verdict, 0) + 1

    line = Text("  ")
    line.append(f"{len(result.findings)} findings", style="bold")
    line.append("  ·  ", style="dim")
    line.append(f"{counts['reachable']} reachable", style=VERDICT_STYLE["reachable"])
    line.append("  ·  ", style="dim")
    line.append(f"{counts['unknown']} unknown", style=VERDICT_STYLE["unknown"])
    line.append("  ·  ", style="dim")
    line.append(f"{counts['not_reachable']} not reachable", style="dim")
    return line


# --- entry points -----------------------------------------------------------------


def render_table(result: ScanResult, *, show_all: bool = False) -> None:
    console.print()
    console.print(header(result))

    if not result.findings:
        console.print()
        console.print(Text("  No known advisories for the resolved packages.", style="bold green"))
        console.print()
        return

    groups = group_by_package(result)
    relevant, ignorable = (groups, []) if show_all else split_by_relevance(groups)

    blocks: list[RenderableType] = [Text()]
    for package, findings in relevant:
        blocks.append(package_heading(package, findings))
        # One column of left padding so the severity badges line up under the package
        # name rather than hanging off its left edge.
        blocks.extend(Padding(finding_block(f), (0, 0, 0, 1)) for f in findings)
        blocks.append(Text())

    if ignorable:
        blocks.append(Text("  ── nothing reaches these ──", style="dim"))
        blocks.extend(ignored_line(package, findings) for package, findings in ignorable)
        blocks.append(Text())
        blocks.append(Text("  Pass --show-all to expand them.", style="dim italic"))
        blocks.append(Text())

    console.print(Group(*blocks))
    console.rule(style="dim")
    console.print()
    console.print(totals_line(result))
    console.print()
    console.print(severity_bars(result))
    console.print()


ANALYSIS_INPUTS = {"details", "references", "fix_commits"}
"""Advisory fields this tool reads but does not report.

``details`` is the advisory prose the model is asked to read, ``references`` the link
list OSV publishes, and ``fix_commits`` the patch URLs the diff fetcher follows. All
three are inputs to the analysis rather than conclusions from it, and together they were
63% of the output — a scan of 25 findings weighed 70KB, two thirds of it text a consumer
can fetch from OSV with the advisory id it already has.
"""


def render_json(result: ScanResult) -> None:
    """Machine output. Plain, unstyled, and the only thing on stdout.

    Every finding survives regardless of what the table collapses: suppressing a finding
    is a display decision, and a machine consumer needs the full set.
    """
    console.print(
        result.model_dump_json(
            indent=2, exclude={"findings": {"__all__": {"advisory": ANALYSIS_INPUTS}}}
        ),
        soft_wrap=True,
        markup=False,
    )


# --- guide ------------------------------------------------------------------------
# A guide that lists an unimplemented flag beside a working one is worse than no
# guide: someone will use it and assume it did something. Every entry carries status.

READY = "ready"
PLANNED = "planned"
PARTIAL = "partial"

COMMANDS: list[tuple[str, str, str]] = [
    ("scan [PATH]", READY, "Resolve the lockfile, match advisories, print findings."),
    ("explain <ID>", PLANNED, "Everything known about one advisory: path, fix, evidence."),
    ("guide", READY, "This page."),
]

SCAN_OPTIONS: list[tuple[str, str, str]] = [
    ("--format table", READY, "Grouped, colourised output for reading."),
    ("--format json", READY, "Machine-readable. Warnings stay on stderr so pipes stay clean."),
    ("--format sarif", PLANNED, "GitHub's Security tab ingests this."),
    ("--min-severity", READY, "Threshold, not a single level: high means high and critical."),
    ("--offline", READY, "No network. Serves cached advisories only."),
    ("--python", READY, "Point at the scanned project's virtualenv explicitly."),
    ("--only-reachable", READY, "Hide findings your code provably cannot reach."),
    ("--show-all", READY, "Expand packages nothing reaches, instead of one line each."),
    ("--fail-on", READY, "Gate CI on any finding, or only on ones your code reaches."),
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
        "The change that would actually close a finding. LOCKFILE_REFRESH just relocks, "
        "DIRECT_BUMP edits your manifest, OVERRIDE gets past a blocking parent, "
        "BACKPORT_EXISTS points at a patched release on your own major line, NO_FIX "
        "means none has been released, and UNKNOWN means the lookup did not complete.",
    ),
    (
        "Fix target",
        "The lowest fix on your own major line, not the newest release. On urllib3 "
        "1.26.5 that is 1.26.17 rather than 2.0.6: it closes the advisory without a "
        "major upgrade and rarely collides with a parent's constraint.",
    ),
    (
        "Reachability",
        "Whether a call path exists from your code into the package. REACHABLE prints "
        "the path as evidence. NOT_REACHABLE is claimed only when nothing analysed "
        "imports the package. UNKNOWN means a path could not be ruled out.",
    ),
    (
        "UNKNOWN is not safe",
        "When dynamic dispatch sits on any partial path, the verdict is UNKNOWN, never "
        "NOT_REACHABLE. A false 'you are safe' is the one error that makes a security "
        "tool worse than useless.",
    ),
]


def _status_style(status: str) -> str:
    return {READY: "green", PARTIAL: "yellow"}.get(status, "dim")


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
