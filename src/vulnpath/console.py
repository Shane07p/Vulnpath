"""The single shared console.

Every byte the tool writes to a terminal goes through one of these two objects.
Nothing outside the render layer calls ``print``; see CLAUDE.md.
"""

import contextlib
import sys

from rich.console import Console


def _force_utf8() -> None:
    """Make stdout and stderr accept any character an advisory might contain.

    Advisory summaries are arbitrary prose from upstream databases — arrows, dashes,
    non-Latin scripts. A Windows console defaults to cp1252, so printing one raises
    ``UnicodeEncodeError`` and takes the whole scan down. Replacing unencodable
    characters degrades a glyph; not doing so loses the entire report.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):
                reconfigure(encoding="utf-8", errors="replace")


_force_utf8()

console = Console(highlight=False)
"""Normal output. Machine-readable formats are written here too."""

err_console = Console(stderr=True, highlight=False)
"""Diagnostics, warnings, and errors. Kept off stdout so ``--format json`` stays parseable."""

# ``highlight=False`` is not cosmetic. Rich's automatic highlighter injects colour
# escapes *inside* tokens it recognises — a version string, a CVE id, a package
# version in a table cell. That corrupts any value a caller might parse, and would
# mangle ``--format json`` output outright. Styling here is explicit or absent.
