"""The single shared console.

Every byte the tool writes to a terminal goes through one of these two objects.
Nothing outside the render layer calls ``print``; see CLAUDE.md.
"""

from rich.console import Console

console = Console(highlight=False)
"""Normal output. Machine-readable formats are written here too."""

err_console = Console(stderr=True, highlight=False)
"""Diagnostics, warnings, and errors. Kept off stdout so ``--format json`` stays parseable."""

# ``highlight=False`` is not cosmetic. Rich's automatic highlighter injects colour
# escapes *inside* tokens it recognises — a version string, a CVE id, a package
# version in a table cell. That corrupts any value a caller might parse, and would
# mangle ``--format json`` output outright. Styling here is explicit or absent.
