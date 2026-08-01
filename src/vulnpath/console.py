"""The single shared console.

Every byte the tool writes to a terminal goes through one of these two objects.
Nothing outside the render layer calls ``print``; see CLAUDE.md.
"""

from rich.console import Console

console = Console()
"""Normal output. Machine-readable formats are written here too."""

err_console = Console(stderr=True)
"""Diagnostics, warnings, and errors. Kept off stdout so ``--format json`` stays parseable."""
