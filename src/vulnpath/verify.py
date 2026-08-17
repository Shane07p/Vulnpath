"""Does an extracted symbol exist in the code that is actually installed?

The check that makes the extraction stage safe to have at all. A model reading advisory
prose can return a name that is well-formed, plausible, and absent from the library. A
verdict narrowed to a symbol that does not exist would report no path to code that is
really there — a false negative, the one failure this tool refuses to produce.

So a symbol earns its place by being found. Everything here is ``ast`` over installed
source: no network, no heuristics about what a name looks like, no benefit of the doubt.

Being found is not always literal. Most vulnerable symbols are named the way a user would
import them — ``yaml.load``, not ``yaml.loader.load`` — and a facade binds that name by
re-export rather than defining it. Following one is reading real import statements in real
files, so it is evidence, not a guess; it is bounded so a cycle of mutual imports cannot
run forever.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

from vulnpath.imports import build_import_table
from vulnpath.installed import find_module_file
from vulnpath.symbols import ModuleSymbols, parse_module

MAX_REEXPORT_DEPTH = 3
"""How many re-export hops a symbol may travel before the search gives up.

Three covers the deepest real facade chain seen in practice — package ``__init__``, a
private implementation module, and the module that one imports from. A symbol needing
more than that is not being dropped as fake so much as left unproven, and unproven means
falling back to the package-level verdict, which is the safe direction.
"""


@dataclass(frozen=True)
class Verification:
    """Which extracted symbols survived, and which did not."""

    verified: tuple[str, ...]
    dropped: tuple[str, ...]

    @property
    def is_usable(self) -> bool:
        """Whether anything survived to narrow a verdict with.

        Nothing surviving is not evidence the advisory is irrelevant. It means this stage
        could not confirm a symbol, so the caller keeps the package-level answer.
        """
        return bool(self.verified)


def module_splits(symbol: str) -> list[tuple[str, str]]:
    """(module, remaining attribute path) pairs for a dotted symbol, longest module first.

    ``yaml.loader.Loader.construct`` could be a module of that exact name, an attribute of
    module ``yaml.loader``, or a nested attribute of ``yaml``. The string alone cannot say
    where the module path stops and the attribute path begins, so each split is tried until
    one resolves to a file on disk.
    """
    parts = symbol.split(".")
    return [
        (".".join(parts[:count]), ".".join(parts[count:])) for count in range(len(parts) - 1, 0, -1)
    ]


class _Verifier:
    """One verification pass, holding the parsed modules it has already read.

    The cache is the reason this is a class. A single advisory names several symbols in
    the same module, and each candidate split re-tests the same handful of files, so
    without it one advisory re-parses the same source many times over.
    """

    def __init__(self, site_packages: Path) -> None:
        self.site_packages = site_packages
        self._parsed: dict[str, tuple[ModuleSymbols, bool] | None] = {}

    def _module(self, module_fqn: str) -> tuple[ModuleSymbols, bool] | None:
        """A parsed module and whether it is a package, or ``None`` if neither is available."""
        if module_fqn in self._parsed:
            return self._parsed[module_fqn]

        result: tuple[ModuleSymbols, bool] | None = None
        path = find_module_file(self.site_packages, module_fqn)
        if path is not None:
            parsed = parse_module(path, module_fqn)
            if parsed is not None:
                result = (parsed, path.name == "__init__.py")

        self._parsed[module_fqn] = result
        return result

    def _star_sources(self, parsed: ModuleSymbols, is_package: bool) -> list[str]:
        """Modules this one re-exports wholesale via ``from x import *``.

        The import table cannot name what a star binds, and star re-export is how most
        real facades are assembled, so the only way to know whether a name is bound here
        is to look at the module it is pulled from.
        """
        sources: list[str] = []
        for record in parsed.imports:
            if record.name != "*":
                continue
            resolved = build_import_table(
                [replace(record, name="__star__")], parsed.fqn, is_package=is_package
            )
            target = resolved.get("__star__")
            if target:
                sources.append(target.removesuffix(".__star__"))
        return sources

    def _reexports(
        self, parsed: ModuleSymbols, is_package: bool, attribute: str, depth: int, seen: set[str]
    ) -> bool:
        """Whether this module binds ``attribute`` from elsewhere, and it exists there."""
        head, _, rest = attribute.partition(".")

        table = build_import_table(parsed.imports, parsed.fqn, is_package=is_package)
        target = table.get(head)
        if target is not None and self._exists(
            f"{target}.{rest}" if rest else target, depth + 1, seen
        ):
            return True

        return any(
            self._exists(f"{source}.{attribute}", depth + 1, seen)
            for source in self._star_sources(parsed, is_package)
        )

    def _exists(self, symbol: str, depth: int, seen: set[str]) -> bool:
        """Whether this exact dotted name resolves to a definition in installed source.

        ``seen`` guards against mutually importing modules, which are ordinary in real
        packages and would otherwise recurse until the depth limit on every lookup.
        """
        if depth > MAX_REEXPORT_DEPTH or symbol in seen:
            return False
        seen.add(symbol)

        for module_fqn, attribute in module_splits(symbol):
            found = self._module(module_fqn)
            if found is None:
                continue
            parsed, is_package = found

            # Definition FQNs are already module-qualified, so a hit is an exact match on
            # the symbol as written.
            if any(definition.fqn == symbol for definition in parsed.definitions):
                return True

            if self._reexports(parsed, is_package, attribute, depth, seen):
                return True

        return False

    def check(self, symbols: tuple[str, ...]) -> Verification:
        verified: list[str] = []
        dropped: list[str] = []
        for symbol in symbols:
            if self._exists(symbol, depth=0, seen=set()):
                verified.append(symbol)
            else:
                dropped.append(symbol)
        return Verification(verified=tuple(verified), dropped=tuple(dropped))


def verify_symbols(symbols: tuple[str, ...], site_packages: Path) -> Verification:
    """Keep the symbols that exist in installed source; drop the rest.

    Dropping is silent to the user but not to the caller: ``Verification.dropped`` is what
    proves the check is doing anything, and is the number the evaluation reports as
    hallucinations caught.
    """
    return _Verifier(site_packages).check(symbols)
