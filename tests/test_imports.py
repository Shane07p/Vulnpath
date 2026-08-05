"""Turning import statements into a local-name-to-FQN table."""

from vulnpath.imports import build_import_table
from vulnpath.symbols import RawImport


def test_plain_import() -> None:
    table = build_import_table([RawImport(module=None, name="yaml")], "app.utils")
    assert table["yaml"] == "yaml"


def test_dotted_import_binds_only_the_first_segment() -> None:
    """`import os.path` binds the name `os`, not `os.path`."""
    table = build_import_table([RawImport(module=None, name="os.path")], "app.utils")
    assert table["os"] == "os"


def test_aliased_import() -> None:
    table = build_import_table([RawImport(module=None, name="numpy", alias="np")], "app.utils")
    assert table["np"] == "numpy"


def test_from_import() -> None:
    table = build_import_table([RawImport(module="json", name="loads")], "app.utils")
    assert table["loads"] == "json.loads"


def test_aliased_from_import_resolves_to_the_true_qualname() -> None:
    """The case the spec calls out: `from x.y import z as w` must resolve w -> x.y.z."""
    table = build_import_table(
        [RawImport(module="utils.loader", name="read", alias="read_settings")], "app.main"
    )
    assert table["read_settings"] == "utils.loader.read"


def test_relative_import_one_level() -> None:
    """`from . import core` inside app.main resolves to app.core."""
    table = build_import_table([RawImport(module=None, name="core", level=1)], "app.main")
    assert table["core"] == "app.core"


def test_relative_import_with_a_module() -> None:
    """`from .core import Processor` inside app.main resolves to app.core.Processor."""
    table = build_import_table([RawImport(module="core", name="Processor", level=1)], "app.main")
    assert table["Processor"] == "app.core.Processor"


def test_relative_import_two_levels() -> None:
    """`from ..shared import thing` inside app.sub.main resolves to app.shared.thing."""
    table = build_import_table([RawImport(module="shared", name="thing", level=2)], "app.sub.main")
    assert table["thing"] == "app.shared.thing"


def test_a_relative_import_past_the_root_is_dropped() -> None:
    """Rather than producing a nonsense FQN that would match nothing."""
    table = build_import_table([RawImport(module="x", name="y", level=5)], "app.main")
    assert "y" not in table


def test_relative_import_inside_a_package_init() -> None:
    """`from . import y` inside app/sub/__init__.py resolves to app.sub.y.

    `module_fqn` for a package's `__init__.py` is the package itself, so unlike a
    regular module, level=1 must not strip a trailing component that isn't there.
    """
    table = build_import_table(
        [RawImport(module=None, name="y", level=1)], "app.sub", is_package=True
    )
    assert table["y"] == "app.sub.y"


def test_relative_import_with_a_module_inside_a_package_init() -> None:
    """`from .mod import thing` inside app/sub/__init__.py resolves to app.sub.mod.thing."""
    table = build_import_table(
        [RawImport(module="mod", name="thing", level=1)], "app.sub", is_package=True
    )
    assert table["thing"] == "app.sub.mod.thing"


def test_relative_import_boundary_for_a_module() -> None:
    """`app.sub` as a regular module has one package component (`app`): level=1 is the
    deepest level that resolves, level=2 is the first that must be dropped."""
    deepest = build_import_table([RawImport(module=None, name="y", level=1)], "app.sub")
    assert deepest["y"] == "app.y"

    dropped = build_import_table([RawImport(module=None, name="y", level=2)], "app.sub")
    assert "y" not in dropped


def test_relative_import_boundary_for_a_package() -> None:
    """`app.sub` as a package (its own `__package__`) has two components: level=2 is
    the deepest level that resolves, level=3 is the first that must be dropped — one
    level deeper than the identical `module_fqn` allows as a regular module."""
    deepest = build_import_table(
        [RawImport(module=None, name="y", level=2)], "app.sub", is_package=True
    )
    assert deepest["y"] == "app.y"

    dropped = build_import_table(
        [RawImport(module=None, name="y", level=3)], "app.sub", is_package=True
    )
    assert "y" not in dropped


def test_star_imports_are_ignored() -> None:
    """`from x import *` binds unknown names; nothing useful can be recorded."""
    table = build_import_table([RawImport(module="json", name="*")], "app.utils")
    assert table == {}


def test_later_imports_win() -> None:
    """Matching Python: the last binding of a name is the live one."""
    table = build_import_table(
        [
            RawImport(module="first", name="thing"),
            RawImport(module="second", name="thing"),
        ],
        "app.utils",
    )
    assert table["thing"] == "second.thing"
