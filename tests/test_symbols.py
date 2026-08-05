"""Per-file AST extraction. No resolution happens here — only what the file says."""

from pathlib import Path

from vulnpath.symbols import ModuleSymbols, parse_module

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE_APP = FIXTURES / "sample_app"


def _symbols(name: str) -> ModuleSymbols:
    parsed = parse_module(SAMPLE_APP / f"{name}.py", f"sample_app.{name}")
    assert parsed is not None
    return parsed


def _definitions(symbols: ModuleSymbols) -> dict[str, str]:
    return {d.fqn: d.kind for d in symbols.definitions}


def test_module_itself_is_a_definition() -> None:
    """Module-level code runs on import, so the module is a node in its own right."""
    assert _definitions(_symbols("core"))["sample_app.core"] == "module"


def test_classes_and_methods_are_qualified() -> None:
    definitions = _definitions(_symbols("core"))
    assert definitions["sample_app.core.Processor"] == "class"
    assert definitions["sample_app.core.Processor.process"] == "method"
    assert definitions["sample_app.core.Base.describe"] == "method"


def test_module_level_functions_are_functions_not_methods() -> None:
    assert _definitions(_symbols("utils"))["sample_app.utils.read_settings"] == "function"


def test_base_classes_are_recorded() -> None:
    assert _symbols("core").bases["sample_app.core.Processor"] == ("Base",)


def test_calls_are_attributed_to_their_enclosing_definition() -> None:
    calls = {(c.caller, c.name) for c in _symbols("main").calls}
    assert ("sample_app.main.run", "Processor") in calls
    assert ("sample_app.main.run", "read_settings") in calls
    assert ("sample_app.main.run", "processor.process") in calls


def test_dotted_calls_keep_their_full_written_name() -> None:
    calls = {(c.caller, c.name) for c in _symbols("utils").calls}
    assert ("sample_app.utils.read_settings", "yaml.load") in calls


def test_plain_imports_are_recorded() -> None:
    imports = _symbols("utils").imports
    assert any(i.module is None and i.name == "yaml" and i.level == 0 for i in imports)


def test_aliased_from_imports_keep_both_names() -> None:
    imports = _symbols("utils").imports
    assert any(
        i.module == "json" and i.name == "loads" and i.alias == "parse_json" for i in imports
    )


def test_dynamic_dispatch_marks_the_enclosing_function() -> None:
    """The flag that lets a later phase say UNKNOWN instead of NOT_REACHABLE."""
    assert "sample_app.dynamic.dispatch" in _symbols("dynamic").dynamic


def test_ordinary_functions_are_not_marked_dynamic() -> None:
    assert _symbols("core").dynamic == frozenset()


def test_decorator_call_is_attributed_to_the_enclosing_scope() -> None:
    """A decorator runs when the ``def`` statement runs, in the module, not in
    ``handler`` — ``handler`` hasn't finished being defined yet when it evaluates."""
    calls = {(c.caller, c.name) for c in _symbols("decorated").calls}
    assert ("sample_app.decorated", "cache") in calls
    assert ("sample_app.decorated", "get_ttl") in calls


def test_default_argument_call_is_attributed_to_the_enclosing_scope() -> None:
    calls = {(c.caller, c.name) for c in _symbols("decorated").calls}
    assert ("sample_app.decorated", "compute_default") in calls


def test_class_base_call_is_attributed_to_the_enclosing_scope() -> None:
    calls = {(c.caller, c.name) for c in _symbols("decorated").calls}
    assert ("sample_app.decorated", "make_base") in calls


def test_a_dynamically_computed_base_marks_the_class_dynamic() -> None:
    """``bases`` is empty either way for ``class Dynamic(make_base())`` and
    ``class Dynamic:`` — ``dynamic`` is what tells them apart."""
    symbols = _symbols("decorated")
    assert symbols.bases["sample_app.decorated.Dynamic"] == ()
    assert "sample_app.decorated.Dynamic" in symbols.dynamic


def test_an_unparseable_file_returns_none(tmp_path: Path) -> None:
    """Reported by the caller, never silently skipped."""
    broken = tmp_path / "broken.py"
    broken.write_text("def oops(:\n", encoding="utf-8")
    assert parse_module(broken, "broken") is None


def test_a_file_with_invalid_encoding_returns_none(tmp_path: Path) -> None:
    broken = tmp_path / "binary.py"
    broken.write_bytes(b"\xff\xfe\x00\x01 not text")
    assert parse_module(broken, "binary") is None
