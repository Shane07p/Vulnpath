"""Domain model behaviour."""

from vulnpath.models import (
    Advisory,
    BlockingParent,
    Finding,
    Fix,
    FixShape,
    Package,
    Severity,
    normalise,
)


def test_normalise_lowercases() -> None:
    assert normalise("PyYAML") == "pyyaml"


def test_normalise_collapses_separator_runs_to_a_hyphen() -> None:
    """PEP 503 folds -, _ and . together, but does not remove them.

    So `py_yaml` and `Py.YAML` are the same package, and neither is `pyyaml`.
    """
    assert normalise("py_yaml") == normalise("Py.YAML") == normalise("py-yaml") == "py-yaml"
    assert normalise("py_yaml") != normalise("pyyaml")


def test_findings_without_a_fix_are_valid() -> None:
    """Classification runs after advisory matching, so a Finding exists before its Fix."""
    finding = Finding(
        package=Package(name="pyyaml", version="5.3.1", depth=1),
        advisory=Advisory(id="CVE-1", severity=Severity.CRITICAL),
    )
    assert finding.fix is None


def test_an_actionable_fix_has_a_command() -> None:
    fix = Fix(
        shape=FixShape.DIRECT_BUMP,
        target_version="5.4",
        command='uv add "pyyaml>=5.4"',
        reason="Your pin ==5.3.1 forbids 5.4.",
    )
    assert fix.is_actionable


def test_no_fix_is_not_actionable() -> None:
    assert not Fix(shape=FixShape.NO_FIX, reason="No fixed version exists.").is_actionable


def test_unknown_is_not_actionable() -> None:
    """A shape we could not determine must never read as a usable answer."""
    assert not Fix(shape=FixShape.UNKNOWN, reason="PyPI unreachable.").is_actionable


def test_blocking_parents_record_the_constraint_and_the_way_out() -> None:
    fix = Fix(
        shape=FixShape.OVERRIDE,
        target_version="2.0.6",
        reason="requests 2.25.1 requires urllib3<1.27.",
        blocking_parents=(
            BlockingParent(name="requests", constraint="<1.27,>=1.21.1", upgrade_to="2.32.5"),
        ),
    )
    assert fix.blocking_parents[0].name == "requests"
    assert fix.blocking_parents[0].upgrade_to == "2.32.5"
