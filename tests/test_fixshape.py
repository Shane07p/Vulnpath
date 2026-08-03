"""Fix-shape classification.

Pure: every test builds a FixContext directly. No network, no fixtures, no mocks.
"""

from vulnpath.fixshape import FixContext, classify
from vulnpath.models import Advisory, AffectedRange, FixShape, Package, Severity


def _context(
    *,
    version: str = "1.26.5",
    depth: int = 1,
    fixed: tuple[str, ...] = ("1.26.17",),
    declared: str | None = None,
    parents: dict[str, str] | None = None,
    released: tuple[str, ...] | None = ("1.26.5", "1.26.17", "2.0.6"),
    parent_upgrades: dict[str, str] | None = None,
    ranges: tuple[AffectedRange, ...] = (),
) -> FixContext:
    return FixContext(
        package=Package(name="urllib3", version=version, depth=depth),
        advisory=Advisory(
            id="CVE-1",
            severity=Severity.HIGH,
            fixed_versions=fixed,
            affected_ranges=ranges,
        ),
        declared=declared,
        parents=parents or {},
        released=released,
        parent_upgrades=parent_upgrades or {},
    )


def test_nothing_blocking_is_a_lockfile_refresh() -> None:
    fix = classify(_context())
    assert fix.shape is FixShape.LOCKFILE_REFRESH
    assert fix.target_version == "1.26.17"
    assert fix.command == "uv lock --upgrade-package urllib3"


def test_a_permissive_declared_constraint_is_still_a_lockfile_refresh() -> None:
    """The manifest already allows the fix. Only the lockfile is stale."""
    assert classify(_context(declared=">=1.0")).shape is FixShape.LOCKFILE_REFRESH


def test_your_own_pin_blocking_the_fix_is_a_direct_bump() -> None:
    fix = classify(_context(declared="==1.26.5"))
    assert fix.shape is FixShape.DIRECT_BUMP
    assert fix.command == 'uv add "urllib3>=1.26.17"'
    assert "==1.26.5" in fix.reason


def test_a_parent_blocking_the_fix_is_an_override() -> None:
    fix = classify(_context(depth=2, fixed=("2.0.6",), parents={"requests": "<1.27,>=1.21.1"}))
    assert fix.shape is FixShape.OVERRIDE
    assert fix.blocking_parents[0].name == "requests"
    assert fix.blocking_parents[0].constraint == "<1.27,>=1.21.1"


def test_an_override_names_the_parent_upgrade_when_one_exists() -> None:
    """Upgrading the parent beats forcing a version it never declared support for."""
    fix = classify(
        _context(
            depth=2,
            fixed=("2.0.6",),
            parents={"requests": "<1.27,>=1.21.1"},
            parent_upgrades={"requests": "2.32.5"},
        )
    )
    assert fix.blocking_parents[0].upgrade_to == "2.32.5"
    assert "requests>=2.32.5" in (fix.command or "")


def test_a_parent_blocker_outranks_your_own_pin() -> None:
    """The case a depth-based rule gets wrong.

    urllib3 is both a direct dependency and a dependency of requests. If both
    constraints forbid the target, editing your own pin achieves nothing, because
    the resolver still has to satisfy requests.
    """
    fix = classify(
        _context(
            depth=1,
            fixed=("2.0.6",),
            declared="==1.26.5",
            parents={"requests": "<1.27,>=1.21.1"},
        )
    )
    assert fix.shape is FixShape.OVERRIDE


def test_no_fixed_version_and_no_unaffected_release_is_no_fix() -> None:
    fix = classify(_context(fixed=(), released=("1.26.5",)))
    assert fix.shape is FixShape.NO_FIX
    assert fix.command is None


def test_a_fix_only_on_a_newer_major_with_a_clean_release_on_your_line_is_a_backport() -> None:
    """The advisory listed only 2.0.6, but the ranges prove 1.26.17 is not affected."""
    fix = classify(
        _context(
            fixed=("2.0.6",),
            released=("1.26.5", "1.26.17", "2.0.6"),
            ranges=(AffectedRange(introduced="0", fixed="1.26.17"),),
        )
    )
    assert fix.shape is FixShape.BACKPORT_EXISTS
    assert fix.target_version == "1.26.17"


def test_a_newer_release_is_not_offered_as_a_backport_without_proof() -> None:
    """The bug this test exists for.

    With no affected ranges there is nothing showing 1.26.17 fixes anything. Offering
    it anyway recommends an upgrade on no evidence, which is worse than saying nothing.
    """
    fix = classify(_context(fixed=("2.0.6",), released=("1.26.5", "1.26.17", "2.0.6")))
    assert fix.shape is not FixShape.BACKPORT_EXISTS


def test_a_release_still_inside_the_affected_range_is_not_a_backport() -> None:
    """1.26.17 exists but the advisory says the 1.26 line is affected throughout."""
    fix = classify(
        _context(
            fixed=("2.0.6",),
            released=("1.26.5", "1.26.17", "2.0.6"),
            ranges=(AffectedRange(introduced="0", fixed="2.0.6"),),
        )
    )
    assert fix.shape is not FixShape.BACKPORT_EXISTS


def test_an_unreachable_release_list_is_unknown_not_no_fix() -> None:
    """A network failure must never be reported as "no fix exists"."""
    fix = classify(_context(fixed=(), released=None))
    assert fix.shape is FixShape.UNKNOWN
    assert not fix.is_actionable


def test_an_unparseable_installed_version_is_unknown() -> None:
    assert classify(_context(version="not-a-version")).shape is FixShape.UNKNOWN


def test_unparseable_fixed_versions_are_ignored() -> None:
    """OSV GIT ranges can put a commit SHA here."""
    fix = classify(_context(fixed=("644124ecd0b6e417c527191f866daa05a", "1.26.17")))
    assert fix.target_version == "1.26.17"


def test_a_parent_whose_constraint_could_not_be_read_is_unknown() -> None:
    """An unread constraint is not a permissive one."""
    fix = classify(_context(depth=2, parents={"requests": "!!! unparseable"}))
    assert fix.shape is FixShape.UNKNOWN
