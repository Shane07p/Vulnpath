"""PEP 440 version handling.

Every version comparison in this tool goes through this module. String comparison
gets `1.0` versus `1.0.0` wrong, and that error becomes wrong upgrade advice.
"""

import pytest

from vulnpath.versions import (
    Version,
    parse_specifier,
    parse_version,
    satisfies,
    select_target,
)


def test_equivalent_versions_written_differently_are_equal() -> None:
    assert parse_version("1.0") == parse_version("1.0.0")


def test_ordering_is_numeric_not_lexicographic() -> None:
    """String comparison puts "1.10" before "1.9". PEP 440 does not."""
    first = parse_version("1.10.0")
    second = parse_version("1.9.0")
    assert first is not None and second is not None
    assert first > second


@pytest.mark.parametrize("raw", ["1.0.0", "2.0.6", "1.26.17", "1.0.post1", "1!2.0", "1.0rc1"])
def test_valid_versions_parse(raw: str) -> None:
    assert parse_version(raw) is not None


@pytest.mark.parametrize("raw", ["", "not-a-version", "644124ecd0b6e417c527191f866daa05a"])
def test_unparseable_versions_return_none_rather_than_raising(raw: str) -> None:
    """A commit SHA reaches this code from OSV GIT ranges. It must not crash a scan."""
    assert parse_version(raw) is None


def test_specifier_parses() -> None:
    spec = parse_specifier("<1.27,>=1.21.1")
    assert spec is not None
    assert satisfies(Version("1.26.17"), spec)
    assert not satisfies(Version("2.0.6"), spec)


def test_unparseable_specifier_returns_none() -> None:
    assert parse_specifier("this is not a specifier") is None


def test_absent_specifier_permits_everything() -> None:
    """A package with no declared constraint blocks nothing."""
    assert satisfies(Version("99.0.0"), None)


def test_target_prefers_the_installed_major_line() -> None:
    """The whole point: a user on 1.26.5 wants 1.26.17, not a major upgrade to 2.0.6."""
    target = select_target(Version("1.26.5"), [Version("2.0.6"), Version("1.26.17")])
    assert target == Version("1.26.17")


def test_target_is_the_lowest_fix_on_that_line() -> None:
    target = select_target(
        Version("1.26.5"),
        [Version("1.26.20"), Version("1.26.17"), Version("1.26.18")],
    )
    assert target == Version("1.26.17")


def test_target_falls_back_to_the_lowest_candidate_when_no_same_major_fix_exists() -> None:
    target = select_target(Version("1.26.5"), [Version("3.0.0"), Version("2.0.6")])
    assert target == Version("2.0.6")


def test_candidates_at_or_below_installed_are_not_targets() -> None:
    """Downgrading is not a fix."""
    assert select_target(Version("2.0.0"), [Version("1.26.17"), Version("2.0.0")]) is None


def test_no_candidates_gives_no_target() -> None:
    assert select_target(Version("1.0.0"), []) is None
