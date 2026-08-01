"""Scan orchestration, plus the severity-filter safety rule."""

from pathlib import Path

import pytest

from vulnpath.models import Severity
from vulnpath.scan import passes_severity_floor, run_scan

SAMPLE_PROJECT = Path(__file__).parent / "fixtures" / "sample_project"


@pytest.mark.parametrize(
    ("severity", "floor", "expected"),
    [
        (Severity.CRITICAL, Severity.HIGH, True),
        (Severity.HIGH, Severity.HIGH, True),
        (Severity.MEDIUM, Severity.HIGH, False),
        (Severity.LOW, Severity.MEDIUM, False),
        (Severity.LOW, None, True),
    ],
)
def test_severity_floor_filters_as_a_threshold(
    severity: Severity, floor: Severity | None, expected: bool
) -> None:
    assert passes_severity_floor(severity, floor) is expected


@pytest.mark.parametrize("floor", [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL])
def test_unknown_severity_is_never_filtered_out(floor: Severity) -> None:
    """Hiding a finding because its severity was never published is a false negative.

    A data gap is not evidence of low risk. This is the same principle as UNKNOWN
    reachability never collapsing into NOT_REACHABLE.
    """
    assert passes_severity_floor(Severity.UNKNOWN, floor) is True


def test_offline_scan_without_a_cache_reports_nothing_rather_than_failing(
    tmp_path: Path,
) -> None:
    result = run_scan(SAMPLE_PROJECT, offline=True, cache_dir=tmp_path)
    assert result.offline is True
    assert result.packages_scanned == 8
    assert result.findings == []


def test_scan_counts_packages_from_the_lockfile_excluding_the_project(tmp_path: Path) -> None:
    result = run_scan(SAMPLE_PROJECT, offline=True, cache_dir=tmp_path)
    assert result.packages_scanned == 8
