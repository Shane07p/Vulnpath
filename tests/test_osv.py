"""Advisory parsing, deduplication and caching. No network."""

from pathlib import Path

from vulnpath.models import Advisory, Severity
from vulnpath.osv import (
    Cache,
    OsvVulnerability,
    deduplicate,
    extract_fixed_versions,
    extract_severity,
    to_advisory,
)

GHSA_PAYLOAD = {
    "id": "GHSA-jjg7-2v4v-x38h",
    "aliases": ["CVE-2024-3651"],
    "summary": "Denial of service in idna.encode",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
    "database_specific": {"severity": "MODERATE"},
    "affected": [
        {
            "package": {"name": "idna", "ecosystem": "PyPI"},
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.7"}]},
                {
                    "type": "GIT",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "1d365e17e10d72d0b7876316fc7b9ca0eeb"},
                    ],
                },
            ],
        }
    ],
    "references": [{"type": "ADVISORY", "url": "https://example.test/advisory"}],
}


def _vuln() -> OsvVulnerability:
    return OsvVulnerability.model_validate(GHSA_PAYLOAD)


def test_severity_word_is_read_from_database_specific() -> None:
    assert extract_severity(_vuln()) is Severity.MEDIUM


def test_moderate_maps_to_medium() -> None:
    payload = dict(GHSA_PAYLOAD, database_specific={"severity": "moderate"})
    assert extract_severity(OsvVulnerability.model_validate(payload)) is Severity.MEDIUM


def test_absent_severity_is_unknown_not_low() -> None:
    payload = dict(GHSA_PAYLOAD, database_specific={})
    assert extract_severity(OsvVulnerability.model_validate(payload)) is Severity.UNKNOWN


def test_git_commit_ranges_are_not_offered_as_fix_versions() -> None:
    """A commit SHA is real data but useless in `uv add "pkg>=X"`."""
    assert extract_fixed_versions(_vuln(), "idna") == ("3.7",)


def test_fix_versions_ignore_other_packages() -> None:
    assert extract_fixed_versions(_vuln(), "urllib3") == ()


def test_unknown_extra_fields_do_not_break_parsing() -> None:
    payload = dict(GHSA_PAYLOAD, some_future_field={"osv": "added this later"})
    assert OsvVulnerability.model_validate(payload).id == "GHSA-jjg7-2v4v-x38h"


def test_advisory_prefers_its_cve_alias_for_display() -> None:
    advisory = to_advisory(_vuln(), "idna")
    assert advisory.id == "GHSA-jjg7-2v4v-x38h"
    assert advisory.display_id == "CVE-2024-3651"


def test_advisory_without_a_cve_alias_displays_its_own_id() -> None:
    assert Advisory(id="PYSEC-2024-60").display_id == "PYSEC-2024-60"


# --- deduplication ----------------------------------------------------------------
# OSV returns one record per source database, so a single CVE arrives twice.


def _pair() -> list[Advisory]:
    return [
        Advisory(
            id="GHSA-jjg7-2v4v-x38h",
            aliases=("CVE-2024-3651",),
            summary="Short summary",
            severity=Severity.MEDIUM,
            fixed_versions=("3.7",),
            references=("https://example.test/ghsa",),
        ),
        Advisory(
            id="PYSEC-2024-60",
            aliases=("CVE-2024-3651",),
            summary="A considerably longer description of the same flaw",
            severity=Severity.UNKNOWN,
            fixed_versions=("3.7",),
            references=("https://example.test/pysec",),
        ),
    ]


def test_same_cve_from_two_databases_collapses_to_one() -> None:
    assert len(deduplicate(_pair())) == 1


def test_merge_keeps_the_severity_that_was_actually_published() -> None:
    merged = deduplicate(_pair())[0]
    assert merged.severity is Severity.MEDIUM


def test_merge_keeps_the_fuller_summary() -> None:
    merged = deduplicate(_pair())[0]
    assert merged.summary == "A considerably longer description of the same flaw"


def test_merge_unions_aliases_and_references() -> None:
    merged = deduplicate(_pair())[0]
    assert set(merged.references) == {
        "https://example.test/ghsa",
        "https://example.test/pysec",
    }


def test_distinct_cves_are_not_merged() -> None:
    advisories = [
        Advisory(id="GHSA-a", aliases=("CVE-2024-1",)),
        Advisory(id="GHSA-b", aliases=("CVE-2024-2",)),
    ]
    assert len(deduplicate(advisories)) == 2


# --- cache ------------------------------------------------------------------------


def test_cache_round_trips_a_query(tmp_path: Path) -> None:
    cache = Cache(tmp_path)
    cache.write_query("idna@2.10", ["GHSA-jjg7-2v4v-x38h"])
    assert cache.read_query("idna@2.10") == ["GHSA-jjg7-2v4v-x38h"]


def test_cache_miss_returns_none(tmp_path: Path) -> None:
    assert Cache(tmp_path).read_query("nothing@0.0.0") is None


def test_cache_round_trips_an_advisory(tmp_path: Path) -> None:
    cache = Cache(tmp_path)
    cache.write_vuln(GHSA_PAYLOAD["id"], GHSA_PAYLOAD)  # type: ignore[arg-type]
    restored = cache.read_vuln("GHSA-jjg7-2v4v-x38h")
    assert restored is not None
    assert extract_severity(restored) is Severity.MEDIUM
