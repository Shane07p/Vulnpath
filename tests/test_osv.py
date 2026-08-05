"""Advisory parsing, deduplication, caching and failure handling."""

import os
import time
from pathlib import Path
from unittest import mock

import httpx

from vulnpath.models import Advisory, Package, Severity
from vulnpath.osv import (
    QUERY_TTL_SECONDS,
    Cache,
    OsvClient,
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


# --- network failure handling -----------------------------------------------------
# The request path had no coverage, which is how the cache-poisoning bug below shipped.


def test_a_failed_query_is_never_written_to_the_cache(tmp_path: Path) -> None:
    """The regression that matters most in this file.

    Caching an empty result for a request that failed persists "no known
    vulnerabilities" to disk permanently. Every later scan then serves that from cache
    without touching the network, so one dropped connection marks a package clean
    forever. That is the false-negative failure mode the project forbids.
    """
    client = OsvClient(tmp_path, offline=False)
    packages = [Package(name="pyyaml", version="5.3.1", depth=1)]

    with mock.patch("httpx.post", side_effect=httpx.ConnectError("network down")):
        assert client.advisories_for(packages) == {}

    assert list((tmp_path / "queries").glob("*.json")) == []
    assert client.packages_unqueried == 1


def test_a_later_scan_retries_a_package_whose_query_failed(tmp_path: Path) -> None:
    client = OsvClient(tmp_path, offline=False)
    packages = [Package(name="pyyaml", version="5.3.1", depth=1)]
    with mock.patch("httpx.post", side_effect=httpx.ConnectError("network down")):
        client.advisories_for(packages)

    retried = OsvClient(tmp_path, offline=False)
    with mock.patch("httpx.post", side_effect=httpx.ConnectError("still down")) as post:
        retried.advisories_for(packages)

    assert post.called, "a failed lookup must not be remembered as a clean result"


def test_a_genuinely_clean_package_is_cached(tmp_path: Path) -> None:
    """The other half: an empty answer OSV actually gave is a real result."""
    client = OsvClient(tmp_path, offline=False)
    packages = [Package(name="pyyaml", version="5.3.1", depth=1)]

    response = mock.Mock()
    response.raise_for_status = mock.Mock()
    response.json = mock.Mock(return_value={"results": [{}]})

    with mock.patch("httpx.post", return_value=response):
        client.advisories_for(packages)

    assert client.cache.read_query("pyyaml@5.3.1") == []
    assert client.packages_unqueried == 0


def test_offline_with_nothing_cached_reports_the_gap(tmp_path: Path) -> None:
    client = OsvClient(tmp_path, offline=True)
    client.advisories_for([Package(name="pyyaml", version="5.3.1", depth=1)])
    assert client.packages_unqueried == 1


# --- merge correctness ------------------------------------------------------------


def test_merge_takes_the_worst_severity_not_the_longest_summary() -> None:
    """One database rating a flaw LOW must not override another rating it CRITICAL."""
    merged = deduplicate(
        [
            Advisory(id="A", aliases=("CVE-1",), summary="x" * 200, severity=Severity.LOW),
            Advisory(id="B", aliases=("CVE-1",), summary="short", severity=Severity.CRITICAL),
        ]
    )[0]
    assert merged.severity is Severity.CRITICAL


def test_merged_records_keep_their_ids_as_aliases() -> None:
    """Otherwise `explain PYSEC-2024-60` can never match a merged advisory."""
    merged = deduplicate(_pair())[0]
    assert "PYSEC-2024-60" in merged.aliases
    assert "GHSA-jjg7-2v4v-x38h" in merged.aliases


# --- cache expiry -----------------------------------------------------------------


def test_a_stale_query_entry_is_refetched(tmp_path: Path) -> None:
    """Observed in practice, not hypothetical.

    A scan cached 25 advisories for gitpython 3.1.29; OSV returned 28 minutes later.
    Without expiry the first answer is served forever and the three newly published
    advisories are never reported — a false negative that grows worse with age.
    """
    cache = Cache(tmp_path)
    cache.write_query("gitpython@3.1.29", ["GHSA-old"])

    path = tmp_path / "queries" / "gitpython@3.1.29.json"
    stale = time.time() - (QUERY_TTL_SECONDS + 60)
    os.utime(path, (stale, stale))

    assert cache.read_query("gitpython@3.1.29") is None


def test_a_fresh_query_entry_is_served_from_cache(tmp_path: Path) -> None:
    cache = Cache(tmp_path)
    cache.write_query("gitpython@3.1.29", ["GHSA-new"])
    assert cache.read_query("gitpython@3.1.29") == ["GHSA-new"]


def test_advisory_bodies_do_not_expire(tmp_path: Path) -> None:
    """An advisory's content is immutable once published; only the id list changes."""
    cache = Cache(tmp_path)
    cache.write_vuln(GHSA_PAYLOAD["id"], GHSA_PAYLOAD)  # type: ignore[arg-type]

    path = tmp_path / "vulns" / "GHSA-jjg7-2v4v-x38h.json"
    ancient = time.time() - (QUERY_TTL_SECONDS * 365)
    os.utime(path, (ancient, ancient))

    assert cache.read_vuln("GHSA-jjg7-2v4v-x38h") is not None
