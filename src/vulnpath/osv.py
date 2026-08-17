"""OSV.dev client with a disk cache.

Two calls are needed, not one: ``querybatch`` returns only advisory ids, and each
advisory's content comes from ``/v1/vulns/{id}``. Both layers are cached, because
advisories change slowly and a scan should be near-instant on the second run.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict

from vulnpath.models import (
    Advisory,
    AffectedRange,
    Package,
    Severity,
    normalise,
    severity_rank,
)

OSV_API = "https://api.osv.dev"
BATCH_SIZE = 100
"""OSV does not document a hard limit on querybatch; 100 is well inside what it accepts."""

QUERY_TTL_SECONDS = 24 * 60 * 60
"""How long a package's advisory list stays trusted.

Only the *query* layer expires. Advisory bodies are keyed by id and are effectively
immutable, so they are cached permanently; which advisories affect a given version
is not, because new ones are published against releases that already exist."""

_UNSAFE = re.compile(r"[^A-Za-z0-9._@-]+")


# --- wire format ------------------------------------------------------------------
# Parsed at the boundary so nothing downstream handles a raw dict.


class _Lenient(BaseModel):
    model_config = ConfigDict(extra="ignore")


class OsvEvent(_Lenient):
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None


class OsvRange(_Lenient):
    type: str = ""
    repo: str = ""
    events: list[OsvEvent] = []


class OsvPackageRef(_Lenient):
    name: str = ""
    ecosystem: str = ""


class OsvAffected(_Lenient):
    package: OsvPackageRef = OsvPackageRef()
    ranges: list[OsvRange] = []
    versions: list[str] = []


class OsvSeverity(_Lenient):
    type: str = ""
    score: str = ""


class OsvReference(_Lenient):
    type: str = ""
    url: str = ""


class OsvVulnerability(_Lenient):
    id: str
    aliases: list[str] = []
    summary: str = ""
    details: str = ""
    severity: list[OsvSeverity] = []
    affected: list[OsvAffected] = []
    references: list[OsvReference] = []
    database_specific: dict[str, Any] = {}


# --- severity ---------------------------------------------------------------------

_GHSA_SEVERITY: dict[str, Severity] = {
    "LOW": Severity.LOW,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


def extract_severity(vuln: OsvVulnerability) -> Severity:
    """Read a severity word if the advisory carries one.

    OSV's ``severity`` field holds CVSS *vectors*, not scores — deriving a band from
    one means implementing the CVSS formula, which is not worth guessing at. Advisories
    sourced from GHSA carry a plain word in ``database_specific``; everything else is
    honestly ``UNKNOWN``.
    """
    raw = vuln.database_specific.get("severity")
    if isinstance(raw, str):
        return _GHSA_SEVERITY.get(raw.upper(), Severity.UNKNOWN)
    return Severity.UNKNOWN


def extract_fixed_versions(vuln: OsvVulnerability, package_name: str) -> tuple[str, ...]:
    """Released versions the fix landed in, for this package only.

    Only ``ECOSYSTEM`` ranges. Advisories also carry ``GIT`` ranges whose events hold
    commit SHAs — real data, but useless in ``uv add "pkg>=X"``, and alarming to read
    in a column headed "fixed in".
    """
    wanted = normalise(package_name)
    fixed: list[str] = []
    for affected in vuln.affected:
        if normalise(affected.package.name) != wanted:
            continue
        for range_ in affected.ranges:
            if range_.type.upper() not in {"ECOSYSTEM", "SEMVER"}:
                continue
            for event in range_.events:
                if event.fixed:
                    fixed.append(event.fixed)
    return tuple(dict.fromkeys(fixed))


def extract_affected_ranges(vuln: OsvVulnerability, package_name: str) -> tuple[AffectedRange, ...]:
    """The intervals of versions this advisory says are affected, for this package.

    Needed to answer whether a release the advisory never mentions is safe. Knowing
    only the fixed versions cannot answer that, and guessing would mean recommending
    an upgrade with no evidence it fixes anything.
    """
    wanted = normalise(package_name)
    ranges: list[AffectedRange] = []
    for affected in vuln.affected:
        if normalise(affected.package.name) != wanted:
            continue
        for range_ in affected.ranges:
            if range_.type.upper() not in {"ECOSYSTEM", "SEMVER"}:
                continue
            introduced: str | None = None
            for event in range_.events:
                if event.introduced is not None:
                    introduced = event.introduced
                elif event.fixed is not None or event.last_affected is not None:
                    ranges.append(
                        AffectedRange(
                            introduced=introduced,
                            fixed=event.fixed,
                            last_affected=event.last_affected,
                        )
                    )
                    introduced = None
            if introduced is not None:
                ranges.append(AffectedRange(introduced=introduced))
    return tuple(ranges)


def extract_fix_commits(vuln: OsvVulnerability) -> tuple[str, ...]:
    """Commit URLs for the fixes, built from ``GIT`` ranges.

    These are the same ranges ``extract_fixed_versions`` deliberately skips. A commit SHA
    is useless as a version to upgrade to, which is why it is filtered out there — but it
    is exactly what is wanted to read the patch that fixed the flaw.

    Not filtered to any host here. Whether a URL can actually be fetched as a diff is the
    fetcher's business, and it is the one place that knows which hosts it supports.
    """
    commits: list[str] = []
    for affected in vuln.affected:
        for range_ in affected.ranges:
            if range_.type.upper() != "GIT" or not range_.repo:
                continue
            repo = range_.repo.rstrip("/").removesuffix(".git")
            for event in range_.events:
                if event.fixed:
                    commits.append(f"{repo}/commit/{event.fixed}")
    return tuple(dict.fromkeys(commits))


def _union_ranges(group: list[Advisory]) -> tuple[AffectedRange, ...]:
    """Deduplicate affected ranges across records by their field values.

    Pydantic models are not hashable, so the usual ``dict.fromkeys`` trick does not
    work here.
    """
    seen: set[tuple[str | None, str | None, str | None]] = set()
    merged: list[AffectedRange] = []
    for advisory in group:
        for affected in advisory.affected_ranges:
            key = (affected.introduced, affected.fixed, affected.last_affected)
            if key not in seen:
                seen.add(key)
                merged.append(affected)
    return tuple(merged)


def _merge(group: list[Advisory]) -> Advisory:
    """Fold records describing the same CVE into one.

    Fields are taken from whichever record actually has them: GHSA carries severity,
    PYSEC often carries a fuller description, and fixed versions can differ where one
    database tracked a backport the other missed. Taking the union loses nothing.
    """
    primary = max(group, key=lambda a: (a.severity is not Severity.UNKNOWN, len(a.summary)))

    # The worst severity anyone published, not the primary record's. Picking the record
    # with the longest summary and taking its severity would let a database that rated
    # something LOW override another that rated the same flaw CRITICAL.
    severity = max((a.severity for a in group), key=severity_rank)

    def _union(values: list[tuple[str, ...]]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(item for group_ in values for item in group_))

    return Advisory(
        id=primary.id,
        # Every merged record's own id becomes an alias. Without this the dropped
        # record's id is unreachable — `vulnpath explain PYSEC-2024-60` would never
        # match, and a cache keyed by advisory id would miss the same advisory
        # arriving under a different database's identifier.
        aliases=_union([a.aliases for a in group] + [tuple(a.id for a in group)]),
        summary=max((a.summary for a in group), key=len),
        details=max((a.details for a in group), key=len),
        severity=severity,
        fixed_versions=_union([a.fixed_versions for a in group]),
        # Union of ranges, not the primary's. One database can describe an interval
        # the other omits, and a missing interval reads as "not affected".
        affected_ranges=_union_ranges(group),
        references=_union([a.references for a in group]),
        fix_commits=_union([a.fix_commits for a in group]),
    )


def deduplicate(advisories: list[Advisory]) -> list[Advisory]:
    """Collapse advisories that describe the same vulnerability.

    OSV returns one record per source database, so a single CVE arrives twice — once
    from GHSA and once from PYSEC. Reporting both doubles the finding count for no
    added information, which is exactly the noise this tool exists to remove.
    """
    groups: dict[str, list[Advisory]] = {}
    for advisory in advisories:
        groups.setdefault(advisory.display_id, []).append(advisory)
    return [_merge(group) for group in groups.values()]


def to_advisory(vuln: OsvVulnerability, package_name: str) -> Advisory:
    return Advisory(
        id=vuln.id,
        aliases=tuple(vuln.aliases),
        summary=vuln.summary,
        details=vuln.details,
        severity=extract_severity(vuln),
        fixed_versions=extract_fixed_versions(vuln, package_name),
        affected_ranges=extract_affected_ranges(vuln, package_name),
        references=tuple(ref.url for ref in vuln.references if ref.url),
        fix_commits=extract_fix_commits(vuln),
    )


# --- cache ------------------------------------------------------------------------


def default_cache_dir() -> Path:
    """Per-user cache, never inside the scanned repo — that gets committed by accident."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "vulnpath" / "cache"
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "vulnpath"


def safe_key(key: str) -> str:
    return _UNSAFE.sub("_", key)[:120]


class Cache:
    """Two flat JSON stores: package queries, and advisory bodies."""

    def __init__(self, root: Path) -> None:
        self.queries = root / "queries"
        self.vulns = root / "vulns"

    def read_query(self, key: str) -> list[str] | None:
        """Cached advisory ids for a package, unless the entry has expired.

        Which advisories affect a given version is not a fixed fact: new ones are
        published against releases that already exist. Observed in practice — a scan
        cached 25 advisories for gitpython 3.1.29 and OSV returned 28 minutes later.
        Without expiry that first answer is served forever and the three new
        advisories are never reported.

        Expiry uses the file's modification time so the stored format stays a plain
        list, readable by older builds.
        """
        path = self.queries / f"{safe_key(key)}.json"
        try:
            age = time.time() - path.stat().st_mtime
        except OSError:
            return None
        if age > QUERY_TTL_SECONDS:
            return None

        data = read_json(path)
        if isinstance(data, list) and all(isinstance(i, str) for i in data):
            return [str(i) for i in data]
        return None

    def write_query(self, key: str, ids: list[str]) -> None:
        write_json(self.queries / f"{safe_key(key)}.json", ids)

    def read_vuln(self, advisory_id: str) -> OsvVulnerability | None:
        data = read_json(self.vulns / f"{safe_key(advisory_id)}.json")
        if isinstance(data, dict):
            return OsvVulnerability.model_validate(data)
        return None

    def write_vuln(self, advisory_id: str, payload: dict[str, Any]) -> None:
        write_json(self.vulns / f"{safe_key(advisory_id)}.json", payload)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def write_json(path: Path, payload: Any) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
    except OSError:
        # A cache that cannot be written is a slow scan, not a failed one.
        pass


# --- client -----------------------------------------------------------------------


class OsvClient:
    """Looks up advisories for resolved packages.

    In offline mode no request is made at all; whatever the cache holds is used and
    the shortfall is reported so the output can say how complete it is.
    """

    def __init__(
        self,
        cache_dir: Path | None = None,
        *,
        offline: bool = False,
        timeout: float = 20.0,
    ) -> None:
        self.cache = Cache(cache_dir or default_cache_dir())
        self.offline = offline
        self.timeout = timeout
        self.cache_hits = 0
        self.packages_unqueried = 0
        """Packages whose advisory list could not be obtained at all.

        Either offline with nothing cached, or the request failed. These are gaps in
        coverage, not evidence of a clean package, and the renderers say so.
        """

    def advisories_for(self, packages: list[Package]) -> dict[str, list[Advisory]]:
        """Advisory list per normalised package name."""
        ids_by_package = self._advisory_ids(packages)

        result: dict[str, list[Advisory]] = {}
        for package in packages:
            advisories: list[Advisory] = []
            for advisory_id in ids_by_package.get(package.name, []):
                vuln = self._vulnerability(advisory_id)
                if vuln is not None:
                    advisories.append(to_advisory(vuln, package.name))
            advisories = deduplicate(advisories)
            if advisories:
                result[package.name] = advisories
        return result

    def _advisory_ids(self, packages: list[Package]) -> dict[str, list[str]]:
        found: dict[str, list[str]] = {}
        pending: list[Package] = []

        for package in packages:
            cached = self.cache.read_query(f"{package.name}@{package.version}")
            if cached is not None:
                found[package.name] = cached
                self.cache_hits += 1
            else:
                pending.append(package)

        if not pending:
            return found

        if self.offline:
            self.packages_unqueried += len(pending)
            return found

        for start in range(0, len(pending), BATCH_SIZE):
            chunk = pending[start : start + BATCH_SIZE]
            results = self._querybatch(chunk)
            if results is None:
                # The request failed. Record the gap and move on WITHOUT caching —
                # writing an empty list here would persist "no known vulnerabilities"
                # to disk permanently, and every later scan would serve that from
                # cache without touching the network. One dropped connection would
                # silently mark a package clean forever.
                self.packages_unqueried += len(chunk)
                continue
            for package, ids in zip(chunk, results, strict=True):
                found[package.name] = ids
                self.cache.write_query(f"{package.name}@{package.version}", ids)

        return found

    def _querybatch(self, packages: list[Package]) -> list[list[str]] | None:
        """Advisory ids per package, or ``None`` if the query could not be answered.

        The ``None`` matters: "OSV said this package is clean" and "OSV could not be
        reached" must not share a representation. Collapsing them is how a network
        failure becomes a permanent false negative.
        """
        payload = {
            "queries": [
                {"package": {"name": p.name, "ecosystem": "PyPI"}, "version": p.version}
                for p in packages
            ]
        }
        try:
            response = httpx.post(f"{OSV_API}/v1/querybatch", json=payload, timeout=self.timeout)
            response.raise_for_status()
            body = response.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            return None

        results = body.get("results") if isinstance(body, dict) else None
        if not isinstance(results, list) or len(results) != len(packages):
            return None

        out: list[list[str]] = []
        for entry in results:
            vulns = entry.get("vulns") if isinstance(entry, dict) else None
            ids = (
                [v["id"] for v in vulns if isinstance(v, dict) and isinstance(v.get("id"), str)]
                if isinstance(vulns, list)
                else []
            )
            out.append(ids)
        return out

    def _vulnerability(self, advisory_id: str) -> OsvVulnerability | None:
        cached = self.cache.read_vuln(advisory_id)
        if cached is not None:
            return cached
        if self.offline:
            return None

        try:
            response = httpx.get(f"{OSV_API}/v1/vulns/{advisory_id}", timeout=self.timeout)
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            return None

        if not isinstance(payload, dict):
            return None
        self.cache.write_vuln(advisory_id, payload)
        return OsvVulnerability.model_validate(payload)
