"""PyPI JSON client with a disk cache.

Deliberately shaped like ``osv.py``: same cache layout, and the same rule that a
failed request is not an answer and is never written to disk.

Two endpoints are used. ``/pypi/{name}/json`` gives every released version, which the
backport scan needs. ``/pypi/{name}/{version}/json`` gives one release's
``requires_dist``, which is where a parent's constraint lives — ``uv.lock`` records
dependency edges without specifiers, so it cannot answer that question.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import httpx
from packaging.requirements import InvalidRequirement, Requirement

from vulnpath.models import normalise
from vulnpath.osv import default_cache_dir, read_json, safe_key, write_json

PYPI_API = "https://pypi.org"


def constraint_on(requires_dist: Sequence[str], package: str) -> str | None:
    """The specifier one requirement list places on ``package``.

    Requirements guarded by an extra are skipped: an optional dependency is not
    installed unless the extra was requested, so its constraint does not bind the
    resolution being analysed.
    """
    wanted = normalise(package)
    for raw in requires_dist:
        try:
            requirement = Requirement(raw)
        except InvalidRequirement:
            continue
        if normalise(requirement.name) != wanted:
            continue
        if requirement.marker is not None and "extra" in str(requirement.marker):
            continue
        specifier = str(requirement.specifier)
        return specifier or None
    return None


class PyPIClient:
    """Release lists and dependency constraints, cached on disk."""

    def __init__(
        self,
        cache_dir: Path | None = None,
        *,
        offline: bool = False,
        timeout: float = 20.0,
    ) -> None:
        root = cache_dir or default_cache_dir()
        self.releases_dir = root / "pypi-releases"
        self.metadata_dir = root / "pypi-metadata"
        self.offline = offline
        self.timeout = timeout
        self.lookups_failed = 0

    def releases(self, name: str) -> tuple[str, ...] | None:
        """Every released version of ``name``, or ``None`` if that could not be found out.

        The distinction is load-bearing. An empty tuple says the package has no
        releases and would classify a finding as NO_FIX; ``None`` says the question
        went unanswered and classifies it UNKNOWN.
        """
        key = normalise(name)
        cached = read_json(self.releases_dir / f"{safe_key(key)}.json")
        if isinstance(cached, list):
            return tuple(str(v) for v in cached)

        payload = self._fetch(f"{PYPI_API}/pypi/{key}/json")
        if payload is None:
            return None

        raw = payload.get("releases")
        if not isinstance(raw, dict):
            self.lookups_failed += 1
            return None

        versions = [str(v) for v in raw]
        write_json(self.releases_dir / f"{safe_key(key)}.json", versions)
        return tuple(versions)

    def requires_dist(self, name: str, version: str) -> tuple[str, ...] | None:
        """One release's requirement strings, or ``None`` if unavailable."""
        key = f"{normalise(name)}@{version}"
        cached = read_json(self.metadata_dir / f"{safe_key(key)}.json")
        if isinstance(cached, list):
            return tuple(str(r) for r in cached)

        payload = self._fetch(f"{PYPI_API}/pypi/{normalise(name)}/{version}/json")
        if payload is None:
            return None

        info = payload.get("info")
        raw = info.get("requires_dist") if isinstance(info, dict) else None
        requirements = [str(r) for r in raw] if isinstance(raw, list) else []
        write_json(self.metadata_dir / f"{safe_key(key)}.json", requirements)
        return tuple(requirements)

    def _fetch(self, url: str) -> dict[str, Any] | None:
        if self.offline:
            self.lookups_failed += 1
            return None
        try:
            response = httpx.get(url, timeout=self.timeout)
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            self.lookups_failed += 1
            return None
        if not isinstance(payload, dict):
            self.lookups_failed += 1
            return None
        return payload
