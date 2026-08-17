"""The diff that fixed an advisory, reduced to the part worth reading.

Advisory prose often describes the effect and never names the code. Of six advisories
sampled, four named no symbol at all — one of them describing an ``Authorization`` header
leaking on redirect without ever mentioning ``rebuild_auth``, the function at fault. The
fix commit names it in the first hunk.

So this exists to add information, not to re-read what prose already said. Two things make
that safe to depend on:

**A diff is evidence, not an answer.** Everything a commit touched appears in it, including
refactors and unrelated cleanups, so what comes out of here is a candidate list. The model
still has to choose, and ``verify`` still has to confirm the choice exists.

**Not every fix commit is a fix.** Advisories point at whatever commit the database
recorded, which is sometimes a version bump touching only ``__init__.py``, and sometimes a
whole release range — one sampled here ran to 384KB across 180 hunks of an entire library.
A release diff is not more information, it is less: the answer is in there, diluted past
the point of being findable. Those are refused rather than truncated, because truncating
keeps an arbitrary slice and quietly presents it as the fix.
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx

from vulnpath.osv import default_cache_dir, read_json, safe_key, write_json

GITHUB_COMMIT = re.compile(r"^https?://github\.com/[^/]+/[^/]+/commit/[0-9a-f]{7,40}$")
"""Only GitHub commit URLs are fetchable as diffs here.

Other forges have their own patch conventions, and guessing one produces an HTML page
that happens to parse as a diff of nothing. An unsupported host is skipped, which costs
precision and never costs correctness.
"""

MAX_PATCH_BYTES = 80_000
"""Above this a commit is a release range rather than a fix, and is refused.

Chosen from the sampled spread rather than from taste: the two useful diffs were 7.8KB and
14KB, and the unusable one was 384KB. Anything approaching that size has a signal-to-noise
ratio that makes the model's job harder than prose alone, so falling back is the better
answer.
"""

MAX_DIFF_CHARS = 12_000
"""How much of the reduced diff is kept for the prompt."""

SKIP_PATH = re.compile(
    r"(^|/)(tests?|testing|dummyserver|docs?|examples?|benchmarks?)/|"
    r"(^|/)(setup|conftest)\.py$|_test\.py$|test_[^/]*\.py$"
)
"""Paths whose changes never name a vulnerable symbol.

Test files are the bulk of most security commits and are the most misleading part: a test
named ``test_redirect_strips_auth`` looks exactly like a finding and is not one.
"""


def is_fetchable(url: str) -> bool:
    return bool(GITHUB_COMMIT.match(url))


def module_path(path: str) -> str:
    """The importable part of a repository path, or empty if there is none.

    ``src/urllib3/poolmanager.py`` and ``urllib3/poolmanager.py`` are the same module; the
    layout of the repository is not the layout of the installed package.
    """
    if not path.endswith(".py") or SKIP_PATH.search(path):
        return ""
    trimmed = path.removeprefix("src/")
    return trimmed.removesuffix(".py").replace("/", ".").removesuffix(".__init__")


def reduce_patch(patch: str, limit: int = MAX_DIFF_CHARS) -> str:
    """Keep the Python hunks of a unified diff, dropping tests, docs and packaging.

    Hunk headers are kept because git puts the enclosing definition in them, which is
    precisely the thing being looked for — often the answer is legible from the headers
    alone, without reading a single changed line.
    """
    kept: list[str] = []
    current = ""
    total = 0

    for line in patch.splitlines():
        if line.startswith("+++ b/"):
            current = module_path(line[6:].strip())
            if current:
                header = f"\n--- {current} ---"
                kept.append(header)
                total += len(header)
            continue

        if not current:
            continue
        if not (line.startswith(("@@", "+", "-")) or line.startswith("  ")):
            continue
        if line.startswith(("+++", "---")):
            continue

        if total + len(line) > limit:
            kept.append("... (diff truncated)")
            break
        kept.append(line)
        total += len(line)

    return "\n".join(kept).strip()


class PatchCache:
    """Reduced diffs keyed by commit URL, kept forever — a commit never changes."""

    def __init__(self, root: Path) -> None:
        self.root = root / "patches"

    def _path(self, url: str) -> Path:
        return self.root / f"{safe_key(url)}.json"

    def read(self, url: str) -> str | None:
        data = read_json(self._path(url))
        return data if isinstance(data, str) else None

    def write(self, url: str, diff: str) -> None:
        write_json(self._path(url), diff)


class PatchFetcher:
    """Fetches and reduces fix diffs, once per commit, ever."""

    def __init__(
        self, cache_dir: Path | None = None, *, offline: bool = False, timeout: float = 30.0
    ) -> None:
        self.cache = PatchCache(cache_dir or default_cache_dir())
        self.offline = offline
        self.timeout = timeout
        self.fetched = 0
        self.refused_too_large = 0

    def diff_for(self, commit_urls: tuple[str, ...]) -> str:
        """Every usable reduced diff among these commits, up to one shared budget.

        All of them rather than the first. An advisory listing several commits does not
        list several copies of one fix: CVE-2018-18074 names two, of which the first only
        widens a version-compatibility assertion and the second is the actual change to
        ``rebuild_auth``. Taking the first found the bump, missed the fix, and reported
        that the advisory named nothing.
        """
        collected: list[str] = []
        budget = MAX_DIFF_CHARS

        for url in commit_urls:
            if budget <= 0:
                break
            if not is_fetchable(url):
                continue

            cached = self.cache.read(url)
            if cached is None:
                if self.offline:
                    continue
                cached = self._fetch(url)
                if cached is None:
                    # Never cached. A failed fetch is not a commit with no Python in it,
                    # and this cache has no expiry to correct the difference later.
                    continue
                self.cache.write(url, cached)

            if cached:
                collected.append(cached[:budget])
                budget -= len(cached)

        return "\n".join(collected).strip()

    def _fetch(self, url: str) -> str | None:
        try:
            response = httpx.get(f"{url}.patch", timeout=self.timeout, follow_redirects=True)
            response.raise_for_status()
        except httpx.HTTPError:
            return None

        patch = response.text
        self.fetched += 1
        if len(patch) > MAX_PATCH_BYTES:
            # Cached as empty on purpose: the commit is genuinely unusable, and that fact
            # is as permanent as the commit. Re-downloading 384KB on every scan to reach
            # the same conclusion helps nobody.
            self.refused_too_large += 1
            return ""
        return reduce_patch(patch)
