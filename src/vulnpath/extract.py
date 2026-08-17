"""Which symbols an advisory names, read out of its prose.

The only stage that calls a model. Everything else in this pipeline is derivable from
files on disk; which function an advisory is *about* is written in English and nowhere
else, so it is read rather than computed.

Two rules make that safe to depend on. Nothing produced here is trusted until ``verify``
has found it in installed source, and a failed extraction returns ``None`` rather than an
empty tuple — "this advisory names no symbol" and "we could not ask" are different
answers, and collapsing them would narrow a finding to nothing on the strength of a
missing API key.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError

from vulnpath.models import Advisory

# Cache helpers live in ``osv`` because that is where caching first appeared. Imported
# rather than copied, and rather than hoisted into a module of their own — moving them
# would mean editing a stage this session is not touching.
from vulnpath.osv import default_cache_dir, read_json, safe_key, write_json

ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
DEFAULT_MODEL = "gemini-2.5-flash"
API_KEY_ENV = "GEMINI_API_KEY"

EXTRACTION_VERSION = 5
"""Bumped when the prompt or the schema changes.

The cache is permanent, so without this a stored answer to an older question would be
served forever as though it answered the current one.
"""

MAX_RETRY_WAIT = 60.0
"""Longest pause honoured after a rate limit, in seconds.

A provider asking for longer than this is rationing by the day rather than the minute,
and no scan should sit blocked waiting for that. Better to finish with package-level
verdicts and say so.
"""

RETRY_SECONDS = re.compile(r"retry in ([0-9.]+)s")
"""Gemini puts the wait in the error prose rather than a ``Retry-After`` header."""

DETAIL_LIMIT = 6000
"""How much advisory prose is sent.

Advisory ``details`` runs to tens of kilobytes on some records — full reproduction
scripts, patch text, mailing-list threads. The symbol is named early in essentially all
of them, so the tail buys nothing and is paid for on every uncached advisory.
"""

RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "OBJECT",
    "properties": {"symbols": {"type": "ARRAY", "items": {"type": "STRING"}}},
    "required": ["symbols"],
}
"""Gemini's schema dialect is a subset of OpenAPI 3.0, not JSON Schema — hence the
uppercase type names. Written out rather than generated from the pydantic model, because
translating between the two dialects is more code than the eight lines it would save.

This constrains decoding, so the reply is structurally valid by construction. It says
nothing about whether the symbols are real; that is ``verify``'s job.
"""

PROMPT = """You are reading a security advisory for the Python package `{package}`.

Name the specific functions, methods or classes the vulnerability is IN — the code that \
must run for this advisory to matter.

Rules:
- Give fully-qualified importable paths, each beginning with one of these top-level \
import names: {import_names}
- Name only symbols identified by the evidence below — the advisory text, or the fix diff \
when one is included. Do not infer likely names from what you know of the package's API, \
and do not guess at internal helpers no evidence mentions.
- A symbol that appears only in a proof of concept, a reproduction script or an example \
of *calling* the package is not the vulnerable symbol, unless the evidence says the flaw \
is in it.
- If neither the text nor the diff identifies a specific symbol, return an empty list. An \
empty list is a correct answer and is preferred over a guess.

Advisory {advisory_id}
Summary: {summary}

{details}
{patch}"""

PATCH_SECTION = """
Here is the commit that fixed this advisory. It is evidence of equal standing with the \
text above — where the text describes only the effect, this shows the code at fault.

Each `--- module ---` line gives the module the following hunks belong to, and each `@@` \
line ends with the definition the change sits inside. A definition whose body the fix \
modified is normally the vulnerable symbol, and should be named as \
`<module>.<definition>`.

Two cautions. A commit also carries refactors, renames and cleanups that merely travelled \
with the fix, so name a definition only where the change plausibly *is* the fix. And a \
definition the fix newly *added* is part of the remedy rather than the flaw — name the \
one that was changed to call it, not the new helper.

{diff}
"""
"""Appended to the prompt when a fix diff was obtained.

Worth the tokens because prose frequently describes the effect and never the code: an
advisory can spend a paragraph on an ``Authorization`` header leaking across a redirect
without once naming ``rebuild_auth``, which the diff names in its first hunk.
"""


class ExtractedSymbols(BaseModel):
    """The model's reply, parsed but not yet believed."""

    model_config = ConfigDict(extra="ignore")

    symbols: tuple[str, ...] = ()


def api_key_from_dotenv(path: Path) -> str:
    """Read one key out of a ``.env`` file, or return empty if there is none to read.

    Deliberately reads a single named variable rather than loading the file into the
    environment. A scan runs against directories the user did not write, and a general
    loader pointed at one would let a scanned repository set arbitrary environment
    variables in this process. Nothing here can set anything.

    A dependency-free reader rather than python-dotenv, because this handles the one
    shape a key is written in and adding a package for it is not worth the weight.
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return ""

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#") or "=" not in stripped:
            continue
        name, _, value = stripped.partition("=")
        if name.strip() == API_KEY_ENV:
            return value.strip().strip("'\"")
    return ""


def build_prompt(
    advisory: Advisory, package: str, import_names: frozenset[str], diff: str = ""
) -> str:
    """The question put to the model, with the advisory's own words as the evidence.

    The diff is appended rather than replacing the prose. Where a commit is genuinely the
    fix it names the symbol outright, but plenty are version bumps that touch nothing, and
    dropping the prose for one of those would trade the only evidence there is for none.
    """
    return PROMPT.format(
        package=package,
        import_names=", ".join(sorted(import_names)),
        advisory_id=advisory.display_id,
        summary=advisory.summary or "(none published)",
        details=advisory.details[:DETAIL_LIMIT] or "(no further detail published)",
        patch=PATCH_SECTION.format(diff=diff) if diff else "",
    )


def is_plausible(symbol: str, import_names: frozenset[str]) -> bool:
    """A cheap shape check, before the expensive one.

    Rejects prose that arrived where a name was asked for ("the load function"), and
    names belonging to some other package entirely. Everything surviving this must still
    be found in installed source — this only avoids reading files to reject a string that
    was never a symbol.
    """
    parts = symbol.split(".")
    if len(parts) < 2 or not all(part.isidentifier() for part in parts):
        return False
    return parts[0] in import_names


def parse_response(payload: Any) -> ExtractedSymbols | None:
    """Dig the JSON out of Gemini's envelope, or ``None`` if there is none to dig.

    The envelope is unwrapped defensively rather than modelled: a reply can carry no
    candidate at all — a safety block, a truncated generation — and that is a failure to
    extract rather than a malformed extraction.
    """
    if not isinstance(payload, dict):
        return None
    candidates = payload.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        return None
    first = candidates[0]
    if not isinstance(first, dict):
        return None
    content = first.get("content")
    if not isinstance(content, dict):
        return None
    parts = content.get("parts")
    if not isinstance(parts, list) or not parts:
        return None
    text = parts[0].get("text") if isinstance(parts[0], dict) else None
    if not isinstance(text, str):
        return None

    try:
        return ExtractedSymbols.model_validate_json(text)
    except ValidationError:
        return None


class SymbolCache:
    """Extractions keyed by advisory id, kept forever.

    No TTL, unlike the OSV *query* cache. What an advisory says is fixed once published,
    so the answer to "which symbols does this text name" cannot go stale the way "which
    advisories affect this version" does.
    """

    def __init__(self, root: Path) -> None:
        self.root = root / "symbols"

    def _path(self, advisory_id: str) -> Path:
        return self.root / f"{safe_key(f'v{EXTRACTION_VERSION}_{advisory_id}')}.json"

    def read(self, advisory_id: str) -> tuple[str, ...] | None:
        data = read_json(self._path(advisory_id))
        if isinstance(data, list) and all(isinstance(item, str) for item in data):
            return tuple(str(item) for item in data)
        return None

    def write(self, advisory_id: str, symbols: tuple[str, ...]) -> None:
        write_json(self._path(advisory_id), list(symbols))


class SymbolExtractor:
    """Asks the model which symbols an advisory names, once per advisory, ever.

    Unavailable — offline, or no API key — is a first-class state rather than an error.
    The caller degrades to package-level reachability and says so in the reported
    confidence, which is what ``--offline`` is specified to do.
    """

    def __init__(
        self,
        cache_dir: Path | None = None,
        *,
        offline: bool = False,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        timeout: float = 30.0,
    ) -> None:
        self.cache = SymbolCache(cache_dir or default_cache_dir())
        self.offline = offline

        # The environment wins over the file, so an export overrides a stale .env the
        # way anyone would expect. The file is read from the working directory, never
        # from the project being scanned — that directory is not necessarily the
        # user's, and its .env is not theirs to trust.
        if api_key is not None:
            self.api_key = api_key
        else:
            self.api_key = os.environ.get(API_KEY_ENV, "") or api_key_from_dotenv(
                Path.cwd() / ".env"
            )
        self.model = model
        self.timeout = timeout
        self.cache_hits = 0
        self.extractions_failed = 0

        self._rate_limited = False
        self._retry_after = 0.0

        self.quota_exhausted = False
        """Set once the provider has refused twice for quota, and never unset.

        A scan asks once per advisory, so a real project asks dozens of times. Without
        this, a quota that ran out on the third advisory is rediscovered by every one
        after it, at two requests and a sleep each — turning a finished scan into a long
        wait for the same answer. The first exhaustion is the last one worth finding.
        """

    @property
    def is_configured(self) -> bool:
        """Whether extraction was set up at all — a key exists and the network is allowed.

        Distinct from ``is_available``, which also asks whether the provider is still
        answering. A run that had a key and ran out of quota is a different thing to
        report than one that never had a key, and telling the second story for the first
        sends someone to look for a key they already set.
        """
        return bool(self.api_key) and not self.offline

    @property
    def is_available(self) -> bool:
        """Whether a request could be made right now. A cached answer needs neither."""
        return self.is_configured and not self.quota_exhausted

    def symbols_for(
        self, advisory: Advisory, package: str, import_names: frozenset[str], diff: str = ""
    ) -> tuple[str, ...] | None:
        """Symbols this advisory names, or ``None`` if extraction could not be done.

        Both empty results send the caller back to the package-level verdict — there is
        no symbol to narrow to either way, and neither is evidence the advisory is
        irrelevant. What differs is whether the question has been settled: ``()`` means
        the advisory was read and names nothing specific, and is cached so no later scan
        asks again. ``None`` means no answer was obtained, is never cached, and will be
        retried.
        """
        cached = self.cache.read(advisory.id)
        if cached is not None:
            self.cache_hits += 1
            return cached

        if not self.is_available or not import_names:
            return None

        # One retry. Constrained decoding makes a malformed reply rare enough that a
        # second failure is a signal about the service, not about this advisory. A rate
        # limit is the exception: retrying it instantly is guaranteed to fail, so the
        # wait the provider asked for is honoured before the second attempt.
        extracted = self._request(advisory, package, import_names, diff)
        if extracted is None and not self.quota_exhausted:
            if self._retry_after > 0:
                time.sleep(min(self._retry_after, MAX_RETRY_WAIT))
            extracted = self._request(advisory, package, import_names, diff)
        if extracted is None and self._rate_limited:
            # Refused twice for quota. Stop asking for the rest of this scan.
            self.quota_exhausted = True
        if extracted is None:
            self.extractions_failed += 1
            # Deliberately not cached. Writing a failure into a cache with no expiry
            # would make one bad afternoon permanent — the same mistake that let a
            # dropped OSV connection mark a package clean forever.
            return None

        kept = tuple(
            symbol
            for symbol in dict.fromkeys(extracted.symbols)
            if is_plausible(symbol, import_names)
        )
        self.cache.write(advisory.id, kept)
        return kept

    def _note_rate_limit(self, response: httpx.Response) -> None:
        """Record that the provider refused for quota, and how long it asked us to wait.

        The wait comes from the ``Retry-After`` header where one is sent, and otherwise
        out of the error prose — Gemini states it there rather than in a header.
        """
        self._rate_limited = True
        header = response.headers.get("retry-after", "")
        if header.strip().isdigit():
            self._retry_after = float(header.strip())
            return
        match = RETRY_SECONDS.search(response.text)
        self._retry_after = float(match.group(1)) if match else 0.0

    def _request(
        self, advisory: Advisory, package: str, import_names: frozenset[str], diff: str = ""
    ) -> ExtractedSymbols | None:
        body = {
            "contents": [
                {"parts": [{"text": build_prompt(advisory, package, import_names, diff)}]}
            ],
            "generationConfig": {
                "temperature": 0,
                "responseMimeType": "application/json",
                "responseSchema": RESPONSE_SCHEMA,
            },
        }
        self._rate_limited = False
        self._retry_after = 0.0
        try:
            response = httpx.post(
                ENDPOINT.format(model=self.model),
                json=body,
                headers={"x-goog-api-key": self.api_key},
                timeout=self.timeout,
            )
            if response.status_code == 429:
                self._note_rate_limit(response)
                return None
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            return None
        return parse_response(payload)
