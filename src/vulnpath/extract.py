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

EXTRACTION_VERSION = 1
"""Bumped when the prompt or the schema changes.

The cache is permanent, so without this a stored answer to an older question would be
served forever as though it answered the current one.
"""

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
- Name only symbols the advisory text itself identifies. Do not infer likely names from \
what you know of the package's API, and do not guess at internal helpers the text does \
not mention.
- A symbol that appears only in a proof of concept, a reproduction script or an example \
of *calling* the package is not the vulnerable symbol, unless the text says the flaw is \
in it.
- If the advisory describes the flaw only in general terms and names no specific symbol, \
return an empty list. An empty list is a correct answer and is preferred over a guess.

Advisory {advisory_id}
Summary: {summary}

{details}
"""


class ExtractedSymbols(BaseModel):
    """The model's reply, parsed but not yet believed."""

    model_config = ConfigDict(extra="ignore")

    symbols: tuple[str, ...] = ()


def build_prompt(advisory: Advisory, package: str, import_names: frozenset[str]) -> str:
    """The question put to the model, with the advisory's own words as the evidence."""
    return PROMPT.format(
        package=package,
        import_names=", ".join(sorted(import_names)),
        advisory_id=advisory.display_id,
        summary=advisory.summary or "(none published)",
        details=advisory.details[:DETAIL_LIMIT] or "(no further detail published)",
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
        self.api_key = api_key if api_key is not None else os.environ.get(API_KEY_ENV, "")
        self.model = model
        self.timeout = timeout
        self.cache_hits = 0
        self.extractions_failed = 0

    @property
    def is_available(self) -> bool:
        """Whether a request could be made at all. A cached answer needs neither."""
        return bool(self.api_key) and not self.offline

    def symbols_for(
        self, advisory: Advisory, package: str, import_names: frozenset[str]
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
        # second failure is a signal about the service, not about this advisory.
        extracted = self._request(advisory, package, import_names) or self._request(
            advisory, package, import_names
        )
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

    def _request(
        self, advisory: Advisory, package: str, import_names: frozenset[str]
    ) -> ExtractedSymbols | None:
        body = {
            "contents": [{"parts": [{"text": build_prompt(advisory, package, import_names)}]}],
            "generationConfig": {
                "temperature": 0,
                "responseMimeType": "application/json",
                "responseSchema": RESPONSE_SCHEMA,
            },
        }
        try:
            response = httpx.post(
                ENDPOINT.format(model=self.model),
                json=body,
                headers={"x-goog-api-key": self.api_key},
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            return None
        return parse_response(payload)
