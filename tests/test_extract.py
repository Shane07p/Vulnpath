"""Symbol extraction: the prompt, the envelope, and what happens when it fails.

No test here touches the network. What is under test is the contract around the model
call rather than the model's answers: that a failure is never mistaken for an empty
result, that a failure is never written to a cache with no expiry, and that the reply is
unwrapped defensively enough to survive a response shape nobody planned for.
"""

import json
from pathlib import Path
from unittest import mock

import httpx

from vulnpath.extract import (
    DETAIL_LIMIT,
    RESPONSE_SCHEMA,
    SymbolExtractor,
    build_prompt,
    is_plausible,
    parse_response,
)
from vulnpath.models import Advisory

YAML_NAMES = frozenset({"yaml"})


def _advisory(summary: str = "Arbitrary code execution", details: str = "") -> Advisory:
    return Advisory(
        id="GHSA-abcd-1234-efgh",
        aliases=("CVE-2020-14343",),
        summary=summary,
        details=details,
    )


def _reply(*symbols: str) -> mock.Mock:
    """A Gemini response carrying a schema-valid payload."""
    response = mock.Mock()
    response.raise_for_status = mock.Mock()
    response.json = mock.Mock(
        return_value={
            "candidates": [
                {"content": {"parts": [{"text": json.dumps({"symbols": list(symbols)})}]}}
            ]
        }
    )
    return response


def _extractor(tmp_path: Path, *, offline: bool = False) -> SymbolExtractor:
    """An extractor with a key and a private cache, so no test reads the user's."""
    return SymbolExtractor(tmp_path, api_key="test-key", offline=offline)


# --- the prompt ---------------------------------------------------------------------


def test_the_prompt_carries_the_advisory_and_the_import_names() -> None:
    """The model is given the evidence, not asked to recall the package from memory."""
    prompt = build_prompt(_advisory(details="yaml.load is unsafe"), "pyyaml", YAML_NAMES)

    assert "CVE-2020-14343" in prompt
    assert "Arbitrary code execution" in prompt
    assert "yaml.load is unsafe" in prompt
    assert "pyyaml" in prompt


def test_long_advisory_details_are_truncated() -> None:
    """Some advisories embed a full reproduction script and a patch.

    The symbol is named early in essentially all of them, so the tail is paid for on
    every uncached advisory and buys nothing.
    """
    details = "HEAD" + ("." * DETAIL_LIMIT) + "TAIL"
    prompt = build_prompt(_advisory(details=details), "pyyaml", YAML_NAMES)

    assert "HEAD" in prompt
    assert "TAIL" not in prompt


def test_an_advisory_with_no_prose_still_produces_a_prompt() -> None:
    """Plenty of OSV records carry neither summary nor details."""
    prompt = build_prompt(_advisory(summary="", details=""), "pyyaml", YAML_NAMES)
    assert "none published" in prompt


def test_the_schema_is_gemini_dialect_and_requires_the_field() -> None:
    """OpenAPI 3.0 subset, not JSON Schema — the uppercase types are load-bearing.

    Lowercase names are silently rejected, which turns constrained decoding off and
    leaves free-form prose to parse.
    """
    assert RESPONSE_SCHEMA["type"] == "OBJECT"
    assert RESPONSE_SCHEMA["properties"]["symbols"]["type"] == "ARRAY"
    assert RESPONSE_SCHEMA["required"] == ["symbols"]


# --- unwrapping the reply -----------------------------------------------------------


def test_a_well_formed_reply_parses() -> None:
    parsed = parse_response(_reply("yaml.load").json())
    assert parsed is not None
    assert parsed.symbols == ("yaml.load",)


def test_a_reply_with_no_candidates_is_a_failure_not_an_empty_result() -> None:
    """A safety block or a truncated generation returns an envelope with nothing in it.

    Reading that as "no symbols" would narrow a finding to nothing on the strength of a
    refusal.
    """
    assert parse_response({"candidates": []}) is None
    assert parse_response({}) is None
    assert parse_response("not even a dict") is None


def test_a_reply_whose_text_is_not_json_is_a_failure() -> None:
    """Constrained decoding makes this rare, not impossible."""
    payload = {"candidates": [{"content": {"parts": [{"text": "I cannot help with that."}]}}]}
    assert parse_response(payload) is None


def test_a_reply_of_the_wrong_shape_is_a_failure() -> None:
    payload = {"candidates": [{"content": {"parts": [{"text": '{"symbols": "yaml.load"}'}]}}]}
    assert parse_response(payload) is None


# --- the plausibility filter --------------------------------------------------------


def test_prose_is_not_a_symbol() -> None:
    assert not is_plausible("the load function", YAML_NAMES)


def test_a_bare_name_is_not_qualified_enough() -> None:
    """``load`` alone cannot be matched against a call graph keyed by full paths."""
    assert not is_plausible("load", YAML_NAMES)


def test_a_symbol_from_another_package_is_rejected() -> None:
    """Asked about PyYAML, told about the standard library."""
    assert not is_plausible("os.system", YAML_NAMES)


def test_a_qualified_name_in_the_right_package_passes() -> None:
    assert is_plausible("yaml.loader.Loader.construct", YAML_NAMES)


# --- availability -------------------------------------------------------------------


def test_offline_returns_none_without_asking(tmp_path: Path) -> None:
    """``--offline`` must work with no key, degrading rather than failing."""
    extractor = _extractor(tmp_path, offline=True)

    with mock.patch("httpx.post") as post:
        assert extractor.symbols_for(_advisory(), "pyyaml", YAML_NAMES) is None

    post.assert_not_called()


def test_no_api_key_returns_none_without_asking(tmp_path: Path) -> None:
    extractor = SymbolExtractor(tmp_path, api_key="")

    with mock.patch("httpx.post") as post:
        assert extractor.symbols_for(_advisory(), "pyyaml", YAML_NAMES) is None

    post.assert_not_called()
    assert not extractor.is_available


def test_a_package_with_no_known_import_names_is_not_asked_about(tmp_path: Path) -> None:
    """Without import names there is nothing to qualify a symbol against."""
    extractor = _extractor(tmp_path)

    with mock.patch("httpx.post") as post:
        assert extractor.symbols_for(_advisory(), "pyyaml", frozenset()) is None

    post.assert_not_called()


# --- failure handling ---------------------------------------------------------------


def test_a_network_failure_returns_none_rather_than_an_empty_tuple(tmp_path: Path) -> None:
    """The distinction the whole module is built around.

    ``()`` means the advisory names nothing specific, and narrows a finding. ``None``
    means no answer was obtained, and must leave the package-level verdict alone.
    """
    extractor = _extractor(tmp_path)

    with mock.patch("httpx.post", side_effect=httpx.ConnectError("network down")):
        assert extractor.symbols_for(_advisory(), "pyyaml", YAML_NAMES) is None

    assert extractor.extractions_failed == 1


def test_a_failure_is_never_written_to_the_cache(tmp_path: Path) -> None:
    """This cache has no expiry, so a cached failure would be permanent.

    The same mistake in the OSV client let one dropped connection mark a package clean
    forever. Here it would mean an advisory permanently believed to name no symbols.
    """
    extractor = _extractor(tmp_path)

    with mock.patch("httpx.post", side_effect=httpx.ConnectError("network down")):
        extractor.symbols_for(_advisory(), "pyyaml", YAML_NAMES)

    assert extractor.cache.read("GHSA-abcd-1234-efgh") is None

    with mock.patch("httpx.post", return_value=_reply("yaml.load")):
        assert extractor.symbols_for(_advisory(), "pyyaml", YAML_NAMES) == ("yaml.load",)


def test_a_malformed_reply_is_retried_once_then_given_up_on(tmp_path: Path) -> None:
    """Twice, not forever. A second failure is a signal about the service."""
    blocked = mock.Mock()
    blocked.raise_for_status = mock.Mock()
    blocked.json = mock.Mock(return_value={"candidates": []})

    extractor = _extractor(tmp_path)
    with mock.patch("httpx.post", return_value=blocked) as post:
        assert extractor.symbols_for(_advisory(), "pyyaml", YAML_NAMES) is None

    assert post.call_count == 2


def test_a_retry_can_succeed(tmp_path: Path) -> None:
    blocked = mock.Mock()
    blocked.raise_for_status = mock.Mock()
    blocked.json = mock.Mock(return_value={"candidates": []})

    extractor = _extractor(tmp_path)
    with mock.patch("httpx.post", side_effect=[blocked, _reply("yaml.load")]):
        assert extractor.symbols_for(_advisory(), "pyyaml", YAML_NAMES) == ("yaml.load",)

    assert extractor.extractions_failed == 0


# --- the request ---------------------------------------------------------------------


def test_the_request_constrains_decoding_and_authenticates_by_header(tmp_path: Path) -> None:
    """The key goes in a header, not the query string, so it stays out of logs and URLs."""
    extractor = _extractor(tmp_path)

    with mock.patch("httpx.post", return_value=_reply("yaml.load")) as post:
        extractor.symbols_for(_advisory(), "pyyaml", YAML_NAMES)

    _, kwargs = post.call_args
    assert kwargs["headers"]["x-goog-api-key"] == "test-key"
    assert kwargs["json"]["generationConfig"]["responseSchema"] == RESPONSE_SCHEMA
    assert kwargs["json"]["generationConfig"]["responseMimeType"] == "application/json"
    assert kwargs["json"]["generationConfig"]["temperature"] == 0
    assert "test-key" not in post.call_args[0][0]


# --- caching -------------------------------------------------------------------------


def test_a_result_is_cached_and_the_second_call_asks_nothing(tmp_path: Path) -> None:
    """Extraction is paid for once per advisory, ever."""
    extractor = _extractor(tmp_path)

    with mock.patch("httpx.post", return_value=_reply("yaml.load")) as post:
        extractor.symbols_for(_advisory(), "pyyaml", YAML_NAMES)
    assert post.call_count == 1

    second = _extractor(tmp_path)
    with mock.patch("httpx.post") as post:
        assert second.symbols_for(_advisory(), "pyyaml", YAML_NAMES) == ("yaml.load",)

    post.assert_not_called()
    assert second.cache_hits == 1


def test_an_empty_result_caches_as_empty_and_not_as_missing(tmp_path: Path) -> None:
    """ "This advisory names nothing specific" is an answer worth keeping.

    If it round-tripped as ``None`` the advisory would be re-extracted on every scan,
    and the caller would fall back to package level despite having been told otherwise.
    """
    extractor = _extractor(tmp_path)

    with mock.patch("httpx.post", return_value=_reply()):
        assert extractor.symbols_for(_advisory(), "pyyaml", YAML_NAMES) == ()

    second = _extractor(tmp_path)
    with mock.patch("httpx.post") as post:
        assert second.symbols_for(_advisory(), "pyyaml", YAML_NAMES) == ()

    post.assert_not_called()


def test_a_cached_answer_is_served_without_a_key(tmp_path: Path) -> None:
    """Shipping the cache as a repo artifact is only useful if it works unauthenticated."""
    with mock.patch("httpx.post", return_value=_reply("yaml.load")):
        _extractor(tmp_path).symbols_for(_advisory(), "pyyaml", YAML_NAMES)

    offline = SymbolExtractor(tmp_path, api_key="", offline=True)
    assert offline.symbols_for(_advisory(), "pyyaml", YAML_NAMES) == ("yaml.load",)


def test_implausible_symbols_are_filtered_before_caching(tmp_path: Path) -> None:
    """The cache stores the answer as used, so the filter runs before it, not after."""
    extractor = _extractor(tmp_path)

    with mock.patch("httpx.post", return_value=_reply("yaml.load", "os.system", "the loader")):
        assert extractor.symbols_for(_advisory(), "pyyaml", YAML_NAMES) == ("yaml.load",)

    assert extractor.cache.read("GHSA-abcd-1234-efgh") == ("yaml.load",)


def test_duplicate_symbols_collapse(tmp_path: Path) -> None:
    extractor = _extractor(tmp_path)

    with mock.patch("httpx.post", return_value=_reply("yaml.load", "yaml.load")):
        assert extractor.symbols_for(_advisory(), "pyyaml", YAML_NAMES) == ("yaml.load",)
