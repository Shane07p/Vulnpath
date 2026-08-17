"""Symbol extraction: the prompt, the envelope, and what happens when it fails.

No test here touches the network. What is under test is the contract around the model
call rather than the model's answers: that a failure is never mistaken for an empty
result, that a failure is never written to a cache with no expiry, and that the reply is
unwrapped defensively enough to survive a response shape nobody planned for.
"""

import json
import os
from pathlib import Path
from unittest import mock

import httpx

from vulnpath.extract import (
    DETAIL_LIMIT,
    MAX_RETRY_WAIT,
    RESPONSE_SCHEMA,
    SymbolExtractor,
    api_key_from_dotenv,
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


# --- reading the key off disk --------------------------------------------------------


def test_the_key_is_read_from_a_dotenv_file(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("GEMINI_API_KEY=abc123\n", encoding="utf-8")
    assert api_key_from_dotenv(env) == "abc123"


def test_quotes_and_spacing_are_tolerated(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text('  GEMINI_API_KEY = "abc123"  \n', encoding="utf-8")
    assert api_key_from_dotenv(env) == "abc123"


def test_comments_and_other_variables_are_ignored(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text(
        "# GEMINI_API_KEY=commented-out\nOTHER=value\nGEMINI_API_KEY=real\n", encoding="utf-8"
    )
    assert api_key_from_dotenv(env) == "real"


def test_nothing_but_the_one_key_is_ever_read(tmp_path: Path) -> None:
    """The security property, not a convenience one.

    A scan runs against directories the user did not write. A general loader pointed at
    one would let a scanned repository set arbitrary environment variables in this
    process — PATH among them. This reader returns a string and touches nothing.
    """
    env = tmp_path / ".env"
    env.write_text("PATH=/evil\nGEMINI_API_KEY=abc123\n", encoding="utf-8")

    before = os.environ.get("PATH")
    assert api_key_from_dotenv(env) == "abc123"
    assert os.environ.get("PATH") == before


def test_a_missing_or_unreadable_file_is_not_an_error(tmp_path: Path) -> None:
    assert api_key_from_dotenv(tmp_path / "nope.env") == ""


def test_an_exported_variable_wins_over_the_file(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """An export overrides a stale file, the way every other tool behaves."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("GEMINI_API_KEY=from-file\n", encoding="utf-8")
    monkeypatch.setenv("GEMINI_API_KEY", "from-env")

    assert SymbolExtractor(tmp_path).api_key == "from-env"


def test_the_file_is_used_when_nothing_is_exported(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("GEMINI_API_KEY=from-file\n", encoding="utf-8")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    assert SymbolExtractor(tmp_path).api_key == "from-file"


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


# --- rate limits ---------------------------------------------------------------------
# A free-tier key allows a couple of dozen requests, and a real scan asks once per
# advisory. Rate limiting is therefore the expected path on any project worth scanning,
# not an edge case.


def _rate_limited(retry_in: str = "18.1") -> mock.Mock:
    response = mock.Mock()
    response.status_code = 429
    response.headers = {}
    response.text = f"Quota exceeded. Please retry in {retry_in}s."
    return response


def test_an_immediate_retry_is_not_attempted_after_a_rate_limit(tmp_path: Path) -> None:
    """Retrying a quota refusal instantly is guaranteed to fail.

    The provider states how long to wait; honouring it is the difference between a
    second attempt and a second identical rejection.
    """
    extractor = _extractor(tmp_path)

    with (
        mock.patch("httpx.post", return_value=_rate_limited("18.1")) as post,
        mock.patch("vulnpath.extract.time.sleep") as sleep,
    ):
        assert extractor.symbols_for(_advisory(), "pyyaml", YAML_NAMES) is None

    assert post.call_count == 2
    sleep.assert_called_once_with(18.1)


def test_a_retry_after_header_is_preferred_when_sent(tmp_path: Path) -> None:
    response = _rate_limited()
    response.headers = {"retry-after": "5"}
    extractor = _extractor(tmp_path)

    with (
        mock.patch("httpx.post", return_value=response),
        mock.patch("vulnpath.extract.time.sleep") as sleep,
    ):
        extractor.symbols_for(_advisory(), "pyyaml", YAML_NAMES)

    sleep.assert_called_once_with(5.0)


def test_an_absurd_wait_is_capped(tmp_path: Path) -> None:
    """A provider rationing by the day must not block a scan for the day."""
    extractor = _extractor(tmp_path)

    with (
        mock.patch("httpx.post", return_value=_rate_limited("86400")),
        mock.patch("vulnpath.extract.time.sleep") as sleep,
    ):
        extractor.symbols_for(_advisory(), "pyyaml", YAML_NAMES)

    sleep.assert_called_once_with(MAX_RETRY_WAIT)


def test_quota_exhaustion_stops_the_scan_asking_again(tmp_path: Path) -> None:
    """The circuit breaker.

    A scan asks once per advisory. Without this, a quota that ran out on the third
    advisory is rediscovered by every one after it, at two requests and a sleep each.
    """
    extractor = _extractor(tmp_path)

    with (
        mock.patch("httpx.post", return_value=_rate_limited()) as post,
        mock.patch("vulnpath.extract.time.sleep"),
    ):
        extractor.symbols_for(_advisory(), "pyyaml", YAML_NAMES)
        assert extractor.quota_exhausted
        assert not extractor.is_available

        second = Advisory(id="GHSA-second", summary="another")
        assert extractor.symbols_for(second, "pyyaml", YAML_NAMES) is None

    assert post.call_count == 2


def test_a_rate_limit_is_never_cached(tmp_path: Path) -> None:
    """Quota resets. A cache with no expiry must not outlive it."""
    extractor = _extractor(tmp_path)

    with (
        mock.patch("httpx.post", return_value=_rate_limited()),
        mock.patch("vulnpath.extract.time.sleep"),
    ):
        extractor.symbols_for(_advisory(), "pyyaml", YAML_NAMES)

    assert extractor.cache.read("GHSA-abcd-1234-efgh") is None


def test_a_retry_after_the_wait_can_succeed(tmp_path: Path) -> None:
    extractor = _extractor(tmp_path)

    with (
        mock.patch("httpx.post", side_effect=[_rate_limited(), _reply("yaml.load")]),
        mock.patch("vulnpath.extract.time.sleep"),
    ):
        assert extractor.symbols_for(_advisory(), "pyyaml", YAML_NAMES) == ("yaml.load",)

    assert not extractor.quota_exhausted


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
