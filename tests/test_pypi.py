"""PyPI client, caching, and requirement parsing. No network."""

from pathlib import Path
from unittest import mock

import httpx

from vulnpath.pypi import PyPIClient, constraint_on

RELEASES_PAYLOAD = {
    "info": {"requires_dist": ["urllib3<1.27,>=1.21.1", "certifi>=2017.4.17"]},
    "releases": {"1.26.5": [], "1.26.17": [], "2.0.6": [], "2.2.2": []},
}


def _response(payload: dict[str, object]) -> mock.Mock:
    response = mock.Mock()
    response.raise_for_status = mock.Mock()
    response.json = mock.Mock(return_value=payload)
    return response


def test_releases_are_returned_and_cached(tmp_path: Path) -> None:
    client = PyPIClient(tmp_path)
    with mock.patch("httpx.get", return_value=_response(RELEASES_PAYLOAD)):
        assert set(client.releases("urllib3") or ()) == {"1.26.5", "1.26.17", "2.0.6", "2.2.2"}

    second = PyPIClient(tmp_path)
    with mock.patch("httpx.get", side_effect=AssertionError("must not be called")):
        assert set(second.releases("urllib3") or ()) == {"1.26.5", "1.26.17", "2.0.6", "2.2.2"}


def test_a_failed_lookup_returns_none_not_an_empty_list(tmp_path: Path) -> None:
    """Distinguishing these is the whole point.

    An empty tuple would mean "this package has no releases", which would classify a
    finding as NO_FIX. None means "we could not find out", which classifies it UNKNOWN.
    """
    client = PyPIClient(tmp_path)
    with mock.patch("httpx.get", side_effect=httpx.ConnectError("down")):
        assert client.releases("urllib3") is None
    assert client.lookups_failed == 1


def test_a_failed_lookup_is_never_cached(tmp_path: Path) -> None:
    """Caching a failure would make one dropped connection permanent."""
    client = PyPIClient(tmp_path)
    with mock.patch("httpx.get", side_effect=httpx.ConnectError("down")):
        client.releases("urllib3")

    retried = PyPIClient(tmp_path)
    with mock.patch("httpx.get", side_effect=httpx.ConnectError("still down")) as get:
        retried.releases("urllib3")
    assert get.called


def test_offline_returns_none_without_touching_the_network(tmp_path: Path) -> None:
    client = PyPIClient(tmp_path, offline=True)
    with mock.patch("httpx.get", side_effect=AssertionError("must not be called")):
        assert client.releases("urllib3") is None


def test_requires_dist_is_read_from_a_release(tmp_path: Path) -> None:
    client = PyPIClient(tmp_path)
    with mock.patch("httpx.get", return_value=_response(RELEASES_PAYLOAD)):
        assert client.requires_dist("requests", "2.25.1") == (
            "urllib3<1.27,>=1.21.1",
            "certifi>=2017.4.17",
        )


def test_constraint_is_extracted_for_the_named_package() -> None:
    assert (
        constraint_on(["urllib3<1.27,>=1.21.1", "certifi>=2017.4.17"], "urllib3")
        == "<1.27,>=1.21.1"
    )


def test_constraint_lookup_normalises_names() -> None:
    assert constraint_on(["PyYAML>=5.4"], "pyyaml") == ">=5.4"


def test_a_dependency_with_no_specifier_yields_none() -> None:
    """Present but unconstrained. Nothing to block a fix with."""
    assert constraint_on(["certifi"], "certifi") is None


def test_extra_dependencies_are_ignored() -> None:
    """An optional extra is not installed, so its constraint does not bind."""
    requires = ['ipywidgets>=7.5.1; extra == "jupyter"', "markdown-it-py>=2.2.0"]
    assert constraint_on(requires, "ipywidgets") is None
    assert constraint_on(requires, "markdown-it-py") == ">=2.2.0"


def test_an_absent_package_yields_none() -> None:
    assert constraint_on(["urllib3<1.27"], "flask") is None


def test_unparseable_requirement_lines_are_skipped() -> None:
    assert constraint_on(["!!! not a requirement", "urllib3<1.27"], "urllib3") == "<1.27"
