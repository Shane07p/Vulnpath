"""Fetching and reducing the diff that fixed an advisory.

The reduction is the part worth testing hardest. A diff is only useful here if the
Python that changed survives and everything else does not — and the failure that
motivated this module was not a missing diff but a useless one, 384KB of an entire
library in which the answer was present and unfindable.
"""

from pathlib import Path
from unittest import mock

import httpx

from vulnpath.patches import (
    MAX_PATCH_BYTES,
    PatchFetcher,
    is_fetchable,
    module_path,
    reduce_patch,
)

COMMIT = "https://github.com/psf/requests/commit/c45d7c49ea75133e52ab22a8e9e13173938e36ff"

PATCH = """From c45d7c4 Mon Sep 17 00:00:00 2001
diff --git a/requests/sessions.py b/requests/sessions.py
--- a/requests/sessions.py
+++ b/requests/sessions.py
@@ -242,7 +242,9 @@ def rebuild_auth(self, prepared_request, response):
             original_parsed = urlparse(response.request.url)
-            if (original_parsed.hostname != redirect_parsed.hostname):
+            if (original_parsed.hostname != redirect_parsed.hostname
+                    or original_parsed.port != redirect_parsed.port):
                 del headers['Authorization']
diff --git a/tests/test_requests.py b/tests/test_requests.py
--- a/tests/test_requests.py
+++ b/tests/test_requests.py
@@ -100,3 +100,9 @@ def test_redirect_strips_auth(self):
+    def test_new_case(self):
+        assert True
"""


def _response(text: str) -> mock.Mock:
    response = mock.Mock()
    response.raise_for_status = mock.Mock()
    response.text = text
    return response


# --- which URLs can be fetched -------------------------------------------------------


def test_a_github_commit_url_is_fetchable() -> None:
    assert is_fetchable(COMMIT)


def test_a_pull_request_or_compare_url_is_not() -> None:
    """Both have patch endpoints, but neither is a commit and the shapes differ.

    Skipping costs precision. Guessing at a URL shape returns an HTML page that reduces
    to an empty diff and looks exactly like a commit with no Python in it.
    """
    assert not is_fetchable("https://github.com/pallets/jinja/pull/1343")
    assert not is_fetchable("https://github.com/urllib3/urllib3/compare/a6ec68a...1efadf4")


def test_a_non_github_url_is_not_fetchable() -> None:
    assert not is_fetchable("https://bugs.debian.org/910766")
    assert not is_fetchable("https://gitlab.com/owner/repo/-/commit/abc1234")


# --- repository path to module -------------------------------------------------------


def test_a_src_layout_prefix_is_stripped() -> None:
    """The repository's layout is not the installed package's layout."""
    assert module_path("src/urllib3/poolmanager.py") == "urllib3.poolmanager"


def test_a_flat_layout_is_unchanged() -> None:
    assert module_path("requests/sessions.py") == "requests.sessions"


def test_a_package_init_names_the_package() -> None:
    assert module_path("jinja2/__init__.py") == "jinja2"


def test_tests_docs_and_packaging_are_excluded() -> None:
    """A test named ``test_redirect_strips_auth`` looks exactly like a finding."""
    for path in (
        "tests/test_requests.py",
        "test/test_x.py",
        "requests/test_sessions.py",
        "dummyserver/handlers.py",
        "docs/conf.py",
        "setup.py",
        "conftest.py",
    ):
        assert module_path(path) == "", path


def test_non_python_files_are_excluded() -> None:
    assert module_path("CHANGES.rst") == ""
    assert module_path("uv.lock") == ""


# --- reduction -----------------------------------------------------------------------


def test_the_enclosing_definition_survives_reduction() -> None:
    """Git puts the enclosing definition in the hunk header, which is the answer."""
    reduced = reduce_patch(PATCH)

    assert "requests.sessions" in reduced
    assert "def rebuild_auth" in reduced


def test_test_files_do_not_survive_reduction() -> None:
    reduced = reduce_patch(PATCH)
    assert "test_redirect_strips_auth" not in reduced
    assert "test_new_case" not in reduced


def test_reduction_respects_its_budget() -> None:
    reduced = reduce_patch(PATCH, limit=80)
    assert len(reduced) < 400
    assert "truncated" in reduced


# --- fetching ------------------------------------------------------------------------


def test_a_fetched_diff_is_reduced_and_cached(tmp_path: Path) -> None:
    fetcher = PatchFetcher(tmp_path)

    with mock.patch("httpx.get", return_value=_response(PATCH)) as get:
        first = fetcher.diff_for((COMMIT,))
    assert "def rebuild_auth" in first
    assert get.call_count == 1

    with mock.patch("httpx.get") as get:
        assert PatchFetcher(tmp_path).diff_for((COMMIT,)) == first
    get.assert_not_called()


def test_every_usable_commit_contributes(tmp_path: Path) -> None:
    """An advisory listing several commits does not list several copies of one fix.

    CVE-2018-18074 names two: the first only widens a version-compatibility assertion,
    and the second is the change to ``rebuild_auth``. Taking the first found the bump and
    reported that the advisory named nothing.
    """
    bump = "https://github.com/psf/requests/commit/bd840450c0d1e9db3bf62382c15d96378cc3a056"
    bump_patch = (
        "--- a/requests/__init__.py\n"
        "+++ b/requests/__init__.py\n"
        "@@ -57,10 +57,10 @@ def check_compatibility(urllib3_version, chardet_version):\n"
        "-    assert minor <= 23\n"
        "+    assert minor <= 24\n"
    )

    fetcher = PatchFetcher(tmp_path)
    with mock.patch("httpx.get", side_effect=[_response(bump_patch), _response(PATCH)]):
        diff = fetcher.diff_for((bump, COMMIT))

    assert "check_compatibility" in diff
    assert "def rebuild_auth" in diff


def test_a_release_sized_diff_is_refused(tmp_path: Path) -> None:
    """The failure this module's size gate exists for.

    A 384KB commit is a release range, not a fix. Its answer is present and diluted past
    finding, so feeding it to the model is worse than sending prose alone.
    """
    fetcher = PatchFetcher(tmp_path)
    huge = "x" * (MAX_PATCH_BYTES + 1)

    with mock.patch("httpx.get", return_value=_response(huge)):
        assert fetcher.diff_for((COMMIT,)) == ""

    assert fetcher.refused_too_large == 1

    # Cached as unusable, because that will not change. Re-downloading a release diff on
    # every scan to reach the same verdict helps nobody.
    with mock.patch("httpx.get") as get:
        assert PatchFetcher(tmp_path).diff_for((COMMIT,)) == ""
    get.assert_not_called()


def test_a_failed_fetch_is_not_cached(tmp_path: Path) -> None:
    """A dropped connection is not a commit with no Python in it.

    This cache has no expiry, so recording the difference wrongly is permanent.
    """
    fetcher = PatchFetcher(tmp_path)

    with mock.patch("httpx.get", side_effect=httpx.ConnectError("down")):
        assert fetcher.diff_for((COMMIT,)) == ""

    with mock.patch("httpx.get", return_value=_response(PATCH)):
        assert "def rebuild_auth" in PatchFetcher(tmp_path).diff_for((COMMIT,))


def test_offline_fetches_nothing(tmp_path: Path) -> None:
    fetcher = PatchFetcher(tmp_path, offline=True)

    with mock.patch("httpx.get") as get:
        assert fetcher.diff_for((COMMIT,)) == ""
    get.assert_not_called()


def test_offline_still_serves_a_cached_diff(tmp_path: Path) -> None:
    """Shipping the cache as a repo artifact is only useful if it works offline."""
    with mock.patch("httpx.get", return_value=_response(PATCH)):
        PatchFetcher(tmp_path).diff_for((COMMIT,))

    with mock.patch("httpx.get") as get:
        assert "def rebuild_auth" in PatchFetcher(tmp_path, offline=True).diff_for((COMMIT,))
    get.assert_not_called()


def test_an_advisory_with_no_commits_asks_for_nothing(tmp_path: Path) -> None:
    with mock.patch("httpx.get") as get:
        assert PatchFetcher(tmp_path).diff_for(()) == ""
    get.assert_not_called()
