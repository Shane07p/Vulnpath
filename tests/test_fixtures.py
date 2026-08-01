"""Guards on the fixture corpus.

Every stage of this tool is tested against real resolver output, never a hand-written
lockfile. These tests fail loudly if a fixture is deleted or replaced with a mock.
"""

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE_PROJECT = FIXTURES / "sample_project"


def test_sample_project_has_a_real_lockfile() -> None:
    lockfile = SAMPLE_PROJECT / "uv.lock"
    assert lockfile.is_file(), "fixture lockfile missing — regenerate with `uv lock` in that dir"

    content = lockfile.read_text(encoding="utf-8")
    assert "version = 1" in content
    # Resolver output carries hashes and upload timestamps; a hand-written mock will not.
    assert "sha256:" in content


@pytest.mark.parametrize(
    "package",
    ["pyyaml", "urllib3", "jinja2", "requests"],
)
def test_declared_vulnerable_packages_are_in_the_lock(package: str) -> None:
    content = (SAMPLE_PROJECT / "uv.lock").read_text(encoding="utf-8")
    assert f'name = "{package}"' in content


@pytest.mark.parametrize("package", ["certifi", "chardet", "idna", "markupsafe"])
def test_lock_contains_transitive_packages(package: str) -> None:
    """Fix-shape classification needs a real transitive tree, not just direct deps."""
    content = (SAMPLE_PROJECT / "uv.lock").read_text(encoding="utf-8")
    assert f'name = "{package}"' in content
