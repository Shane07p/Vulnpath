"""Environment discovery.

The rule under test is a safety rule: vulnpath runs in its own virtualenv, and
resolving a scan against that environment instead of the target's would describe the
wrong project while looking entirely successful.
"""

import sys
from pathlib import Path

import pytest

from vulnpath.environment import EnvironmentError_, find_site_packages, installed_distributions


def _make_venv(root: Path, *, posix: bool = False) -> Path:
    site_packages = (
        root / ".venv" / "lib" / "python3.12" / "site-packages"
        if posix
        else root / ".venv" / "Lib" / "site-packages"
    )
    site_packages.mkdir(parents=True)
    return site_packages


def test_finds_the_project_venv(tmp_path: Path) -> None:
    expected = _make_venv(tmp_path)
    assert find_site_packages(tmp_path) == expected


def test_finds_a_posix_layout_venv(tmp_path: Path) -> None:
    expected = _make_venv(tmp_path, posix=True)
    assert find_site_packages(tmp_path) == expected


def test_refuses_to_fall_back_to_vulnpaths_own_environment(tmp_path: Path) -> None:
    """The whole point. A silent fallback here is a wrong answer that looks right."""
    with pytest.raises(EnvironmentError_) as exc:
        find_site_packages(tmp_path)

    message = str(exc.value)
    assert "uv sync" in message
    assert sys.prefix in message


def test_explicit_override_is_honoured(tmp_path: Path) -> None:
    other = tmp_path / "elsewhere"
    site_packages = other / "Lib" / "site-packages"
    site_packages.mkdir(parents=True)
    assert find_site_packages(tmp_path, other) == site_packages


def test_bad_override_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(EnvironmentError_, match="not a virtual environment"):
        find_site_packages(tmp_path, tmp_path / "does-not-exist")


def test_unrelated_active_virtualenv_is_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """$VIRTUAL_ENV only counts when it lives inside the project being scanned."""
    elsewhere = tmp_path / "some-other-project"
    (elsewhere / "Lib" / "site-packages").mkdir(parents=True)
    monkeypatch.setenv("VIRTUAL_ENV", str(elsewhere))

    project = tmp_path / "project"
    project.mkdir()
    with pytest.raises(EnvironmentError_):
        find_site_packages(project)


def test_reads_installed_versions_from_dist_info(tmp_path: Path) -> None:
    site_packages = _make_venv(tmp_path)
    (site_packages / "PyYAML-5.3.1.dist-info").mkdir()
    (site_packages / "urllib3-1.26.5.dist-info").mkdir()

    assert installed_distributions(site_packages) == {
        "pyyaml": "5.3.1",
        "urllib3": "1.26.5",
    }


def test_empty_environment_reports_nothing_installed(tmp_path: Path) -> None:
    assert installed_distributions(_make_venv(tmp_path)) == {}
