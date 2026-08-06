"""Reading what an environment has installed, and where its source sits.

Synthetic site-packages trees: the logic is about file layout and metadata, not about
any particular package's contents.
"""

from pathlib import Path

from vulnpath.installed import find_module_file, import_names, owning_distribution


def _dist(site_packages: Path, name: str, version: str) -> Path:
    dist_info = site_packages / f"{name}-{version}.dist-info"
    dist_info.mkdir(parents=True)
    return dist_info


def test_import_names_come_from_record(tmp_path: Path) -> None:
    """RECORD is the reliable source; top_level.txt is increasingly absent."""
    dist_info = _dist(tmp_path, "PyYAML", "5.3.1")
    (dist_info / "RECORD").write_text(
        "yaml/__init__.py,sha256=abc,100\n"
        "yaml/loader.py,sha256=def,200\n"
        "PyYAML-5.3.1.dist-info/METADATA,sha256=ghi,50\n",
        encoding="utf-8",
    )
    assert import_names(tmp_path) == {"pyyaml": frozenset({"yaml"})}


def test_a_distribution_name_is_not_its_import_name(tmp_path: Path) -> None:
    """The reason this module exists. PyYAML imports as yaml, and nothing in the name says so."""
    dist_info = _dist(tmp_path, "PyYAML", "5.3.1")
    (dist_info / "RECORD").write_text("yaml/__init__.py,,\n", encoding="utf-8")

    names = import_names(tmp_path)
    assert "pyyaml" in names
    assert names["pyyaml"] == frozenset({"yaml"})


def test_a_single_module_distribution(tmp_path: Path) -> None:
    dist_info = _dist(tmp_path, "six", "1.16.0")
    (dist_info / "RECORD").write_text("six.py,sha256=abc,100\n", encoding="utf-8")
    assert import_names(tmp_path) == {"six": frozenset({"six"})}


def test_a_distribution_installing_several_names(tmp_path: Path) -> None:
    dist_info = _dist(tmp_path, "setuptools", "70.0.0")
    (dist_info / "RECORD").write_text(
        "setuptools/__init__.py,,\npkg_resources/__init__.py,,\n", encoding="utf-8"
    )
    assert import_names(tmp_path)["setuptools"] == frozenset({"setuptools", "pkg_resources"})


def test_dist_info_and_data_entries_are_not_import_names(tmp_path: Path) -> None:
    dist_info = _dist(tmp_path, "thing", "1.0")
    (dist_info / "RECORD").write_text(
        "thing/__init__.py,,\n"
        "thing-1.0.dist-info/METADATA,,\n"
        "thing-1.0.data/scripts/run,,\n"
        "../../bin/thing,,\n",
        encoding="utf-8",
    )
    assert import_names(tmp_path)["thing"] == frozenset({"thing"})


def test_top_level_txt_is_used_when_there_is_no_record(tmp_path: Path) -> None:
    dist_info = _dist(tmp_path, "legacy", "0.1")
    (dist_info / "top_level.txt").write_text("legacy\nlegacy_extra\n", encoding="utf-8")
    assert import_names(tmp_path)["legacy"] == frozenset({"legacy", "legacy_extra"})


def test_a_distribution_with_no_usable_metadata_is_skipped(tmp_path: Path) -> None:
    _dist(tmp_path, "empty", "1.0")
    assert import_names(tmp_path) == {}


def test_owning_distribution_matches_on_the_top_level_name() -> None:
    names = {"pyyaml": frozenset({"yaml"}), "requests": frozenset({"requests"})}
    assert owning_distribution("yaml.loader.Loader", names) == "pyyaml"
    assert owning_distribution("requests", names) == "requests"


def test_an_unknown_module_has_no_owning_distribution() -> None:
    assert owning_distribution("os.path", {"pyyaml": frozenset({"yaml"})}) is None


def test_finds_a_plain_module_file(tmp_path: Path) -> None:
    (tmp_path / "yaml").mkdir()
    (tmp_path / "yaml" / "loader.py").write_text("", encoding="utf-8")
    assert find_module_file(tmp_path, "yaml.loader") == tmp_path / "yaml" / "loader.py"


def test_finds_a_packages_init(tmp_path: Path) -> None:
    (tmp_path / "yaml").mkdir()
    (tmp_path / "yaml" / "__init__.py").write_text("", encoding="utf-8")
    assert find_module_file(tmp_path, "yaml") == tmp_path / "yaml" / "__init__.py"


def test_a_module_that_is_not_installed_here_is_not_an_error(tmp_path: Path) -> None:
    """The standard library and compiled extensions both land here, and both are leaves."""
    assert find_module_file(tmp_path, "os.path") is None
    assert find_module_file(tmp_path, "_ctypes") is None
