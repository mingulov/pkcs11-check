"""Published-artifact tests: install integrity, entry points, fetch-then-test order.

These are the assertions the manual TestPyPI validation pass showed were missing:
they run in the ordinary meta-test suite AND in the post-TestPyPI gate
(`.github/workflows/testpypi-gate.yml`), which executes this file from outside
its checkout against the TestPyPI-installed package. So every path here resolves
through the *imported* `pkcs11_check` package (package origin, shipped manifest),
never through the source checkout, and the file needs nothing beyond the runtime
dependencies (no yaml, no git).
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from importlib.metadata import PackageNotFoundError, entry_points, version
from pathlib import Path

import pytest

import pkcs11_check
from pkcs11_check import __version__
from pkcs11_check.cli.app import app
from pkcs11_check.core.collection import CollectedPytestItem, collect_pytest_item_metadata
from pkcs11_check.testcases.data import SOURCES_TOML
from tests._plain_cli_runner import PlainCliRunner

runner = PlainCliRunner()

# Resolved through the imported package so the gate (installed layout) and the
# dev suite (editable layout) both target the testcases they actually import.
_HMAC_MODULE = (
    Path(pkcs11_check.__file__).resolve().parent
    / "testcases"
    / "wycheproof"
    / "test_wycheproof_hmac.py"
)

_CANONICAL_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(rc[1-9][0-9]*)?$")


def _distribution_version() -> str:
    """Installed `pkcs11-check` dist version, or skip when no metadata exists.

    Under PKCS11_CHECK_GATE_STRICT (set by the TestPyPI gate, whose pip
    install always writes metadata) a missing distribution is a failure:
    skipping there would let a broken install stay green.
    """
    try:
        return version("pkcs11-check")
    except PackageNotFoundError:
        if os.environ.get("PKCS11_CHECK_GATE_STRICT"):
            pytest.fail("pkcs11-check distribution metadata is not installed")
        pytest.skip("pkcs11-check distribution metadata is not installed")


def test_version_stamp_is_canonical_and_matches_distribution() -> None:
    """Install integrity: the `__version__` stamp agrees with dist metadata."""
    assert _CANONICAL_VERSION.match(__version__), __version__
    assert _distribution_version() == __version__


def test_console_scripts_are_registered() -> None:
    """Install integrity: both console shims resolve to installed entry points."""
    _distribution_version()  # skip when there is no metadata to read
    scripts = {e.name: e for e in entry_points(group="console_scripts")}
    for name, value in (
        ("pkcs11-check", "pkcs11_check.cli.app:main"),
        ("pkcs11-check-report", "pkcs11_check.report.__main__:main"),
    ):
        entry = scripts.get(name)
        assert entry is not None, f"console script {name!r} is missing"
        assert entry.value == value, entry.value
        # A string match alone would pass with a deleted/renamed target.
        assert callable(entry.load()), f"console script {name!r} does not load"


def test_pytest11_entry_point_loads_the_plugin() -> None:
    """Entry-point registration: the pytest plugin resolves and exposes hooks."""
    _distribution_version()  # skip when there is no metadata to read
    plugin_entry = next(
        (e for e in entry_points(group="pytest11") if e.name == "pkcs11-check"), None
    )
    assert plugin_entry is not None, "pytest11 entry point 'pkcs11-check' is missing"
    assert plugin_entry.value == "pkcs11_check.plugin", plugin_entry.value
    # Another distribution could register the same name and mask a missing one.
    assert plugin_entry.dist is not None
    assert plugin_entry.dist.metadata["Name"] == "pkcs11-check"
    plugin = plugin_entry.load()
    assert callable(plugin.pytest_addoption), "plugin exposes no pytest_addoption hook"
    assert callable(plugin.pytest_configure), "plugin exposes no pytest_configure hook"


def _manifest_source_names() -> list[str]:
    """Vendor source names from the SHIPPED manifest (no checkout, no network)."""
    assert SOURCES_TOML.is_file(), f"shipped manifest is missing: {SOURCES_TOML}"
    manifest = tomllib.loads(SOURCES_TOML.read_text(encoding="utf-8"))
    names = sorted(manifest)
    assert names, "shipped manifest lists no sources"
    return names


def test_fetch_data_status_distinguishes_missing_and_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ordering primitive: `--status` reports per-source missing vs fetched."""
    monkeypatch.chdir(tmp_path)  # status output names only the data dir, never the cwd
    names = _manifest_source_names()
    empty = tmp_path / "empty-data"
    empty.mkdir()

    missing = runner.invoke(app, ["fetch-data", "--status", "--data-dir", str(empty)])
    assert missing.exit_code == 0, missing.output
    for name in names:
        assert name in missing.output
        assert f"(pkcs11-check fetch-data {name})" in missing.output

    for name in names:
        (empty / name).mkdir()
    present = runner.invoke(app, ["fetch-data", "--status", "--data-dir", str(empty)])
    assert present.exit_code == 0, present.output
    for name in names:
        assert name in present.output
        assert f"(pkcs11-check fetch-data {name})" not in present.output


def _collect_hmac_items(data_dir: Path) -> list[CollectedPytestItem]:
    """Collect the HMAC vector module with `data_dir` as the only vector source."""
    assert _HMAC_MODULE.is_file(), f"shipped HMAC module is missing: {_HMAC_MODULE}"
    # Deliberately no PKCS11_CHECK_NO_COLLECTION_CACHE: the flip must prove
    # real fetch-then-test ordering through the production cache path (the
    # cache digest covers data-dir file mtimes/sizes, so distinct data dirs
    # can never alias — a stale hit here would be a product bug, not flakes).
    env = {
        **os.environ,
        "PKCS11_CHECK_DATA_DIR": str(data_dir),
    }
    # Must not raise: with vectors absent the suite skips, it never crashes.
    return collect_pytest_item_metadata([str(_HMAC_MODULE)], [], env=env)


# Two fresh-subprocess collections (each well under a second); the 180s
# allowance matches what the no-data guard needs for the same helper.
@pytest.mark.timeout(180)
def test_vector_suite_flips_from_skip_to_collected_when_data_appears(
    tmp_path: Path,
) -> None:
    """Fetch-then-test ordering: data presence flips the suite empty->executing.

    A synthetic one-vector file stands in for `fetch-data` (no network): with
    no data the module collects no vector cases, and once the vector file the
    fetch would have installed appears, the same module collects its case.
    """
    empty_data = tmp_path / "empty-data"
    empty_data.mkdir()
    before = _collect_hmac_items(empty_data)
    assert not any("tc1-valid" in item.nodeid for item in before), [i.nodeid for i in before]

    fetched = tmp_path / "fetched-data" / "wycheproof" / "testvectors_v1"
    fetched.mkdir(parents=True)
    (fetched / "hmac_sha512_test.json").write_text(
        json.dumps(
            {
                "testGroups": [
                    {
                        "tagSize": 512,
                        "tests": [
                            {"tcId": 1, "result": "valid", "key": "00", "msg": "00", "tag": "00"}
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    after = _collect_hmac_items(tmp_path / "fetched-data")
    assert any("hmac_sha512_test.json:tc1-valid" in item.nodeid for item in after), [
        i.nodeid for i in after
    ]
