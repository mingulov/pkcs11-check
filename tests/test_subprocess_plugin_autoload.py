"""Regression tests for per-subprocess pytest plugin autoload control.

Isolated unit subprocesses disable plugin autoload and enable only the plugins
they need, trimming startup cost without changing test behavior.
"""

from __future__ import annotations

import sys
from pathlib import Path

from pkcs11_check.core.file_runner import (
    _subprocess_plugin_env,
    _unit_plugin_addopts,
)

_TESTCASES = Path(__file__).resolve().parents[1] / "src" / "pkcs11_check" / "testcases"


def test_base_plugins_only_for_ordinary_file() -> None:
    addopts = _unit_plugin_addopts(str(_TESTCASES / "test_reinitialize.py"))
    assert addopts == "-p pkcs11-check -p pytest_reportlog -p timeout"


def test_hypothesis_plugin_added_for_hypothesis_file() -> None:
    addopts = _unit_plugin_addopts(str(_TESTCASES / "test_fuzz.py"))
    assert addopts is not None
    assert "-p hypothesispytest" in addopts
    assert "-p benchmark" not in addopts


def test_benchmark_plugin_added_for_benchmark_file() -> None:
    addopts = _unit_plugin_addopts(str(_TESTCASES / "test_benchmark.py"))
    assert addopts is not None
    assert "-p benchmark" in addopts


def test_unreadable_file_leaves_autoload_enabled() -> None:
    # No addopts -> caller must NOT disable autoload (safe fallback).
    assert _unit_plugin_addopts(str(_TESTCASES / "does_not_exist.py")) is None


def test_env_disables_autoload_and_sets_addopts() -> None:
    env = _subprocess_plugin_env({}, str(_TESTCASES / "test_reinitialize.py"))
    assert env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert env["PYTEST_ADDOPTS"] == "-p pkcs11-check -p pytest_reportlog -p timeout"


def test_env_preserves_existing_addopts() -> None:
    base = {"PYTEST_ADDOPTS": "--maxfail=1"}
    env = _subprocess_plugin_env(base, str(_TESTCASES / "test_reinitialize.py"))
    assert env["PYTEST_ADDOPTS"].endswith("--maxfail=1")
    assert env["PYTEST_ADDOPTS"].startswith("-p pkcs11-check")


def test_env_unchanged_when_file_unreadable() -> None:
    base = {"FOO": "bar"}
    env = _subprocess_plugin_env(base, str(_TESTCASES / "does_not_exist.py"))
    # On Windows the helper ALWAYS seeds PYTHONUTF8=1 so a unit's pytest output cannot die
    # on a cp1252 console. That baseline is deliberate and unrelated to plugin selection,
    # so the property under test is "nothing beyond the platform baseline was added", not
    # "the mapping is byte-identical".
    # PKCS11_CHECK_UNIT_CHILD is the same kind of deliberate baseline: it marks the
    # process as an isolated child so plugin.py arms its own FFI-proof per-test timeout,
    # and it is unrelated to plugin selection.
    expected = {"FOO": "bar", "PKCS11_CHECK_UNIT_CHILD": "1"}
    if sys.platform == "win32":
        expected["PYTHONUTF8"] = "1"
    assert env == expected
    assert "PYTEST_DISABLE_PLUGIN_AUTOLOAD" not in env


def test_nodeid_target_resolves_to_file() -> None:
    nodeid = f"{_TESTCASES / 'test_benchmark.py'}::TestX::test_y"
    addopts = _unit_plugin_addopts(nodeid.split("::", 1)[0])
    assert addopts is not None and "-p benchmark" in addopts
