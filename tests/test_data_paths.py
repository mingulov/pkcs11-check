"""Tests for data path resolution logic."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

import pkcs11_check.testcases.data as data_mod


class TestResolveDataDir:
    def test_env_var_overrides(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("PKCS11_CHECK_DATA_DIR", str(tmp_path / "custom"))
        # Force re-import to pick up the env var
        importlib.reload(data_mod)
        try:
            assert data_mod.resolve_data_dir() == tmp_path / "custom"
        finally:
            importlib.reload(data_mod)

    def test_xdg_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PKCS11_CHECK_DATA_DIR", raising=False)
        monkeypatch.setattr("pkcs11_check.testcases.data._find_repo_data_dir", lambda: None)
        from pkcs11_check.testcases.data import resolve_data_dir

        result = resolve_data_dir()
        assert str(result).endswith(".local/share/pkcs11-check/data")


class TestSourcesManifest:
    def test_sources_toml_exists_in_package(self) -> None:
        from pkcs11_check.testcases.data import SOURCES_TOML

        assert SOURCES_TOML.exists(), f"sources.toml not found at {SOURCES_TOML}"

    def test_sources_toml_has_expected_keys(self) -> None:
        import tomllib

        from pkcs11_check.testcases.data import SOURCES_TOML

        with open(SOURCES_TOML, "rb") as f:
            sources = tomllib.load(f)
        assert "wycheproof" in sources
        assert "acvp" in sources
        for name, entry in sources.items():
            assert "repo" in entry, f"{name} missing 'repo'"
            assert "commit" in entry, f"{name} missing 'commit'"
            assert "archive_sha256" in entry, f"{name} missing 'archive_sha256'"


class TestDisabledAutoDiscovery:
    def test_auto_discovers_from_data_dir(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        baseline_file = tmp_path / "disabled-tests.txt"
        baseline_file.write_text(
            "# test baseline\nsrc/pkcs11_check/testcases/test_foo.py::TestFoo::test_bar\n"
        )
        monkeypatch.setenv("PKCS11_CHECK_DATA_DIR", str(tmp_path))

        from pkcs11_check.core.test_selection import auto_discover_disabled_baseline

        result = auto_discover_disabled_baseline()
        assert result is not None
        assert result == baseline_file

    def test_no_discovery_when_missing(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("PKCS11_CHECK_DATA_DIR", str(tmp_path))

        from pkcs11_check.core.test_selection import auto_discover_disabled_baseline

        assert auto_discover_disabled_baseline() is None
