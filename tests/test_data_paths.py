"""Tests for data path resolution logic."""

from __future__ import annotations

import importlib
import zipfile
from pathlib import Path

import pytest

import pkcs11_check.testcases.data as data_mod
from pkcs11_check.cli.fetch_cmd import (
    _download_with_progress,
    _extract_filtered,
    _license_files_from_entry,
    _locate_upstream_license_paths,
)


class TestResolveDataDir:
    def test_env_var_overrides(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        # Use monkeypatch.context() so the env var is *already restored* before
        # the finally-reload runs.  The old pattern (setenv outside + finally
        # reload) left the bogus var visible during the restoring reload, which
        # permanently poisoned WYCHEPROOF_DIR for the rest of the process and
        # silently skipped the A18 HKDF meta-tests (finding-hiding bug).
        try:
            with monkeypatch.context() as m:
                m.setenv("PKCS11_CHECK_DATA_DIR", str(tmp_path / "custom"))
                importlib.reload(data_mod)
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


class TestLicenseFilesFromEntry:
    def test_returns_list_for_string_paths(self) -> None:
        entry: dict[str, object] = {"license_files": ["LICENSE", "ed25519/LICENSE"]}
        assert _license_files_from_entry(entry) == ["LICENSE", "ed25519/LICENSE"]

    def test_returns_empty_when_missing(self) -> None:
        assert _license_files_from_entry({}) == []

    def test_returns_empty_when_not_a_list(self) -> None:
        assert _license_files_from_entry({"license_files": "LICENSE"}) == []


class TestLocateUpstreamLicensePaths:
    def test_resolves_direct_match_under_dest(self, tmp_path: Path) -> None:
        dest = tmp_path / "wycheproof"
        dest.mkdir()
        (dest / "LICENSE").write_text("apache text", encoding="utf-8")

        found = _locate_upstream_license_paths(dest, ["LICENSE"])

        assert found == [dest / "LICENSE"]

    def test_resolves_one_level_down_for_github_archive_layout(self, tmp_path: Path) -> None:
        dest = tmp_path / "wycheproof"
        archive_root = dest / "wycheproof-abcdef1"
        archive_root.mkdir(parents=True)
        (archive_root / "LICENSE").write_text("apache text", encoding="utf-8")

        found = _locate_upstream_license_paths(dest, ["LICENSE"])

        assert found == [archive_root / "LICENSE"]

    def test_resolves_nested_subdir_license_path(self, tmp_path: Path) -> None:
        dest = tmp_path / "cctv"
        archive_root = dest / "CCTV-1234567"
        nested = archive_root / "ed25519"
        nested.mkdir(parents=True)
        (nested / "LICENSE").write_text("bsd text", encoding="utf-8")

        found = _locate_upstream_license_paths(dest, ["ed25519/LICENSE"])

        assert found == [nested / "LICENSE"]

    def test_omits_unresolvable_entries_silently(self, tmp_path: Path) -> None:
        dest = tmp_path / "acvp"
        dest.mkdir()
        # Only one of two declared paths is present on disk.
        archive_root = dest / "ACVP-Server-abc"
        archive_root.mkdir()
        (archive_root / "README.md").write_text("nist text", encoding="utf-8")

        found = _locate_upstream_license_paths(dest, ["README.md", "LICENSE"])

        assert found == [archive_root / "README.md"]

    def test_returns_empty_when_dest_missing(self, tmp_path: Path) -> None:
        assert _locate_upstream_license_paths(tmp_path / "absent", ["LICENSE"]) == []

    def test_preserves_declaration_order(self, tmp_path: Path) -> None:
        dest = tmp_path / "mixed"
        archive_root = dest / "repo-1"
        sub = archive_root / "sub"
        sub.mkdir(parents=True)
        (archive_root / "FIRST").write_text("a", encoding="utf-8")
        (sub / "SECOND").write_text("b", encoding="utf-8")

        found = _locate_upstream_license_paths(dest, ["sub/SECOND", "FIRST"])

        assert found == [sub / "SECOND", archive_root / "FIRST"]


class TestFetchDataSecurity:
    def test_download_rejects_non_https_url(self, tmp_path: Path) -> None:
        dest = tmp_path / "download.zip"

        with pytest.raises(ValueError, match="HTTPS"):
            _download_with_progress("file:///etc/passwd", dest, "bad")

        assert not dest.exists()

    def test_extract_filtered_rejects_path_traversal(self, tmp_path: Path) -> None:
        zip_path = tmp_path / "archive.zip"
        outside = tmp_path / "escape.txt"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("repo-main/ok.txt", "ok")
            zf.writestr("repo-main/../escape.txt", "bad")

        with pytest.raises(ValueError, match="unsafe archive member"):
            _extract_filtered(zip_path, tmp_path / "dest", None)

        assert not outside.exists()


class TestDisabledAutoDiscovery:
    def test_auto_discovers_from_data_dir(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        baseline_file = tmp_path / "disabled-tests.txt"
        baseline_file.write_text(
            "# test baseline\nsrc/pkcs11_check/testcases/test_foo.py::TestFoo::test_bar\n",
            encoding="utf-8",
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
