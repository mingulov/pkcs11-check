"""The fetch-data version manifest records what actually landed.

``sources.toml`` pins what to fetch; ``versions.json`` in the data dir records
what is there, so ``fetch-data --status`` can show the fetched short-sha and
flag stale checkouts. No network: record/read are pure local helpers.
"""

from __future__ import annotations

from pathlib import Path

from pkcs11_check.cli.app import app
from pkcs11_check.cli.fetch_cmd import (
    VERSIONS_FILE,
    _load_manifest,
    _read_fetched_versions,
    _record_fetched_version,
)
from tests._plain_cli_runner import PlainCliRunner

runner = PlainCliRunner()

_ENTRY = {
    "repo": "X/Y",
    "commit": "abc123def456",
    "commit_date": "2026-01-01T00:00:00Z",
    "archive_sha256": "dead",
}


def test_record_then_read_roundtrips(tmp_path: Path) -> None:
    _record_fetched_version("demo", _ENTRY, tmp_path)
    back = _read_fetched_versions(tmp_path)
    assert back["demo"]["commit"] == "abc123def456"
    assert back["demo"]["repo"] == "X/Y"
    assert back["demo"]["fetched_at"]  # stamped at record time
    assert (tmp_path / VERSIONS_FILE).is_file()


def test_read_absent_or_corrupt_yields_empty(tmp_path: Path) -> None:
    assert _read_fetched_versions(tmp_path) == {}
    (tmp_path / VERSIONS_FILE).write_text("not json{", encoding="utf-8")
    assert _read_fetched_versions(tmp_path) == {}
    (tmp_path / VERSIONS_FILE).write_text("[1, 2]", encoding="utf-8")
    assert _read_fetched_versions(tmp_path) == {}


def test_status_shows_fetched_and_stale(tmp_path: Path) -> None:
    manifest = _load_manifest()
    name = next(iter(manifest))
    (tmp_path / name).mkdir()
    # Matching pin: fetched short-sha shown, no stale flag.
    _record_fetched_version(name, manifest[name], tmp_path)
    shown = runner.invoke(app, ["fetch-data", "--status", "--data-dir", str(tmp_path)])
    assert shown.exit_code == 0, shown.output
    assert f"@{manifest[name]['commit'][:8]}" in shown.output
    assert "stale" not in shown.output
    # Diverged pin: stale flag names both sides.
    _record_fetched_version(name, {**manifest[name], "commit": "0" * 40}, tmp_path)
    shown = runner.invoke(app, ["fetch-data", "--status", "--data-dir", str(tmp_path)])
    assert shown.exit_code == 0, shown.output
    assert "stale" in shown.output
    assert f"@{manifest[name]['commit'][:8]}" in shown.output
