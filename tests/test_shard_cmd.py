"""Tests for pkcs11-check shard-units default directory (U10)."""

from __future__ import annotations

from pathlib import Path

import pytest

from pkcs11_check.cli.app import app
from tests._plain_cli_runner import PlainCliRunner

runner = PlainCliRunner()


def test_shard_units_default_resolves_inside_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """U10: no --testcases means the shipped testcases, whatever the cwd."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["shard-units", "-n", "2"])
    assert result.exit_code == 0, result.output
    assert "test_" in result.output


def test_shard_units_explicit_testcases_wins(tmp_path: Path) -> None:
    """U10: an explicit --testcases still selects that directory."""
    case_dir = tmp_path / "cases"
    case_dir.mkdir()
    (case_dir / "test_only.py").write_text("x = 1\n", encoding="utf-8")
    result = runner.invoke(app, ["shard-units", "-n", "1", "--testcases", str(case_dir)])
    assert result.exit_code == 0, result.output
    assert "test_only.py" in result.output
