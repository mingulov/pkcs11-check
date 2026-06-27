"""Tests that the output disclaimer is written to provider and index files."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pkcs11_check.report.__main__ import _DISCLAIMER, _write_index, _write_provider


def _minimal_group(**overrides: Any) -> dict[str, Any]:
    g: dict[str, Any] = {
        "test_file": "tests/test_x.py",
        "reason": "not_operational",
        "outcome": "xfail",
        "severity": "INFO",
        "count": 1,
        "mechanism": "CKM_AES_CBC",
        "kind": None,
        "label": "test",
        "operation": "encrypt",
        "expected": None,
        "actual": None,
        "issues": [],
        "detail": None,
    }
    g.update(overrides)
    return g


def test_disclaimer_in_provider_file(tmp_path: Path) -> None:
    """_write_provider must prepend _DISCLAIMER to the written .md file."""
    groups = [_minimal_group()]
    _write_provider("testprovider", groups, tmp_path)
    content = (tmp_path / "testprovider.md").read_text(encoding="utf-8")
    assert _DISCLAIMER in content
    assert content.startswith(_DISCLAIMER)


def test_disclaimer_in_index_file(tmp_path: Path) -> None:
    """_write_index must prepend _DISCLAIMER to _index.md."""
    groups = [_minimal_group()]
    provider_groups = {"alpha": groups, "beta": groups}
    correlation: dict[str, Any] = {"universal_themes": [], "outliers": []}
    _write_index(provider_groups, correlation, tmp_path)
    content = (tmp_path / "_index.md").read_text(encoding="utf-8")
    assert _DISCLAIMER in content
    assert content.startswith(_DISCLAIMER)


def test_disclaimer_not_empty() -> None:
    """Sanity-check that the disclaimer constant is non-empty and ASCII."""
    assert _DISCLAIMER
    _DISCLAIMER.encode("ascii")  # must not raise
