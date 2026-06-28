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


def test_index_fail_count_excludes_unclassified(tmp_path: Path) -> None:
    """The index fail column must agree with the per-provider header: the
    unclassified backlog (framework debt) is NOT a scored fail and must not inflate
    it. Previously _counts folded unclassified into fail, so the index overstated
    softhsm2 as 160 fails when the header (health.outcome_counts) scored 28."""
    groups = [
        _minimal_group(reason="accepted_invalid", outcome="fail", severity="CRITICAL", count=2),
        _minimal_group(reason="unclassified", outcome="fail", severity="HIGH", count=130),
    ]
    provider_groups = {"alpha": groups}
    correlation: dict[str, Any] = {"universal_themes": [], "outliers": []}
    _write_index(provider_groups, correlation, tmp_path)
    content = (tmp_path / "_index.md").read_text(encoding="utf-8")
    row = next(ln for ln in content.splitlines() if ln.startswith("| [alpha]"))
    # 2 scored fails, NOT 132; the 130 unclassified must surface in its own column
    assert "| 2 |" in row, f"fail count folded in unclassified: {row}"
    assert "130" in row, f"unclassified backlog not surfaced separately: {row}"
