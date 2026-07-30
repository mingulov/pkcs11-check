"""Tests for pytest collection metadata helpers."""

from __future__ import annotations

from pathlib import Path

from pkcs11_check.core.collection import (
    CollectedPytestItem,
    collect_pytest_item_metadata,
    load_collection_manifest,
    save_collection_manifest,
)


def test_collection_manifest_round_trip(tmp_path: Path) -> None:
    manifest_path = tmp_path / "collection.json"
    items = [
        CollectedPytestItem(
            nodeid="tests/test_demo.py::test_case",
            file_path=str((tmp_path / "test_demo.py").resolve()),
            markers=["subprocess_per_test", "smoke"],
        )
    ]

    save_collection_manifest(manifest_path, items)

    assert load_collection_manifest(manifest_path) == items


def test_collect_pytest_item_metadata_reports_markers(tmp_path: Path) -> None:
    target = tmp_path / "test_demo.py"
    target.write_text(
        "import pytest\n"
        "pytestmark = [pytest.mark.subprocess_per_test, pytest.mark.smoke]\n\n"
        "def test_case():\n"
        "    assert True\n",
        encoding="utf-8",
    )

    items = collect_pytest_item_metadata([str(target)], [])

    assert [item.nodeid for item in items] == [f"{target.name}::test_case"]
    assert items[0].file_path == str(target.resolve())
    assert set(items[0].markers) >= {"subprocess_per_test", "smoke"}
