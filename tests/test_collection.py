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

    # Assert the node-id IDENTIFIES this file and test, not its exact relative spelling.
    # The spelling depends on pytest's rootdir, which is the common ancestor of the CWD and
    # the args -- so it is "test_demo.py::test_case" here but an absolute path when the file
    # is on a different drive from the CWD (Windows CI: workspace D:, %TEMP% C:), where
    # pytest emits no path at all and item_nodeid substitutes the absolute one. File
    # identity is the contract; the relative form was an accident of where pytest was run.
    assert len(items) == 1
    assert items[0].nodeid.endswith(f"{target.name}::test_case")
    assert items[0].file_path == str(target.resolve())
    assert set(items[0].markers) >= {"subprocess_per_test", "smoke"}
