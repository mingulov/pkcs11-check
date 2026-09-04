"""Disabled-baseline matching for canonical isolated test units."""

from __future__ import annotations

from pathlib import Path

import pytest

from pkcs11_check.core.collection import CollectedPytestItem
from pkcs11_check.core.test_selection import build_disabled_selection_plan


@pytest.mark.parametrize(
    ("raw_nodeid", "disabled_nodeid"),
    [
        ("app/src/test_demo.py::test_disabled", "app/src/test_demo.py::test_disabled"),
        (r"app\src\test_demo.py::test_disabled", "app/src/test_demo.py::test_disabled"),
    ],
    ids=["posix-rootdir", "windows-separators"],
)
def test_canonical_test_unit_matches_raw_disabled_nodeid(
    tmp_path: Path,
    raw_nodeid: str,
    disabled_nodeid: str,
) -> None:
    file_path = tmp_path / "test_demo.py"
    unit = f"{file_path}::test_disabled"
    items = [CollectedPytestItem(nodeid=raw_nodeid, file_path=str(file_path), markers=[])]

    plan = build_disabled_selection_plan(
        units=[unit],
        disabled_nodeids={disabled_nodeid},
        baseline_fingerprint="fp-rootdir",
        collected_items=items,
    )

    assert plan.units == []
    assert plan.deselect_by_file == {}


@pytest.mark.parametrize(
    "raw_nodeid",
    [
        "app/src/test_demo.py::test_disabled",
        r"app\src\test_demo.py::test_disabled",
    ],
    ids=["posix-rootdir", "windows-separators"],
)
def test_file_unit_deselects_with_raw_runtime_nodeid(
    tmp_path: Path,
    raw_nodeid: str,
) -> None:
    file_path = tmp_path / "test_demo.py"
    unit = str(file_path)
    raw_enabled = raw_nodeid.replace("test_disabled", "test_enabled")
    items = [
        CollectedPytestItem(nodeid=raw_nodeid, file_path=unit, markers=[]),
        CollectedPytestItem(nodeid=raw_enabled, file_path=unit, markers=[]),
    ]

    plan = build_disabled_selection_plan(
        units=[unit],
        disabled_nodeids={raw_nodeid.replace("\\", "/")},
        baseline_fingerprint="fp-rootdir",
        collected_items=items,
    )

    assert plan.units == [unit]
    assert plan.deselect_by_file == {unit: {raw_nodeid.replace("\\", "/")}}
