"""Rootdir-independent scheduling regressions for isolated pytest units."""

from __future__ import annotations

from pathlib import Path

import pytest
from rich.console import Console

from pkcs11_check.core import _escalation as escalation_mod
from pkcs11_check.core import _unit_discovery as discovery_mod
from pkcs11_check.core._run_units import FileRunState
from pkcs11_check.core.collection import CollectedPytestItem


def test_explicit_test_discovery_anchors_collected_item_to_file_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "test_demo.py"
    target.write_text("def test_case(): pass\n", encoding="utf-8")
    raw_nodeid = "app/src/test_demo.py::test_case"
    seen_env: dict[str, str] = {}

    def fake_collect(*args, **kwargs):
        seen_env.update(kwargs["env"])
        return [CollectedPytestItem(nodeid=raw_nodeid, file_path=str(target), markers=[])]

    monkeypatch.setattr(
        discovery_mod,
        "collect_pytest_item_metadata",
        fake_collect,
    )
    monkeypatch.setattr(
        discovery_mod,
        "collect_pytest_nodeids",
        lambda *args, **kwargs: pytest.fail("raw nodeid fallback must not schedule explicit tests"),
    )

    assert discovery_mod.discover_pytest_units(
        [str(target)],
        tmp_path,
        granularity="test",
        pytest_args=[],
    ) == [f"{target.resolve()}::test_case"]
    assert seen_env["PKCS11_CHECK_NO_COLLECTION_CACHE"] == "1"


@pytest.mark.parametrize(
    "raw_nodeids",
    [
        [
            "app/src/test_demo.py::test_disabled",
            "app/src/test_demo.py::test_excluded",
            "app/src/test_demo.py::test_enabled",
        ],
        [
            r"app\src\test_demo.py::test_disabled",
            r"app\src\test_demo.py::test_excluded",
            r"app\src\test_demo.py::test_enabled",
        ],
    ],
    ids=["posix-rootdir", "windows-separators"],
)
def test_escalation_matches_raw_selection_before_anchoring(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    raw_nodeids: list[str],
) -> None:
    target = tmp_path / "test_demo.py"
    target.write_text("def test_enabled(): pass\n", encoding="utf-8")
    items = [
        CollectedPytestItem(nodeid=nodeid, file_path=str(target), markers=[])
        for nodeid in raw_nodeids
    ]
    seen_env: dict[str, str] = {}

    def fake_collect(*args, **kwargs):
        seen_env.update(kwargs["env"])
        return items

    monkeypatch.setattr(
        escalation_mod,
        "collect_pytest_item_metadata",
        fake_collect,
    )

    units = [str(target)]
    state = FileRunState(units=units.copy(), fingerprint="", results=[])
    additions = escalation_mod._escalate_current_file(
        unit=str(target),
        units=units,
        index=0,
        state=state,
        pytest_args=[],
        env={},
        console=Console(),
        disabled_nodeids={raw_nodeids[0].replace("\\", "/")},
        exclude_nodeids={raw_nodeids[1].replace("\\", "/")},
    )

    assert additions == [f"{target.resolve()}::test_enabled"]
    assert units == [str(target), f"{target.resolve()}::test_enabled"]
    assert seen_env["PKCS11_CHECK_NO_COLLECTION_CACHE"] == "1"
