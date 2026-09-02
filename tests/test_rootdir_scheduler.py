"""Rootdir-independent scheduling regressions for isolated pytest units."""

from __future__ import annotations

from pathlib import Path

import pytest
from rich.console import Console

from pkcs11_check.core import _escalation as escalation_mod
from pkcs11_check.core import _report_records as report_records_mod
from pkcs11_check.core import _unit_discovery as discovery_mod
from pkcs11_check.core._run_units import FileRunState
from pkcs11_check.core.collection import CollectedPytestItem


def _report_ownership_fixture() -> tuple[list[str], list[CollectedPytestItem]]:
    dsa_file = "/app/src/pkcs11_check/testcases/test_dsa_complete.py"
    duplicate_a = "/app/src/a/test_duplicate.py"
    duplicate_b = "/app/src/b/test_duplicate.py"
    return (
        [
            "src/pkcs11_check/testcases/test_dsa_complete.py",
            f"{dsa_file}::TestDSA::test_case[SHA3-512]",
            "src/a/test_duplicate.py",
            "src/b/test_duplicate.py",
        ],
        [
            CollectedPytestItem(
                nodeid=(
                    "app/src/pkcs11_check/testcases/test_dsa_complete.py::"
                    "TestDSA::test_case[SHA3-512]"
                ),
                file_path=dsa_file,
                markers=[],
            ),
            CollectedPytestItem(
                nodeid="app/src/a/test_duplicate.py::test_a",
                file_path=duplicate_a,
                markers=[],
            ),
            CollectedPytestItem(
                nodeid="app/src/b/test_duplicate.py::test_b",
                file_path=duplicate_b,
                markers=[],
            ),
        ],
    )


def test_report_ownership_uses_collected_file_identity_without_basename_guessing() -> None:
    candidates, items = _report_ownership_fixture()

    aliases = report_records_mod._build_report_owner_aliases(
        candidates,
        items,
        cwd=Path("/app"),
    )

    raw_dsa = "app/src/pkcs11_check/testcases/test_dsa_complete.py::TestDSA::test_case[SHA3-512]"
    assert aliases.canonical_nodeid(raw_dsa) == (
        "/app/src/pkcs11_check/testcases/test_dsa_complete.py::TestDSA::test_case[SHA3-512]"
    )
    assert aliases.owner_for_nodeid(raw_dsa) == candidates[0]
    assert aliases.file_identity(candidates[0]) == aliases.file_identity(candidates[1])
    assert aliases.file_identity(candidates[2]) != aliases.file_identity(candidates[3])
    assert aliases.owner_for_nodeid("app/src/a/test_duplicate.py::test_a") == candidates[2]
    assert aliases.owner_for_nodeid("app/src/b/test_duplicate.py::test_b") == candidates[3]


def test_report_ownership_rejects_ambiguous_collected_alias() -> None:
    raw_nodeid = "app/src/test_duplicate.py::test_case"
    items = [
        CollectedPytestItem(raw_nodeid, "/app/src/a/test_duplicate.py", []),
        CollectedPytestItem(raw_nodeid, "/app/src/b/test_duplicate.py", []),
    ]

    with pytest.raises(ValueError, match="ambiguous report owner alias"):
        report_records_mod._build_report_owner_aliases(
            [
                "/app/src/a/test_duplicate.py",
                "/app/src/b/test_duplicate.py",
            ],
            items,
            cwd=Path("/app"),
        )


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
