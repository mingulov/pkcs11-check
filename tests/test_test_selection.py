"""Tests for production disabled-baseline loading and planning."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pkcs11_check.core.collection import CollectedPytestItem
from pkcs11_check.core.test_selection import (
    DisabledBaseline,
    DisabledSelectionPlan,
    build_disabled_selection_plan,
    collect_disabled_candidates,
    load_disabled_baseline,
    parse_disabled_nodeids,
)


def test_parse_disabled_nodeids_ignores_comments_blanks_and_duplicates() -> None:
    text = """
    # comment
    src/pkcs11_check/testcases/test_encrypt.py::test_roundtrip

    src/pkcs11_check/testcases/test_encrypt.py::test_roundtrip
    src/pkcs11_check/testcases/acvp/aes/test_cfb.py::test_acvp_aes_cfb[AES-enc-tc1021]
    """.strip()

    nodeids = parse_disabled_nodeids(text)

    assert nodeids == [
        "src/pkcs11_check/testcases/test_encrypt.py::test_roundtrip",
        "src/pkcs11_check/testcases/acvp/aes/test_cfb.py::"
        "test_acvp_aes_cfb[AES-enc-tc1021]",
    ]


def test_load_disabled_baseline_returns_none_for_none_path() -> None:
    assert load_disabled_baseline(None) is None


def test_load_disabled_baseline_raises_for_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="disabled"):
        load_disabled_baseline(tmp_path / "missing.txt")


def test_load_disabled_baseline_fingerprint_changes_with_content(tmp_path: Path) -> None:
    path = tmp_path / "disabled.txt"
    path.write_text("a.py::test_one\n")

    first = load_disabled_baseline(path)
    assert isinstance(first, DisabledBaseline)

    path.write_text("a.py::test_one\nb.py::test_two\n")
    second = load_disabled_baseline(path)
    assert isinstance(second, DisabledBaseline)

    assert first.fingerprint != second.fingerprint


def test_build_disabled_selection_plan_drops_disabled_test_units(tmp_path: Path) -> None:
    unit_a = f"{tmp_path / 'test_demo.py'}::test_a"
    unit_b = f"{tmp_path / 'test_demo.py'}::test_b"

    plan = build_disabled_selection_plan(
        units=[unit_a, unit_b],
        disabled_nodeids={unit_b},
        baseline_fingerprint="fp-1",
        collected_items=None,
    )

    assert isinstance(plan, DisabledSelectionPlan)
    assert plan.units == [unit_a]
    assert plan.deselect_by_file == {}
    assert plan.baseline_fingerprint == "fp-1"


def test_build_disabled_selection_plan_drops_fully_disabled_file_units(tmp_path: Path) -> None:
    file_path = tmp_path / "test_demo.py"
    unit = str(file_path)
    items = [
        CollectedPytestItem(nodeid=f"{unit}::test_a", file_path=str(file_path), markers=[]),
        CollectedPytestItem(nodeid=f"{unit}::test_b", file_path=str(file_path), markers=[]),
    ]

    plan = build_disabled_selection_plan(
        units=[unit],
        disabled_nodeids={f"{unit}::test_a", f"{unit}::test_b"},
        baseline_fingerprint="fp-2",
        collected_items=items,
    )

    assert plan.units == []
    assert plan.deselect_by_file == {}


def test_build_disabled_selection_plan_retains_mixed_file_units_with_deselects(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "test_demo.py"
    unit = str(file_path)
    items = [
        CollectedPytestItem(nodeid=f"{unit}::test_a", file_path=str(file_path), markers=[]),
        CollectedPytestItem(nodeid=f"{unit}::test_b", file_path=str(file_path), markers=[]),
    ]

    plan = build_disabled_selection_plan(
        units=[unit],
        disabled_nodeids={f"{unit}::test_b"},
        baseline_fingerprint="fp-3",
        collected_items=items,
    )

    assert plan.units == [unit]
    assert plan.deselect_by_file == {unit: {f"{unit}::test_b"}}


def test_build_disabled_selection_plan_rebuilds_from_saved_units(tmp_path: Path) -> None:
    file_path = tmp_path / "test_demo.py"
    file_unit = str(file_path)
    test_unit = f"{tmp_path / 'test_other.py'}::test_live"
    items = [
        CollectedPytestItem(nodeid=f"{file_unit}::test_a", file_path=str(file_path), markers=[]),
        CollectedPytestItem(nodeid=f"{file_unit}::test_b", file_path=str(file_path), markers=[]),
    ]
    saved_units = [file_unit, test_unit]

    first = build_disabled_selection_plan(
        units=saved_units,
        disabled_nodeids={f"{file_unit}::test_b"},
        baseline_fingerprint="fp-4",
        collected_items=items,
    )
    second = build_disabled_selection_plan(
        units=saved_units,
        disabled_nodeids={f"{file_unit}::test_b"},
        baseline_fingerprint="fp-4",
        collected_items=items,
    )

    assert first == second
    assert first.units == saved_units
    assert first.deselect_by_file == {file_unit: {f"{file_unit}::test_b"}}


def test_collect_disabled_candidates_from_report_jsonl_supports_multiple_outcomes(
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "artifact"
    artifact_dir.mkdir()
    report_path = artifact_dir / "report.jsonl"
    report_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_demo.py::test_failed",
                        "when": "call",
                        "outcome": "failed",
                    }
                ),
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_demo.py::test_skipped",
                        "when": "call",
                        "outcome": "skipped",
                    }
                ),
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_demo.py::test_xfailed",
                        "when": "call",
                        "outcome": "skipped",
                        "wasxfail": "known bug",
                    }
                ),
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_demo.py::test_passed",
                        "when": "call",
                        "outcome": "passed",
                    }
                ),
            ]
        )
        + "\n"
    )

    candidates, manual = collect_disabled_candidates(
        [artifact_dir],
        outcomes={"failed", "skipped", "xfailed"},
    )

    assert candidates == [
        "test_demo.py::test_failed",
        "test_demo.py::test_skipped",
        "test_demo.py::test_xfailed",
    ]
    assert manual == []


def test_collect_disabled_candidates_preserves_parametrized_nodeids_sorted(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifact"
    artifact_dir.mkdir()
    (artifact_dir / "report.jsonl").write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_vectors.py::test_case[param-b]",
                        "when": "call",
                        "outcome": "failed",
                    }
                ),
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_vectors.py::test_case[param-a]",
                        "when": "call",
                        "outcome": "failed",
                    }
                ),
            ]
        )
        + "\n"
    )

    candidates, manual = collect_disabled_candidates([artifact_dir], outcomes={"failed"})

    assert candidates == [
        "test_vectors.py::test_case[param-a]",
        "test_vectors.py::test_case[param-b]",
    ]
    assert manual == []


def test_collect_disabled_candidates_recovers_crash_culprit_from_results_json(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifact"
    artifact_dir.mkdir()
    (artifact_dir / "report.jsonl").write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_a.py::test_done",
                        "when": "setup",
                        "outcome": "passed",
                    }
                ),
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_a.py::test_done",
                        "when": "call",
                        "outcome": "passed",
                    }
                ),
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_a.py::test_done",
                        "when": "teardown",
                        "outcome": "passed",
                    }
                ),
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_a.py::test_culprit",
                        "when": "setup",
                        "outcome": "passed",
                    }
                ),
            ]
        )
        + "\n"
    )
    (artifact_dir / "results.json").write_text(
        json.dumps(
            {
                "units": [
                    {
                        "target": "test_a.py",
                        "status": "crashed",
                    }
                ]
            }
        )
    )

    candidates, manual = collect_disabled_candidates([artifact_dir], outcomes={"crashed"})

    assert candidates == ["test_a.py::test_culprit"]
    assert manual == []


def test_collect_disabled_candidates_reports_manual_review_when_culprit_missing(
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "artifact"
    artifact_dir.mkdir()
    (artifact_dir / "report.jsonl").write_text("")
    (artifact_dir / "results.json").write_text(
        json.dumps(
            {
                "units": [
                    {
                        "target": "test_a.py",
                        "status": "timeout",
                    }
                ]
            }
        )
    )

    candidates, manual = collect_disabled_candidates([artifact_dir], outcomes={"timeout"})

    assert candidates == []
    assert len(manual) == 1
    assert "manual review" in manual[0]
