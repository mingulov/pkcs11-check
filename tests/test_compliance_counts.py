"""Tests for the compliance-report count derivers (silent-failure surface).

These functions turn observed coverage / report-log records into the per-function pass/fail
counts the compliance matrix reports. They were untested, so a wrong outcome-vocabulary
mapping or miscount would have shipped silently as wrong compliance numbers.
"""

from __future__ import annotations

import json
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from pkcs11_check.compliance_report import (
    _count_value,
    _counts_from_coverage_payload,
    _counts_from_report_jsonl,
    _outcome_from_pytest_report,
    _outcome_from_status,
)
from pkcs11_check.core._report_writers import (
    _build_isolated_json_payload,
    write_isolated_junit_report,
)
from pkcs11_check.core._run_units import FileRunResult, FileRunState
from pkcs11_check.core._unit_details import _effective_unit_status, _status_with_detail_counts


def test_count_value_clamps_and_coerces() -> None:
    assert _count_value(3) == 3
    assert _count_value(-5) == 0  # negative counts are meaningless -> 0
    assert _count_value(True) == 1  # bool is an int subclass but must count as 1
    assert _count_value("nope") == 0
    assert _count_value(None) == 0


def test_outcome_from_status_vocabulary() -> None:
    assert _outcome_from_status("passed") == "passed"
    assert _outcome_from_status("failed") == "failed"
    assert _outcome_from_status("crash") == "crashed"
    assert _outcome_from_status("errored") == "error"
    assert _outcome_from_status("something-unknown") == "error"  # unknown never silently passes


def test_outcome_from_pytest_report_maps_wasxfail() -> None:
    assert _outcome_from_pytest_report("passed", None) == "passed"
    assert _outcome_from_pytest_report("failed", None) == "failed"
    assert _outcome_from_pytest_report("passed", "known bug") == "xpassed"
    assert _outcome_from_pytest_report("skipped", "known bug") == "xfailed"
    assert _outcome_from_pytest_report("skipped", None) == "skipped"


def test_counts_from_coverage_payload_builds_per_function_counts() -> None:
    coverage = {
        "function_coverage": {
            "called_names": ["C_Sign", "C_Verify"],
            "called_counts": {"C_Sign": 4},
        }
    }
    counts = _counts_from_coverage_payload(coverage)
    assert counts is not None
    assert counts["C_Sign"] == {"tests": 4}
    # a name present but with no count is clamped up to 1 (it WAS called)
    assert counts["C_Verify"] == {"tests": 1}


def test_counts_from_coverage_payload_none_when_no_data() -> None:
    assert _counts_from_coverage_payload({}) is None
    assert _counts_from_coverage_payload({"function_coverage": {"called_names": []}}) is None


def _write_jsonl(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")


def test_counts_from_report_jsonl_aggregates_by_function_and_outcome(tmp_path: Path) -> None:
    p = tmp_path / "report.jsonl"
    _write_jsonl(
        p,
        [
            {
                "$report_type": "TestReport",
                "outcome": "passed",
                "wasxfail": None,
                "user_properties": [["pkcs11_rv_trace", [{"fn": "C_Sign"}, {"fn": "C_Verify"}]]],
            },
            {
                "$report_type": "TestReport",
                "outcome": "failed",
                "wasxfail": None,
                "user_properties": [["pkcs11_rv_trace", [{"fn": "C_Sign"}]]],
            },
            {"$report_type": "CollectReport", "outcome": "passed"},  # ignored: not a TestReport
            {
                "$report_type": "TestReport",
                "outcome": "passed",
                "wasxfail": None,
                "user_properties": [["pkcs11_rv_trace", [{"fn": "not_a_ck_fn"}]]],  # ignored: !C_
            },
        ],
    )
    counts = _counts_from_report_jsonl(p)
    assert counts is not None
    assert counts["C_Sign"]["passed"] == 1
    assert counts["C_Sign"]["failed"] == 1
    assert counts["C_Sign"]["tests"] == 2
    assert counts["C_Verify"] == {**counts["C_Verify"], "passed": 1, "tests": 1}
    assert "not_a_ck_fn" not in counts


def test_counts_from_report_jsonl_maps_direct_caught_seh_to_crashed(tmp_path: Path) -> None:
    p = tmp_path / "report.jsonl"
    _write_jsonl(
        p,
        [
            {
                "$report_type": "TestReport",
                "when": "call",
                "outcome": "failed",
                "wasxfail": None,
                "user_properties": [
                    [
                        "pkcs11_classification",
                        [
                            {
                                "reason": "crash",
                                "detail": {
                                    "windows_status": 0xC0000005,
                                    "signal": "EXCEPTION_ACCESS_VIOLATION",
                                },
                            }
                        ],
                    ],
                    ["pkcs11_rv_trace", [{"fn": "C_GetAttributeValue"}]],
                ],
            }
        ],
    )

    counts = _counts_from_report_jsonl(p)

    assert counts is not None
    assert counts["C_GetAttributeValue"]["crashed"] == 1
    assert counts["C_GetAttributeValue"]["failed"] == 0


def test_counts_from_report_jsonl_skips_malformed_lines(tmp_path: Path) -> None:
    p = tmp_path / "report.jsonl"
    p.write_text(
        "this is not json\n"
        + json.dumps(
            {
                "$report_type": "TestReport",
                "outcome": "passed",
                "wasxfail": None,
                "user_properties": [["pkcs11_rv_trace", [{"fn": "C_Digest"}]]],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    counts = _counts_from_report_jsonl(p)
    assert counts is not None
    assert counts["C_Digest"]["tests"] == 1


def test_counts_from_report_jsonl_missing_file_is_none(tmp_path: Path) -> None:
    assert _counts_from_report_jsonl(tmp_path / "does-not-exist.jsonl") is None


@pytest.mark.parametrize(
    ("durable_status", "detail_counts", "expected_status"),
    [
        ("crashed", {"passed": 1}, "crashed"),
        ("crashed", {"failed": 1}, "crashed"),
        ("timeout", {"crashed": 1}, "timeout"),
        ("timeout", {"failed": 1}, "timeout"),
        ("failed", {"passed": 1}, "failed"),
        ("failed", {"error": 1}, "failed"),
    ],
)
def test_status_with_detail_counts_keeps_durable_priority(
    durable_status: str, detail_counts: dict[str, int], expected_status: str
) -> None:
    assert _status_with_detail_counts(durable_status, detail_counts) == expected_status


@pytest.mark.parametrize(
    ("durable_status", "returncode", "detail_counts", "expected_status"),
    [
        ("crashed", -11, {"timeout": 1}, "crashed"),
        ("timeout", 124, {"crashed": 1}, "timeout"),
        ("escalated", -11, {"timeout": 1}, "crashed"),
        ("escalated", 124, {"crashed": 1}, "timeout"),
    ],
    ids=["outer-crash", "outer-timeout", "escalated-crash", "escalated-timeout"],
)
def test_outer_death_status_wins_over_child_detail_counts(
    durable_status: str,
    returncode: int,
    detail_counts: dict[str, int],
    expected_status: str,
) -> None:
    result = FileRunResult("test_report.py", durable_status, returncode, 0.1)

    assert _effective_unit_status([result], detail_counts) == expected_status


@pytest.mark.parametrize(
    ("durable_status", "detail_counts", "expected_status", "expected_counts"),
    [
        ("crashed", {"passed": 1}, "crashed", {"passed": 1, "crashed": 1}),
        ("crashed", {"timeout": 1}, "crashed", {"timeout": 1, "crashed": 1}),
        ("crashed", {"failed": 1}, "crashed", {"failed": 1, "crashed": 1}),
        ("timeout", {"crashed": 1}, "timeout", {"crashed": 1, "timeout": 1}),
        ("timeout", {"failed": 1}, "timeout", {"failed": 1, "timeout": 1}),
        ("failed", {"passed": 1}, "failed", {"passed": 1, "failed": 1}),
        ("failed", {"error": 1}, "failed", {"error": 1}),
    ],
)
def test_isolated_json_payload_counts_durable_status_without_double_counting(
    durable_status: str,
    detail_counts: dict[str, int],
    expected_status: str,
    expected_counts: dict[str, int],
) -> None:
    target = "test_report.py"
    state = FileRunState(
        units=[target],
        fingerprint="test",
        results=[
            FileRunResult(target, durable_status, -11 if durable_status != "failed" else 1, 0.1)
        ],
    )

    payload = _build_isolated_json_payload(
        state,
        per_unit_details={target: {"counts": detail_counts, "tests": []}},
    )

    unit = payload["units"][0]
    counts = unit["counts"]
    assert unit["status"] == expected_status
    for outcome, expected_count in expected_counts.items():
        assert counts[outcome] == expected_count
    assert payload["summary"]["total"] == sum(expected_counts.values())


@pytest.mark.parametrize(
    ("durable_status", "detail_counts", "xml_node", "xml_type"),
    [
        ("crashed", {"passed": 1}, "error", "crashed"),
        ("crashed", {"timeout": 1}, "error", "crashed"),
        ("failed", {"passed": 1}, "failure", "failure"),
    ],
)
def test_isolated_junit_uses_corrected_effective_status(
    tmp_path: Path,
    durable_status: str,
    detail_counts: dict[str, int],
    xml_node: str,
    xml_type: str,
) -> None:
    target = "test_report.py"
    state = FileRunState(
        units=[target],
        fingerprint="test",
        results=[
            FileRunResult(target, durable_status, -11 if durable_status == "crashed" else 1, 0.1)
        ],
    )
    output = tmp_path / "results.xml"

    write_isolated_junit_report(
        output,
        state,
        per_unit_details={target: {"counts": detail_counts, "tests": []}},
    )

    testcase = ET.parse(output).getroot().find("testcase")
    assert testcase is not None
    assert testcase.find(xml_node) is not None
    assert testcase.find(xml_node).attrib["type"] == xml_type
    assert testcase.find("failure" if xml_node == "error" else "error") is None
