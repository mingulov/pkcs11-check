"""Tests for the compliance-report count derivers (silent-failure surface).

These functions turn observed coverage / report-log records into the per-function pass/fail
counts the compliance matrix reports. They were untested, so a wrong outcome-vocabulary
mapping or miscount would have shipped silently as wrong compliance numbers.
"""

from __future__ import annotations

import json
from pathlib import Path

from pkcs11_check.compliance_report import (
    _count_value,
    _counts_from_coverage_payload,
    _counts_from_report_jsonl,
    _outcome_from_pytest_report,
    _outcome_from_status,
)


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
