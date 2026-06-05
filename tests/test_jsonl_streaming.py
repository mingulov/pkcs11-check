"""Characterization (golden) tests for the report.jsonl readers.

T4 of docs/findings/docker-pooled-deep-audit-2026-06-04.md converts these readers
from load-all (`read_text().splitlines()`, ~1.4 GB RSS on a 214 MB report) to
line-streaming. These tests pin the EXACT current output so the streaming rewrite
is provably byte-identical — same records, same aggregation, same order.
"""

from __future__ import annotations

import json
from pathlib import Path

from pkcs11_check.core.file_runner import (
    _load_report_log_records,
    extract_coverage_from_jsonl,
    extract_quality_report_records_from_jsonl,
)

# Two CoverageReports (to exercise union/sum), four TestReports (varied outcomes
# + an rv_trace user_property), a SelectionReport, and session bookends.
_FIXTURE_RECORDS: list[dict] = [
    {"$report_type": "SessionStart", "pytest_version": "9.0.2"},
    {
        "$report_type": "CoverageReport",
        "function_coverage": {
            "available": 68,
            "called_names": ["C_A", "C_B"],
            "called_counts": {"C_A": 2, "C_B": 3},
            "bootstrap_counts": {"C_Initialize": 1},
            "uncalled_names": ["C_X", "C_Y"],
        },
        "mechanism_coverage": {
            "available_names": ["M1", "M2"],
            "invoked_names": ["M1"],
            "invoked_counts": {"M1": 5},
            "not_invoked_names": ["M2"],
            "invoked_detail": ["D1"],
            "invoked_detail_counts": {"D1": 1},
        },
    },
    {
        "$report_type": "CoverageReport",
        "function_coverage": {
            "available": 68,
            "called_names": ["C_B", "C_Z"],
            "called_counts": {"C_B": 1, "C_Z": 4},
            "bootstrap_counts": {"C_GetSlotList": 2},
            "uncalled_names": ["C_Y"],
        },
        "mechanism_coverage": {
            "available_names": ["M2", "M3"],
            "invoked_names": ["M2"],
            "invoked_counts": {"M2": 7},
            "invoked_detail": ["D2"],
            "invoked_detail_counts": {"D2": 2},
        },
    },
    {"$report_type": "TestReport", "nodeid": "t.py::test_a", "when": "setup", "outcome": "passed"},
    {
        "$report_type": "TestReport",
        "nodeid": "t.py::test_a",
        "when": "call",
        "outcome": "passed",
        "duration": 0.1,
        "user_properties": [["pkcs11_rv_trace", [{"fn": "C_Encrypt", "rv": 0}]]],
    },
    {
        "$report_type": "TestReport",
        "nodeid": "t.py::test_a",
        "when": "teardown",
        "outcome": "passed",
    },
    {"$report_type": "TestReport", "nodeid": "t.py::test_b", "when": "call", "outcome": "failed"},
    {"$report_type": "SelectionReport", "deselected": ["t.py::test_c"]},
    {"$report_type": "SessionFinish", "exitstatus": 1},
]


def _write_fixture(tmp_path: Path) -> Path:
    p = tmp_path / "report.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in _FIXTURE_RECORDS))
    return p


def test_load_report_log_records_returns_all_dicts(tmp_path: Path) -> None:
    recs = _load_report_log_records(_write_fixture(tmp_path))
    assert recs == _FIXTURE_RECORDS


def test_load_report_log_records_missing_file_is_empty(tmp_path: Path) -> None:
    assert _load_report_log_records(tmp_path / "nope.jsonl") == []


def test_quality_records_keep_only_test_and_selection_reports(tmp_path: Path) -> None:
    recs = extract_quality_report_records_from_jsonl(_write_fixture(tmp_path))
    types = [r.get("$report_type") for r in recs]
    assert types == ["TestReport", "TestReport", "TestReport", "TestReport", "SelectionReport"]
    # Records are projected to the fields build_quality_audit reads: the heavy
    # unused fields (rv-trace user_properties, timings) are dropped, the used
    # ones preserved.
    assert all("user_properties" not in r for r in recs)
    assert all("duration" not in r for r in recs)
    call_rec = next(r for r in recs if r.get("when") == "call" and r.get("outcome") == "passed")
    assert call_rec == {
        "$report_type": "TestReport",
        "nodeid": "t.py::test_a",
        "when": "call",
        "outcome": "passed",
    }


def test_slim_records_yield_identical_quality_audit(tmp_path: Path) -> None:
    """Projecting records must not change build_quality_audit's output."""
    from pkcs11_check.core.quality_audit import build_quality_audit

    full = [r for r in _FIXTURE_RECORDS if r["$report_type"] in {"TestReport", "SelectionReport"}]
    slim = extract_quality_report_records_from_jsonl(_write_fixture(tmp_path))
    results = {"summary": {"passed": 1, "failed": 1}, "units": []}
    assert build_quality_audit(results=results, report_log_records=slim) == build_quality_audit(
        results=results, report_log_records=full
    )


def test_coverage_merges_two_reports_exactly(tmp_path: Path) -> None:
    cov = extract_coverage_from_jsonl(_write_fixture(tmp_path))
    assert cov == {
        "function_coverage": {
            "available": 68,
            "called": 3,
            "called_names": ["C_A", "C_B", "C_Z"],
            "called_counts": {"C_A": 2, "C_B": 4, "C_Z": 4},
            "bootstrap_counts": {"C_Initialize": 1, "C_GetSlotList": 2},
            "uncalled_names": ["C_X", "C_Y"],
        },
        "mechanism_coverage": {
            "available": 3,
            "available_names": ["M1", "M2", "M3"],
            "invoked": 2,
            "invoked_names": ["M1", "M2"],
            "invoked_counts": {"M1": 5, "M2": 7},
            "not_invoked": 1,
            "not_invoked_names": ["M3"],
            "invoked_detail": ["D1", "D2"],
            "invoked_detail_counts": {"D1": 1, "D2": 2},
        },
    }


def test_coverage_none_when_no_coverage_report(tmp_path: Path) -> None:
    p = tmp_path / "r.jsonl"
    p.write_text(json.dumps({"$report_type": "TestReport", "nodeid": "x"}) + "\n")
    assert extract_coverage_from_jsonl(p) is None


def test_coverage_missing_file_is_none(tmp_path: Path) -> None:
    assert extract_coverage_from_jsonl(tmp_path / "nope.jsonl") is None
