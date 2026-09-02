"""The shared report-log JSONL reader (core.report_log) that the run/report/merge layers use."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.core._crash_classify import _analyze_report_jsonl
from pkcs11_check.core._report_records import _build_detail_from_report_records
from pkcs11_check.core.report_log import (
    SessionCompletionTracker,
    iter_report_log_records,
    map_report_outcome,
    user_property,
    user_property_names,
)


def test_session_completion_tracker_accepts_concatenated_complete_sessions() -> None:
    tracker = SessionCompletionTracker()
    for record in (
        {"$report_type": "SessionStart"},
        {"$report_type": "SessionFinish", "exitstatus": 1},
        {"$report_type": "SessionStart"},
        {"$report_type": "SessionFinish", "exitstatus": 0},
    ):
        tracker.observe(record)

    assert tracker.complete is True
    assert tracker.single_exitstatus is None


@pytest.mark.parametrize(
    "records",
    [
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "SessionFinish", "exitstatus": 0},
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "SessionFinish", "exitstatus": "0"},
        ],
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "SessionStart"},
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
        [{"$report_type": "SessionFinish", "exitstatus": 0}],
    ],
)
def test_session_completion_tracker_rejects_malformed_or_duplicate_sessions(
    records: list[dict[str, object]],
) -> None:
    tracker = SessionCompletionTracker()
    for record in records:
        tracker.observe(record)

    assert tracker.complete is False


@pytest.mark.parametrize("report_type", ["TestReport", "CollectReport"])
def test_session_completion_tracker_rejects_test_records_outside_session(
    report_type: str,
) -> None:
    tracker = SessionCompletionTracker()
    tracker.observe({"$report_type": report_type})

    assert tracker.complete is False


def test_session_completion_tracker_rejects_test_records_after_finish() -> None:
    tracker = SessionCompletionTracker()
    tracker.observe({"$report_type": "SessionStart"})
    tracker.observe({"$report_type": "SessionFinish", "exitstatus": 0})
    tracker.observe({"$report_type": "TestReport"})

    assert tracker.complete is False


def test_session_completion_tracker_accepts_root_collect_report() -> None:
    tracker = SessionCompletionTracker()
    for record in (
        {"$report_type": "SessionStart"},
        {"$report_type": "CollectReport", "nodeid": "", "outcome": "passed"},
        {"$report_type": "SessionFinish", "exitstatus": 0},
    ):
        tracker.observe(record)

    assert tracker.complete is True
    assert tracker.single_exitstatus == 0


def test_iter_yields_only_dict_records_skipping_blank_and_garbage(tmp_path: Path) -> None:
    p = tmp_path / "report.jsonl"
    p.write_text(
        '{"a": 1}\n'
        "\n"  # blank line skipped
        "   \n"  # whitespace-only skipped
        "not json\n"  # undecodable skipped
        "[1, 2, 3]\n"  # non-dict JSON skipped
        '  {"b": 2}  \n',  # surrounding whitespace stripped
        encoding="utf-8",
    )
    records = list(iter_report_log_records(p))
    assert records == [{"a": 1}, {"b": 2}]


def test_iter_can_signal_malformed_nonblank_records(tmp_path: Path) -> None:
    p = tmp_path / "report.jsonl"
    p.write_text('{"a": 1}\nnot json\n[1, 2, 3]\n', encoding="utf-8")
    invalid = 0

    def mark_invalid() -> None:
        nonlocal invalid
        invalid += 1

    records = list(iter_report_log_records(p, on_invalid=mark_invalid))

    assert records == [{"a": 1}]
    assert invalid == 2


def test_file_run_analysis_rejects_malformed_record_between_bookends(tmp_path: Path) -> None:
    p = tmp_path / "report.jsonl"
    p.write_text(
        '{"$report_type":"SessionStart"}\n'
        '{"$report_type":"TestReport","nodeid":"a.py::test_a",'
        '"when":"call","outcome":"passed"}\n'
        '{"truncated":\n'
        '{"$report_type":"SessionFinish","exitstatus":0}\n',
        encoding="utf-8",
    )

    _detail, _culprit, _completed, exitstatus = _analyze_report_jsonl(p)

    assert exitstatus is None


@pytest.mark.parametrize(
    "bad_record",
    [
        {},
        {"$report_type": 7},
        {"$report_type": "TestReport"},
        {
            "$report_type": "TestReport",
            "nodeid": "a.py::test_a",
            "when": "unknown",
            "outcome": "passed",
        },
        {"$report_type": "CollectReport", "nodeid": "a.py", "outcome": "unknown"},
    ],
)
def test_file_run_analysis_rejects_structurally_invalid_record_between_bookends(
    tmp_path: Path, bad_record: dict[str, object]
) -> None:
    p = tmp_path / "report.jsonl"
    p.write_text(
        "\n".join(
            json.dumps(record)
            for record in (
                {"$report_type": "SessionStart"},
                bad_record,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            )
        )
        + "\n",
        encoding="utf-8",
    )

    _detail, _culprit, _completed, exitstatus = _analyze_report_jsonl(p)

    assert exitstatus is None


def test_iter_is_silent_on_missing_file(tmp_path: Path) -> None:
    assert list(iter_report_log_records(tmp_path / "nope.jsonl")) == []


def test_map_report_outcome_covers_xfail_and_xpass() -> None:
    assert map_report_outcome("passed", None) == "passed"
    assert map_report_outcome("failed", None) == "failed"
    assert map_report_outcome("skipped", None) == "skipped"
    assert map_report_outcome("passed", "known bug") == "xpassed"
    assert map_report_outcome("skipped", "known bug") == "xfailed"
    # a strict-xfail failure stays failed even with wasxfail set
    assert map_report_outcome("failed", "known bug") == "failed"


def test_direct_caught_seh_record_counts_as_crashed() -> None:
    record: dict[str, Any] = {
        "$report_type": "TestReport",
        "when": "call",
        "nodeid": "testcases/test_ffi.py::test_null_pointer",
        "outcome": "failed",
        "user_properties": [
            [
                "pkcs11_classification",
                [
                    {
                        "reason": "crash",
                        "outcome": "fail",
                        "detail": {
                            "windows_status": 0xC0000005,
                            "signal": "EXCEPTION_ACCESS_VIOLATION",
                        },
                    }
                ],
            ]
        ],
    }

    detail = _build_detail_from_report_records([record])

    assert detail is not None
    assert detail["counts"]["crashed"] == 1
    assert detail["counts"]["failed"] == 0
    assert detail["tests"][0]["outcome"] == "crashed"


def test_nested_crash_classification_remains_failed() -> None:
    record: dict[str, Any] = {
        "$report_type": "TestReport",
        "when": "call",
        "nodeid": "testcases/test_probe.py::test_child",
        "outcome": "failed",
        "user_properties": [
            [
                "pkcs11_classification",
                [
                    {
                        "reason": "crash",
                        "outcome": "fail",
                        "detail": {
                            "termination": {
                                "kind": "exception",
                                "windows_status": 0xC0000005,
                            }
                        },
                    }
                ],
            ]
        ],
    }

    detail = _build_detail_from_report_records([record])

    assert detail is not None
    assert detail["counts"]["failed"] == 1
    assert detail["counts"]["crashed"] == 0
    assert detail["tests"][0]["outcome"] == "failed"


@pytest.mark.parametrize("when", ["setup", "teardown"])
def test_fixture_record_with_direct_seh_metadata_counts_as_crashed(when: str) -> None:
    record: dict[str, Any] = {
        "$report_type": "TestReport",
        "when": when,
        "nodeid": "testcases/test_ffi.py::test_null_pointer",
        "outcome": "failed",
        "user_properties": [
            [
                "pkcs11_classification",
                [
                    {
                        "reason": "crash",
                        "detail": {"windows_status": 0xC0000005},
                    }
                ],
            ]
        ],
    }

    from pkcs11_check.core.report_log import map_report_record_outcome

    assert map_report_record_outcome(record) == "crashed"


@pytest.mark.parametrize("when", ["setup", "teardown"])
def test_fixture_direct_seh_is_aggregated_as_one_crash(when: str) -> None:
    records: list[dict[str, Any]] = []
    if when == "teardown":
        records.append(
            {
                "$report_type": "TestReport",
                "when": "call",
                "nodeid": "testcases/test_ffi.py::test_null_pointer",
                "outcome": "passed",
            }
        )
    records.append(
        {
            "$report_type": "TestReport",
            "when": when,
            "nodeid": "testcases/test_ffi.py::test_null_pointer",
            "outcome": "failed",
            "longrepr": "OSError: exception: access violation reading 0x0",
            "user_properties": [
                [
                    "pkcs11_classification",
                    [{"reason": "crash", "detail": {"windows_status": 0xC0000005}}],
                ]
            ],
        }
    )

    detail = _build_detail_from_report_records(records)

    assert detail is not None
    assert detail["counts"]["crashed"] == 1
    assert detail["counts"]["passed"] == 0
    assert detail["counts"]["failed"] == 0
    assert detail["counts"]["error"] == 0
    assert detail["tests"][0]["outcome"] == "crashed"


def test_teardown_crash_preserves_call_failure_evidence_without_double_counting() -> None:
    records = [
        {
            "$report_type": "TestReport",
            "when": "call",
            "nodeid": "testcases/test_policy.py::test_invalid",
            "outcome": "failed",
            "longrepr": "invalid input was accepted",
            "user_properties": [
                [
                    "pkcs11_classification",
                    [{"reason": "accepted_invalid", "outcome": "fail"}],
                ]
            ],
        },
        {
            "$report_type": "TestReport",
            "when": "teardown",
            "nodeid": "testcases/test_policy.py::test_invalid",
            "outcome": "failed",
            "longrepr": "OSError: exception: access violation reading 0x0",
            "user_properties": [
                [
                    "pkcs11_classification",
                    [{"reason": "crash", "detail": {"windows_status": 0xC0000005}}],
                ]
            ],
        },
    ]

    detail = _build_detail_from_report_records(records)

    assert detail is not None
    assert detail["counts"]["crashed"] == 1
    assert detail["counts"]["failed"] == 0
    assert [test["outcome"] for test in detail["tests"]] == ["failed", "crashed"]
    assert detail["tests"][0]["longrepr"] == "invalid input was accepted"


@pytest.mark.parametrize(
    ("finalize", "expected_outcome"),
    [
        ({"outcome": "error", "rv": 5, "rv_name": "CKR_GENERAL_ERROR"}, "error"),
        ({"outcome": "error", "error": "OSError: provider cleanup failed"}, "error"),
        (
            {
                "outcome": "crashed",
                "error": "OSError: exception: access violation reading 0x0",
                "windows_status": 0xC0000005,
                "signal": "EXCEPTION_ACCESS_VIOLATION",
            },
            "crashed",
        ),
        ({"outcome": "timeout", "error": "C_Finalize exceeded teardown budget"}, "timeout"),
    ],
    ids=["ckr", "exception", "access-violation", "timeout"],
)
def test_teardown_finalize_finding_is_additive_once(
    finalize: dict[str, object], expected_outcome: str
) -> None:
    records = [
        {
            "$report_type": "TestReport",
            "when": "call",
            "nodeid": "testcases/test_demo.py::test_ok",
            "outcome": "passed",
        },
        {"$report_type": "TeardownFinalize", **finalize},
    ]

    detail = _build_detail_from_report_records(records)

    assert detail is not None
    assert detail["counts"]["passed"] == 1
    assert detail["counts"][expected_outcome] == 1
    assert sum(detail["counts"].values()) == 2
    assert detail["tests"] == [
        {
            "nodeid": "C_Finalize::teardown",
            "outcome": expected_outcome,
            "duration": 0.0,
            "longrepr": finalize.get("error")
            or "C_Finalize returned CKR_GENERAL_ERROR (0x00000005)",
        }
    ]


def test_clean_teardown_finalize_does_not_add_an_outcome() -> None:
    detail = _build_detail_from_report_records(
        [
            {
                "$report_type": "TestReport",
                "when": "call",
                "nodeid": "testcases/test_demo.py::test_ok",
                "outcome": "passed",
            },
            {"$report_type": "TeardownFinalize", "outcome": "ok", "rv": 0},
        ]
    )

    assert detail is not None
    assert detail["counts"]["passed"] == 1
    assert sum(detail["counts"].values()) == 1
    assert detail["tests"] == []


def test_user_property_returns_first_matching_value() -> None:
    record = {"user_properties": [["k1", "v1"], ["k2", {"nested": True}], ["k1", "v-dup"]]}
    assert user_property(record, "k2") == {"nested": True}
    assert user_property(record, "k1") == "v1"  # first match
    assert user_property(record, "absent") is None
    assert user_property({}, "k1") is None  # no user_properties key


def test_user_property_names_returns_all_property_names() -> None:
    record = {"user_properties": [["k1", "v1"], ["k2", "v2"], []]}  # empty pair ignored
    assert user_property_names(record) == {"k1", "k2"}
    assert user_property_names({}) == set()
