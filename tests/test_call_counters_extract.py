"""Tests for extract_call_counters_from_jsonl (fw#73 Task 5).

The extractor aggregates per-test ``pkcs11_call_counters`` user properties and
``CallCountersReport`` session records from a report JSONL stream into one
run-level ``call_counters`` payload, segmented by ``IsolatedUnitReport``
(target, attempt) marker provenance.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pkcs11_check.core._jsonl_extract import extract_call_counters_from_jsonl


def _buckets(
    total: int,
    *,
    bucket: str = "test",
    fn: str = "C_Sign",
    rv: int = 0,
    name: str = "CKR_OK",
) -> dict[str, Any]:
    return {
        "total_calls": total,
        "buckets": {
            bucket: {
                "calls": total,
                "by_fn": {fn: {"calls": total, "by_rv": {str(rv): {"name": name, "count": total}}}},
            }
        },
    }


def _session_record(
    pid: int,
    total: int,
    buckets: dict[str, Any] | None = None,
    *,
    isolation: str = "file",
    probes_lost: int = 0,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "$report_type": "CallCountersReport",
        "pid": pid,
        "isolation": isolation,
        "probes_lost": probes_lost,
    }
    record.update(_buckets(total) if buckets is None else buckets)
    return record


def _test_entry(pid: int, total: int, buckets: dict[str, Any] | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {"pid": pid}
    entry.update(_buckets(total) if buckets is None else buckets)
    return entry


def _test_report(
    nodeid: str,
    when: str,
    entry: dict[str, Any] | None,
    *,
    outcome: str = "passed",
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "$report_type": "TestReport",
        "nodeid": nodeid,
        "when": when,
        "outcome": outcome,
        "duration": 0.1,
        "user_properties": [],
    }
    if entry is not None:
        report["user_properties"] = [["pkcs11_call_counters", entry]]
    return report


def _marker(target: str, attempt: int) -> dict[str, Any]:
    return {"$report_type": "IsolatedUnitReport", "target": target, "attempt": attempt}


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> Path:
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    return path


def test_extract_prefers_session_record_over_test_deltas(tmp_path: Path) -> None:
    # session record total 10 (pid 100); test deltas total 6 (pid 100)
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            {"$report_type": "SessionStart"},
            _test_report("a.py::t1", "teardown", _test_entry(100, 4)),
            _test_report("a.py::t2", "teardown", _test_entry(100, 2)),
            _session_record(100, 10),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["total_calls"] == 10
    assert payload["complete"] is True


def test_extract_crash_fallback_sums_deltas_and_marks_incomplete(tmp_path: Path) -> None:
    # No session record (crashed before sessionfinish): deltas are the evidence.
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            {"$report_type": "SessionStart"},
            _test_report("a.py::t1", "teardown", _test_entry(100, 4)),
            _test_report("a.py::t2", "teardown", _test_entry(100, 2)),
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["total_calls"] == 6
    assert payload["complete"] is False
    assert payload["by_process"] == [
        {"pid": 100, "isolation": "unknown", "total_calls": 6, "complete": False}
    ]


def test_extract_pid_reconciliation_counts_session_and_foreign_deltas(tmp_path: Path) -> None:
    # pid 200 has a session record (its deltas are skipped); pid 300 (timed-out
    # child) has deltas only and is folded in as fallback.
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            {"$report_type": "SessionStart"},
            _test_report("a.py::t1", "teardown", _test_entry(200, 6)),
            _test_report("a.py::t2", "teardown", _test_entry(300, 5)),
            _session_record(200, 10),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["total_calls"] == 15
    assert payload["complete"] is False
    by_pid = {entry["pid"]: entry for entry in payload["by_process"]}
    assert by_pid[200]["total_calls"] == 10
    assert by_pid[200]["complete"] is True
    assert by_pid[300]["total_calls"] == 5
    assert by_pid[300]["complete"] is False


def test_extract_retries_counted_twice(tmp_path: Path) -> None:
    # Two session records in one group (attempt retried): both are real calls.
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            _marker("a.py", 0),
            _session_record(100, 10),
            _session_record(101, 7),
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["total_calls"] == 17
    assert payload["complete"] is True


def test_extract_probes_lost_marks_incomplete(tmp_path: Path) -> None:
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            {"$report_type": "SessionStart"},
            _session_record(100, 10, probes_lost=1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["total_calls"] == 10
    assert payload["probes_lost"] == 1
    assert payload["complete"] is False


def test_extract_ignores_garbage_without_raising(tmp_path: Path) -> None:
    jsonl = tmp_path / "report.jsonl"
    lines = [
        "not json at all",
        json.dumps([1, 2, 3]),
        json.dumps({"$report_type": "CallCountersReport", "pid": "x", "total_calls": "y"}),
        json.dumps(_test_report("a.py::t1", "teardown", None)),
        json.dumps(
            {
                "$report_type": "TestReport",
                "nodeid": "a.py::t2",
                "when": "teardown",
                "outcome": "passed",
                "user_properties": [["pkcs11_call_counters", [1, 2]]],
            }
        ),
        json.dumps(_session_record(100, 10)),
    ]
    jsonl.write_text("\n".join(lines) + "\n", encoding="utf-8")
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["total_calls"] == 10
    assert payload["complete"] is True


def test_extract_empty_and_old_jsonl_return_none(tmp_path: Path) -> None:
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    assert extract_call_counters_from_jsonl(empty) is None
    old = _write_jsonl(
        tmp_path / "old.jsonl",
        [
            {"$report_type": "SessionStart"},
            _test_report("a.py::t1", "call", None),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    assert extract_call_counters_from_jsonl(old) is None
    assert extract_call_counters_from_jsonl(tmp_path / "missing.jsonl") is None


def test_extract_segments_by_marker_target_attempt(tmp_path: Path) -> None:
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            _marker("a.py", 0),
            _test_report("a.py::t1", "teardown", _test_entry(100, 4)),
            _session_record(100, 10),
            _marker("b.py", 1),
            _test_report("b.py::t1", "teardown", _test_entry(200, 3)),
            _session_record(200, 8),
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    # Each group's session record wins over its own deltas; groups sum.
    assert payload["total_calls"] == 18
    assert payload["complete"] is True


def test_extract_session_start_resets_marker_provenance(tmp_path: Path) -> None:
    # A pid-100 delta before the boundary belongs to group (a.py, 0) where a
    # session record exists; the same pid's delta after SessionStart is
    # unattributed (no session there) and falls back.
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            _marker("a.py", 0),
            _test_report("a.py::t1", "teardown", _test_entry(100, 4)),
            _session_record(100, 10),
            {"$report_type": "SessionStart"},
            _test_report("b.py::t1", "teardown", _test_entry(100, 5)),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["total_calls"] == 15
    assert payload["complete"] is False


def test_extract_malformed_marker_resets_to_unattributed(tmp_path: Path) -> None:
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            _marker("a.py", 0),
            {"$report_type": "IsolatedUnitReport", "target": "b.py"},
            _test_report("b.py::t1", "teardown", _test_entry(100, 5)),
            _session_record(100, 10),
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    # Malformed marker cannot be trusted: both records land unattributed, where
    # the session record still wins over the same-pid delta.
    assert payload["total_calls"] == 10
    assert payload["complete"] is True


def test_extract_is_phase_agnostic(tmp_path: Path) -> None:
    # Production rides teardown reports only, but the extractor must not assume
    # placement: a call-phase property folds the same way.
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            {"$report_type": "SessionStart"},
            _test_report("a.py::t1", "call", _test_entry(100, 6)),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["total_calls"] == 6
    assert payload["complete"] is False


def test_extract_by_process_assembly(tmp_path: Path) -> None:
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            _marker("b.py", 0),
            _session_record(300, 5, isolation="test", probes_lost=0),
            _marker("a.py", 0),
            _session_record(100, 10, isolation="file", probes_lost=0),
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["by_process"] == [
        {"pid": 100, "isolation": "file", "total_calls": 10, "complete": True},
        {"pid": 300, "isolation": "test", "total_calls": 5, "complete": True},
    ]
    assert payload["probes_lost"] == 0


def test_extract_zero_call_session_record_is_data(tmp_path: Path) -> None:
    # Presence of a well-shaped record is data even at zero calls; only the
    # total absence of counters records yields None (old artifacts stay clean).
    jsonl = _write_jsonl(tmp_path / "report.jsonl", [_session_record(100, 0)])
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["total_calls"] == 0
    assert payload["complete"] is True


def test_extract_rejects_bool_and_negative_scalars(tmp_path: Path) -> None:
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            _session_record(True, 10),  # bool pid (bool is an int: must be rejected)
            {
                "$report_type": "CallCountersReport",
                "pid": 100,
                "total_calls": -1,
                "buckets": {},
                "probes_lost": 0,
            },
            _test_report("a.py::t1", "teardown", {"pid": 100, "total_calls": True, "buckets": {}}),
            _session_record(100, 10),
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["total_calls"] == 10
    assert payload["complete"] is True


def test_extract_entry_without_pid_is_ignored(tmp_path: Path) -> None:
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            _test_report("a.py::t1", "teardown", {"total_calls": 6, "buckets": {}}),
        ],
    )
    assert extract_call_counters_from_jsonl(jsonl) is None


def test_extract_session_without_probes_lost_ignored_isolation_defaults(tmp_path: Path) -> None:
    missing_lost = _write_jsonl(
        tmp_path / "missing.jsonl",
        [
            {
                "$report_type": "CallCountersReport",
                "pid": 100,
                "isolation": "file",
                "total_calls": 10,
                "buckets": {},
            },
        ],
    )
    # probes_lost is load-bearing for `complete`: without it the record is garbage.
    assert extract_call_counters_from_jsonl(missing_lost) is None
    missing_isolation = _write_jsonl(
        tmp_path / "noiso.jsonl",
        [
            {
                "$report_type": "CallCountersReport",
                "pid": 100,
                "probes_lost": 0,
                "total_calls": 10,
                "buckets": {},
            },
        ],
    )
    payload = extract_call_counters_from_jsonl(missing_isolation)
    assert payload is not None
    assert payload["total_calls"] == 10
    assert payload["by_process"] == [
        {"pid": 100, "isolation": "unknown", "total_calls": 10, "complete": True}
    ]


def test_extract_malformed_buckets_skipped_without_raise(tmp_path: Path) -> None:
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            {
                "$report_type": "CallCountersReport",
                "pid": 100,
                "isolation": "file",
                "probes_lost": 0,
                "total_calls": 10,
                # by_rv leaf missing "count": merge_serialized would KeyError.
                "buckets": {
                    "test": {
                        "calls": 10,
                        "by_fn": {"C_Sign": {"calls": 10, "by_rv": {"0": {"name": "CKR_OK"}}}},
                    }
                },
            },
            _session_record(200, 7),
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["total_calls"] == 7
    assert [entry["pid"] for entry in payload["by_process"]] == [200]


def test_extract_buckets_merged_across_records(tmp_path: Path) -> None:
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            _session_record(100, 10, _buckets(10, bucket="test", fn="C_Sign")),
            _session_record(200, 5, _buckets(5, bucket="setup_teardown", fn="C_Login")),
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["total_calls"] == 15
    by_bucket = payload["by_bucket"]
    assert by_bucket["total_calls"] == 15
    assert by_bucket["buckets"]["test"]["calls"] == 10
    assert by_bucket["buckets"]["setup_teardown"]["by_fn"]["C_Login"]["calls"] == 5
    assert by_bucket["buckets"]["test"]["by_fn"]["C_Sign"]["by_rv"]["0"]["count"] == 10
