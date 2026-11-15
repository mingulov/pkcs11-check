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

import pytest

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
    # I2 fail-closed totals: the record must be internally consistent
    # (total == sum of buckets); only the isolation key is under test here.
    no_isolation_record = _session_record(100, 10)
    del no_isolation_record["isolation"]
    missing_isolation = _write_jsonl(tmp_path / "noiso.jsonl", [no_isolation_record])
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


# --- Codex R1 fix round (C2): executed-but-counterless segments ---


def test_extract_missing_group_crashed_first_test_marks_incomplete(tmp_path: Path) -> None:
    # C2: a unit that crashed during its first test (marker + setup report,
    # then truncated: no counters, no SessionFinish) must still appear as an
    # empty complete:false group -- never silently vanish.
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            {"$report_type": "SessionStart"},
            _marker("a.py", 0),
            _test_report("a.py::t1", "setup", None),
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["complete"] is False
    assert payload["total_calls"] == 0
    assert payload["by_bucket"] == {"total_calls": 0, "buckets": {}}
    assert payload["probes_lost"] == 0
    assert payload["by_process"] == []


def test_extract_finished_without_counters_is_old_artifact(tmp_path: Path) -> None:
    # C2: the same shape WITH a SessionFinish predates the feature (old
    # artifact): no group, None preserved.
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            {"$report_type": "SessionStart"},
            _marker("a.py", 0),
            _test_report("a.py::t1", "setup", None),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    assert extract_call_counters_from_jsonl(jsonl) is None


def test_extract_marker_without_reports_is_static_skip(tmp_path: Path) -> None:
    # C2: a marker with zero TestReports is a static skip, not an execution:
    # no group with or without a finish.
    assert (
        extract_call_counters_from_jsonl(
            _write_jsonl(
                tmp_path / "skip.jsonl",
                [{"$report_type": "SessionStart"}, _marker("a.py", 0)],
            )
        )
        is None
    )
    assert (
        extract_call_counters_from_jsonl(
            _write_jsonl(
                tmp_path / "skip2.jsonl",
                [
                    {"$report_type": "SessionStart"},
                    _marker("a.py", 0),
                    {"$report_type": "SessionFinish", "exitstatus": 0},
                ],
            )
        )
        is None
    )


def test_extract_crashed_unit_alongside_healthy_marks_incomplete(tmp_path: Path) -> None:
    # C2 (codex scenario): a crashed unit next to a healthy one must flip the
    # run to complete:false; the healthy unit's totals still fold exactly.
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            {"$report_type": "SessionStart"},
            _marker("a.py", 0),
            _test_report("a.py::t1", "teardown", _test_entry(100, 4)),
            _session_record(100, 10),
            {"$report_type": "SessionFinish", "exitstatus": 0},
            {"$report_type": "SessionStart"},
            _marker("b.py", 0),
            _test_report("b.py::t1", "setup", None),
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["total_calls"] == 10
    assert payload["complete"] is False
    assert [entry["pid"] for entry in payload["by_process"]] == [100]


# --- Codex R1 fix round (I1): malformed user_properties container ---


@pytest.mark.parametrize("props", [1, 2.5, True], ids=["int", "float", "bool"])
def test_extract_malformed_properties_container_ignored(tmp_path: Path, props: Any) -> None:
    # I1: a non-list user_properties container must not raise (the old code
    # raised TypeError inside _user_property, aborting the whole extraction);
    # valid counters elsewhere still fold.
    report = _test_report("a.py::t1", "teardown", None)
    report["user_properties"] = props
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            {"$report_type": "SessionStart"},
            report,
            _session_record(100, 10),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["total_calls"] == 10
    assert payload["complete"] is True


def test_extract_malformed_properties_counts_as_executed_when_unfinished(
    tmp_path: Path,
) -> None:
    # I1+C2: malformed counters on an unfinished stream are still evidence of
    # execution: an empty complete:false group, never a raise and never None.
    report = _test_report("a.py::t1", "teardown", None)
    report["user_properties"] = 1
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            {"$report_type": "SessionStart"},
            _marker("a.py", 0),
            report,
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["complete"] is False
    assert payload["total_calls"] == 0


# --- Codex R1 fix round (I2): fail-closed validation ---


def _violation_records() -> dict[str, dict[str, Any]]:
    """One whole-record violation per I2 class (each must be skipped)."""
    good_leaf = {"calls": 10, "by_rv": {"0": {"name": "CKR_OK", "count": 10}}}
    hex_buckets = _buckets(10)
    hex_buckets["buckets"]["test"]["by_fn"]["C_Sign"]["by_rv"] = {
        "0x0": {"name": "CKR_OK", "count": 10}
    }
    negative_buckets = _buckets(10)
    negative_buckets["buckets"]["test"]["by_fn"]["C_Sign"]["by_rv"] = {
        "-1": {"name": "WEIRD", "count": 10}
    }
    bucket_mismatch = _buckets(10)
    bucket_mismatch["buckets"]["test"]["calls"] = 99
    rv_exceeds = _buckets(10)
    rv_exceeds["buckets"]["test"]["by_fn"]["C_Sign"]["by_rv"]["0"]["count"] = 12
    # NOTE: _session_record takes its total from the passed buckets dict, so a
    # total/buckets mismatch needs post-build surgery.
    total_mismatch = _session_record(100, 5, _buckets(5))
    total_mismatch["total_calls"] = 10
    return {
        "unknown-bucket": _session_record(
            100, 10, {"total_calls": 10, "buckets": {"nope": {"calls": 10, "by_fn": {}}}}
        ),
        "unknown-bucket-with-fns": _session_record(
            100,
            10,
            {
                "total_calls": 10,
                "buckets": {"nope": {"calls": 10, "by_fn": {"C_Sign": dict(good_leaf)}}},
            },
        ),
        "hex-rv-key": _session_record(100, 10, hex_buckets),
        "negative-rv-key": _session_record(100, 10, negative_buckets),
        "bucket-calls-mismatch": _session_record(100, 10, bucket_mismatch),
        "entry-total-mismatch": total_mismatch,
        "rv-exceeds-calls": _session_record(100, 10, rv_exceeds),
    }


@pytest.mark.parametrize("name", sorted(_violation_records()))
def test_extract_skips_violating_session_record(tmp_path: Path, name: str) -> None:
    # I2: a record violating the serialized contract is skipped whole; the
    # valid record in the same group still folds and the run stays complete.
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [_violation_records()[name], _session_record(200, 7)],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["total_calls"] == 7
    assert payload["complete"] is True
    assert [entry["pid"] for entry in payload["by_process"]] == [200]


def test_extract_skips_violating_test_entry(tmp_path: Path) -> None:
    # I2: per-test entries face the same fail-closed validation as session
    # records (here: an unknown bucket on a fallback-eligible pid).
    entry = _test_entry(300, 5)
    entry["buckets"] = {"nope": {"calls": 5, "by_fn": {}}}
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            _test_report("a.py::t1", "teardown", entry),
            _session_record(200, 7),
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["total_calls"] == 7
    assert payload["complete"] is True
    assert [entry_row["pid"] for entry_row in payload["by_process"]] == [200]


# --- Per-round (run_id) dimension ---

_R1 = "20261115T120000000000Z-p100"
_R2 = "20261115T130000000000Z-p200"


def _round_session(pid: int, total: int, run_id: str) -> dict[str, Any]:
    record = _session_record(pid, total)
    record["run_id"] = run_id
    return record


def _round_entry(pid: int, total: int, run_id: str) -> dict[str, Any]:
    entry = _test_entry(pid, total)
    entry["run_id"] = run_id
    return entry


def test_extract_splits_rounds_and_keeps_global_rollup(tmp_path: Path) -> None:
    # Two CLI invocations (resume): each round keeps its own block while the
    # top level stays the GLOBAL roll-up with round-tagged process rows.
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            {"$report_type": "SessionStart"},
            _marker("a.py", 0),
            _round_session(100, 10, _R1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
            {"$report_type": "SessionStart"},
            _marker("b.py", 0),
            _round_session(200, 5, _R2),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["total_calls"] == 15
    assert payload["complete"] is True
    assert payload["probes_lost"] == 0
    assert payload["by_process"] == [
        {"pid": 100, "isolation": "file", "total_calls": 10, "complete": True, "round": _R1},
        {"pid": 200, "isolation": "file", "total_calls": 5, "complete": True, "round": _R2},
    ]
    assert sorted(payload["by_round"]) == [_R1, _R2]
    round_1 = payload["by_round"][_R1]
    assert round_1["total_calls"] == 10
    assert round_1["complete"] is True
    assert round_1["probes_lost"] == 0
    assert round_1["by_bucket"]["total_calls"] == 10
    assert round_1["by_process"] == [
        {"pid": 100, "isolation": "file", "total_calls": 10, "complete": True}
    ]
    assert payload["by_round"][_R2]["total_calls"] == 5
    assert payload["by_round"][_R2]["by_process"] == [
        {"pid": 200, "isolation": "file", "total_calls": 5, "complete": True}
    ]


def test_extract_single_round_rows_carry_no_round_key(tmp_path: Path) -> None:
    # Single-round output is identical to today on every existing key; only
    # the additive by_round map is new.
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            {"$report_type": "SessionStart"},
            _marker("a.py", 0),
            _round_session(100, 10, _R1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["by_process"] == [
        {"pid": 100, "isolation": "file", "total_calls": 10, "complete": True}
    ]
    assert list(payload["by_round"]) == [_R1]
    assert payload["by_round"][_R1]["total_calls"] == 10


def test_extract_old_records_fold_into_implicit_round(tmp_path: Path) -> None:
    # Backward compat: records without run_id (pre-round artifacts,
    # direct-pytest runs) form one implicit "" round; totals are unchanged.
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            {"$report_type": "SessionStart"},
            _marker("a.py", 0),
            _session_record(100, 10),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["total_calls"] == 10
    assert payload["complete"] is True
    assert payload["by_process"] == [
        {"pid": 100, "isolation": "file", "total_calls": 10, "complete": True}
    ]
    assert list(payload["by_round"]) == [""]
    implicit = payload["by_round"][""]
    assert implicit["total_calls"] == payload["total_calls"]
    assert implicit["complete"] == payload["complete"]
    assert implicit["probes_lost"] == payload["probes_lost"]
    assert implicit["by_bucket"] == payload["by_bucket"]
    assert implicit["by_process"] == payload["by_process"]


def test_extract_same_pid_across_rounds_never_fuses(tmp_path: Path) -> None:
    # Pid reuse across CLI invocations is real; (round, pid) rows stay split.
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            {"$report_type": "SessionStart"},
            _marker("a.py", 0),
            _round_session(100, 10, _R1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
            {"$report_type": "SessionStart"},
            _marker("b.py", 0),
            _round_session(100, 5, _R2),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["total_calls"] == 15
    assert payload["by_process"] == [
        {"pid": 100, "isolation": "file", "total_calls": 10, "complete": True, "round": _R1},
        {"pid": 100, "isolation": "file", "total_calls": 5, "complete": True, "round": _R2},
    ]


def test_extract_round_completeness_is_independent(tmp_path: Path) -> None:
    # R1 clean, R2 crash-fallback: per-round flags differ, global is false.
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            {"$report_type": "SessionStart"},
            _marker("a.py", 0),
            _round_session(100, 10, _R1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
            {"$report_type": "SessionStart"},
            _marker("b.py", 0),
            _test_report("b.py::t1", "teardown", _round_entry(200, 5, _R2)),
            _test_report("b.py::t1", "teardown", _round_entry(200, 3, _R2)),
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["complete"] is False
    assert payload["total_calls"] == 18
    assert payload["by_round"][_R1]["complete"] is True
    assert payload["by_round"][_R2]["complete"] is False
    assert payload["by_round"][_R2]["total_calls"] == 8


def test_extract_pid_reconciliation_is_run_scoped(tmp_path: Path) -> None:
    # Same pid, same marker shape, different rounds: the R1 entry is NOT
    # superseded by the R2 session record (different processes).
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            {"$report_type": "SessionStart"},
            _marker("a.py", 0),
            _test_report("a.py::t1", "teardown", _round_entry(100, 5, _R1)),
            {"$report_type": "SessionFinish", "exitstatus": 0},
            {"$report_type": "SessionStart"},
            _marker("a.py", 0),
            _round_session(100, 10, _R2),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["total_calls"] == 15
    assert payload["by_round"][_R1]["complete"] is False  # fallback folded
    assert payload["by_round"][_R1]["total_calls"] == 5
    assert payload["by_round"][_R2]["complete"] is True


def test_extract_counterless_segment_is_unattributable_round(tmp_path: Path) -> None:
    # C2 with rounds: a counterless TestReport in an unfinished scope names no
    # round, so the empty group lands in "" (round unknown) and flips global
    # complete while leaving the attributed round complete.
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            {"$report_type": "SessionStart"},
            _marker("a.py", 0),
            _round_session(100, 10, _R1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
            {"$report_type": "SessionStart"},
            _marker("b.py", 0),
            _test_report("b.py::t1", "call", None),
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["complete"] is False
    assert payload["total_calls"] == 10
    assert sorted(payload["by_round"]) == ["", _R1]
    assert payload["by_round"][_R1]["complete"] is True
    assert payload["by_round"][""]["complete"] is False
    assert payload["by_round"][""]["total_calls"] == 0
    assert payload["by_round"][""]["by_process"] == []
    # Untagged-rows contract: the conditional tag counts distinct rounds among
    # ROWS, so the pid-less C2-only "" round leaves R1's rows untagged (the
    # merge must attribute them to R1, not to "").
    assert payload["by_process"] == [
        {"pid": 100, "isolation": "file", "total_calls": 10, "complete": True}
    ]


@pytest.mark.parametrize("bad_run_id", ["", 0, None, {"r": 1}, ["r"], True])
def test_extract_malformed_run_id_skips_session_record(tmp_path: Path, bad_run_id: Any) -> None:
    # Fail-closed (mirror I2): present-but-not-nonempty-string run_id skips
    # the whole record; the valid record still folds.
    bad = _session_record(100, 10)
    bad["run_id"] = bad_run_id
    jsonl = _write_jsonl(tmp_path / "report.jsonl", [bad, _round_session(200, 7, _R1)])
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["total_calls"] == 7
    assert payload["complete"] is True
    assert [row["pid"] for row in payload["by_process"]] == [200]


@pytest.mark.parametrize("bad_run_id", ["", 0, None, {"r": 1}, ["r"], True])
def test_extract_malformed_run_id_skips_test_entry(tmp_path: Path, bad_run_id: Any) -> None:
    entry = _test_entry(300, 5)
    entry["run_id"] = bad_run_id
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            _test_report("a.py::t1", "teardown", entry),
            _round_session(200, 7, _R1),
        ],
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    assert payload["total_calls"] == 7
    assert [row["pid"] for row in payload["by_process"]] == [200]
