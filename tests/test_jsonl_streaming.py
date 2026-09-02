"""Characterization (golden) tests for the report.jsonl readers.

These tests pin the EXACT current output of the report.jsonl readers so any
rewrite is provably byte-identical - same records, same aggregation, same order.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pkcs11_check.core import _report_records as report_records_mod
from pkcs11_check.core import file_runner as file_runner_mod
from pkcs11_check.core._report_records import (
    _build_per_unit_details_from_record_sources,
    _seed_missing_report_record_caches_from_jsonl,
    _write_report_jsonl_from_record_sources,
)
from pkcs11_check.core._report_writers import _build_isolated_json_payload
from pkcs11_check.core._run_units import FileRunResult, FileRunState
from pkcs11_check.core.file_runner import (
    _extract_unit_report_records_from_jsonl,
    _load_report_log_records,
    extract_coverage_from_jsonl,
    extract_quality_report_records_from_jsonl,
    postprocess_jsonl_to_unified,
)
from pkcs11_check.core.process_observation import build_process_observation
from pkcs11_check.report.__main__ import crashes_from_results

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
            "ok_counts": {"C_A": 1, "C_B": 2},
            "bootstrap_counts": {"C_Initialize": 1},
            "module_session_health": {"checks": 1, "duration_s": 0.25},
            "uncalled_names": ["C_X", "C_Y"],
        },
        "mechanism_coverage": {
            "available_names": ["M1", "M2"],
            "advertised_names": ["M1", "M2"],
            "selected_names": ["M1"],
            "selection_rejected_names": ["M2"],
            "attempted_names": ["M1"],
            "invoked_names": ["M1"],
            "invoked_counts": {"M1": 5},
            "not_invoked_names": ["M2"],
            "invoked_detail": ["D1"],
            "invoked_detail_counts": {"D1": 1},
            "accepted_names": ["M1"],
            "rejected_cleanly_names": [],
            "skipped_by_capability_names": [],
            "crashed_names": [],
            "timeout_names": [],
        },
    },
    {
        "$report_type": "CoverageReport",
        "function_coverage": {
            "available": 68,
            "called_names": ["C_B", "C_Z"],
            "called_counts": {"C_B": 1, "C_Z": 4},
            "ok_counts": {"C_B": 1, "C_Z": 3},
            "bootstrap_counts": {"C_GetSlotList": 2},
            "module_session_health": {"checks": 2, "duration_s": 0.5},
            "uncalled_names": ["C_Y"],
        },
        "mechanism_coverage": {
            "available_names": ["M2", "M3"],
            "advertised_names": ["M2", "M3"],
            "selected_names": ["M2"],
            "selection_rejected_names": [],
            "attempted_names": ["M2"],
            "invoked_names": ["M2"],
            "invoked_counts": {"M2": 7},
            "invoked_detail": ["D2"],
            "invoked_detail_counts": {"D2": 2},
            "accepted_names": [],
            "rejected_cleanly_names": ["M2"],
            "skipped_by_capability_names": [],
            "crashed_names": [],
            "timeout_names": [],
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
    p.write_text("".join(json.dumps(r) + "\n" for r in _FIXTURE_RECORDS), encoding="utf-8")
    return p


def _write_jsonl(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")


def test_load_report_log_records_returns_all_dicts(tmp_path: Path) -> None:
    recs = _load_report_log_records(_write_fixture(tmp_path))
    assert recs == _FIXTURE_RECORDS


def test_load_report_log_records_missing_file_is_empty(tmp_path: Path) -> None:
    assert _load_report_log_records(tmp_path / "nope.jsonl") == []


def test_extract_unit_report_records_streams_without_load_all(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    p = tmp_path / "report.jsonl"
    records = [
        {"$report_type": "SessionStart"},
        {
            "$report_type": "TestReport",
            "nodeid": "a.py::test_one",
            "when": "call",
            "outcome": "passed",
        },
        {
            "$report_type": "CoverageReport",
            "function_coverage": {"called_names": ["C_Initialize"]},
        },
        {
            "$report_type": "TestReport",
            "nodeid": "b.py::test_two",
            "when": "call",
            "outcome": "failed",
        },
        {"$report_type": "SessionFinish"},
    ]
    p.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")

    def _load_all_forbidden(_path: Path) -> list[dict[str, object]]:
        pytest.fail("_extract_unit_report_records_from_jsonl must stream records")

    monkeypatch.setattr(file_runner_mod, "_load_report_log_records", _load_all_forbidden)
    monkeypatch.setattr(report_records_mod, "_load_report_log_records", _load_all_forbidden)

    assert _extract_unit_report_records_from_jsonl(
        p,
        candidate_targets={"a.py", "b.py"},
    ) == {
        "a.py": records[:3],
        "b.py": records[3:],
    }


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
            "ok_counts": {"C_A": 1, "C_B": 3, "C_Z": 3},
            "bootstrap_counts": {"C_Initialize": 1, "C_GetSlotList": 2},
            "module_session_health": {"checks": 3, "duration_s": 0.75},
            "uncalled_names": ["C_X", "C_Y"],
        },
        "mechanism_coverage": {
            "available": 3,
            "available_names": ["M1", "M2", "M3"],
            "advertised_names": ["M1", "M2", "M3"],
            "selected_names": ["M1", "M2"],
            "selection_rejected_names": ["M2"],
            "attempted_names": ["M1", "M2"],
            "invoked": 2,
            "invoked_names": ["M1", "M2"],
            "invoked_counts": {"M1": 5, "M2": 7},
            "not_invoked": 1,
            "not_invoked_names": ["M3"],
            "invoked_detail": ["D1", "D2"],
            "invoked_detail_counts": {"D1": 1, "D2": 2},
            "accepted_names": ["M1"],
            "rejected_cleanly_names": ["M2"],
            "skipped_by_capability_names": [],
            "crashed_names": [],
            "timeout_names": [],
        },
    }


def test_coverage_none_when_no_coverage_report(tmp_path: Path) -> None:
    p = tmp_path / "r.jsonl"
    p.write_text(json.dumps({"$report_type": "TestReport", "nodeid": "x"}) + "\n", encoding="utf-8")
    assert extract_coverage_from_jsonl(p) is None


def test_coverage_missing_file_is_none(tmp_path: Path) -> None:
    assert extract_coverage_from_jsonl(tmp_path / "nope.jsonl") is None


def test_jsonl_salvages_process_and_passing_probe_executions_in_order(tmp_path: Path) -> None:
    outer = build_process_observation("a.py", "unit", 0, -1073741819, platform="win32")
    probe_one = build_process_observation("probe-one", "probe", 0, 0)
    probe_two = build_process_observation("probe-two", "probe", 0, -9)
    probe_one["parent_nodeid"] = "a.py::test_pass"
    probe_two["parent_nodeid"] = "a.py::test_pass"
    records = [
        {"$report_type": "ProcessReport", "target": "a.py", "observation": outer},
        {
            "$report_type": "TestReport",
            "nodeid": "a.py::test_pass",
            "when": "call",
            "outcome": "passed",
            "user_properties": [
                [
                    "pkcs11_process_observations",
                    [probe_one, probe_two],
                ]
            ],
        },
        {"$report_type": "SessionFinish", "exitstatus": 0},
    ]
    path = tmp_path / "report.jsonl"
    _write_jsonl(path, records)

    payload = postprocess_jsonl_to_unified(path, tmp_path / "results.json")

    executions = payload["units"][0]["executions"]
    assert [execution["target"] for execution in executions] == [
        "a.py",
        "probe-one",
        "probe-two",
    ]
    assert [execution["attempt"] for execution in executions] == [0, 0, 0]
    assert executions[0]["termination"]["windows_status"] == 0xC0000005
    assert payload["units"][0]["counts"]["passed"] == 1


def test_jsonl_execution_duplicates_keep_first_position_and_increment_attempts(
    tmp_path: Path,
) -> None:
    first = build_process_observation("a.py", "unit", 0, -9)
    duplicate = dict(first)
    later = build_process_observation("a.py", "unit", 1, 0)
    records = [
        {"$report_type": "ProcessReport", "target": "a.py", "observation": first},
        {"$report_type": "ProcessReport", "target": "a.py", "observation": duplicate},
        {"$report_type": "ProcessReport", "target": "a.py", "observation": later},
        {"$report_type": "SessionFinish", "exitstatus": 0},
    ]
    path = tmp_path / "report.jsonl"
    _write_jsonl(path, records)

    payload = postprocess_jsonl_to_unified(path, tmp_path / "results.json")

    executions = payload["units"][0]["executions"]
    assert len(executions) == 2
    assert [execution["attempt"] for execution in executions] == [0, 1]
    assert [execution["termination"]["raw_code"] for execution in executions] == [-9, 0]


def test_jsonl_keeps_identical_probe_observations_from_one_test_report(tmp_path: Path) -> None:
    probe = build_process_observation("probe", "probe", 0, -9)
    probe["parent_nodeid"] = "a.py::test_pass"
    call = {
        "$report_type": "TestReport",
        "nodeid": "a.py::test_pass",
        "when": "call",
        "outcome": "passed",
        "user_properties": [
            [
                "pkcs11_process_observations",
                [probe, dict(probe)],
            ]
        ],
    }
    path = tmp_path / "report.jsonl"
    _write_jsonl(path, [call, {"$report_type": "SessionFinish", "exitstatus": 0}])

    payload = postprocess_jsonl_to_unified(path, tmp_path / "results.json")

    executions = payload["units"][0]["executions"]
    assert len(executions) == 2
    assert [execution["attempt"] for execution in executions] == [0, 1]


def test_resume_rebuild_keeps_prior_records_before_new_records(tmp_path: Path) -> None:
    state_file = tmp_path / "state.json"
    old = {
        "$report_type": "TestReport",
        "nodeid": "old.py::test_old",
        "when": "call",
        "outcome": "passed",
    }
    new = {
        "$report_type": "TestReport",
        "nodeid": "new.py::test_new",
        "when": "call",
        "outcome": "passed",
    }
    report_path = tmp_path / "report.jsonl"
    _write_jsonl(report_path, [old, {"$report_type": "SessionFinish", "exitstatus": 0}])

    _seed_missing_report_record_caches_from_jsonl(
        state_file,
        report_path,
        candidate_targets={"old.py", "new.py"},
    )
    assert _write_report_jsonl_from_record_sources(
        state_file,
        units=["old.py", "new.py"],
        inline_records_by_unit={"new.py": [new]},
        output_path=report_path,
    )

    records = [json.loads(line) for line in report_path.read_text(encoding="utf-8").splitlines()]
    assert [record.get("nodeid") for record in records if record.get("nodeid")] == [
        "old.py::test_old",
        "new.py::test_new",
    ]


def test_resume_saved_process_history_is_ordered_and_not_duplicated(tmp_path: Path) -> None:
    old = build_process_observation("a.py", "unit", 0, -11)
    new = build_process_observation("a.py", "retry", 0, -9)
    old_process = {"$report_type": "ProcessReport", "target": "a.py", "observation": old}
    old_call = {
        "$report_type": "TestReport",
        "nodeid": "a.py::test_old",
        "when": "call",
        "outcome": "passed",
    }
    new_call = {
        "$report_type": "TestReport",
        "nodeid": "a.py::test_new",
        "when": "call",
        "outcome": "passed",
    }
    state = FileRunState(
        units=["a.py"],
        fingerprint="",
        results=[
            FileRunResult("a.py", "crashed", 9, 0.1),
        ],
        process_observations=[old, new],
    )
    state_path = tmp_path / "state.json"
    state_path.write_text(
        json.dumps(
            {
                "units": state.units,
                "fingerprint": state.fingerprint,
                "results": [result.__dict__ for result in state.results],
                "process_observations": state.process_observations,
            }
        ),
        encoding="utf-8",
    )
    report_path = tmp_path / "report.jsonl"
    _write_jsonl(report_path, [old_process, old_call])

    _seed_missing_report_record_caches_from_jsonl(
        state_path,
        report_path,
        candidate_targets=set(state.units),
    )
    assert _write_report_jsonl_from_record_sources(
        state_path,
        units=state.units,
        inline_records_by_unit={"a.py": [new_call]},
        output_path=report_path,
    )

    records = [json.loads(line) for line in report_path.read_text(encoding="utf-8").splitlines()]
    process_observations = [
        record["observation"] for record in records if record["$report_type"] == "ProcessReport"
    ]
    assert [observation["role"] for observation in process_observations] == ["unit", "retry"]

    details = _build_per_unit_details_from_record_sources(
        state_path,
        units=state.units,
        inline_records_by_unit={"a.py": [new_call]},
    )
    payload = _build_isolated_json_payload(state, per_unit_details=details)
    executions = [
        execution for unit in payload["units"] for execution in unit.get("executions", [])
    ]
    assert [execution["role"] for execution in executions] == ["unit", "retry"]


def test_resume_partial_process_history_keeps_cache_before_new_unit_state(
    tmp_path: Path,
) -> None:
    old_zero = build_process_observation("old.py", "unit", 0, -11)
    old_one = dict(old_zero, attempt=1)
    new_zero = build_process_observation("new.py", "unit", 0, -11)
    state = FileRunState(
        units=["old.py", "new.py"],
        fingerprint="",
        results=[
            FileRunResult("old.py", "crashed", 11, 0.1),
            FileRunResult("new.py", "crashed", 11, 0.1),
        ],
        process_observations=[old_zero, new_zero],
        process_observations_complete=False,
    )
    state_path = tmp_path / "state.json"
    state_path.write_text(
        json.dumps(
            {
                "units": state.units,
                "fingerprint": state.fingerprint,
                "results": [result.__dict__ for result in state.results],
                "process_observations": state.process_observations,
            }
        ),
        encoding="utf-8",
    )
    old_records = [
        {"$report_type": "ProcessReport", "target": "old.py", "observation": old_zero},
        {"$report_type": "ProcessReport", "target": "old.py", "observation": old_one},
        {"$report_type": "SessionFinish", "exitstatus": 1},
    ]
    report_path = tmp_path / "report.jsonl"
    _write_jsonl(report_path, old_records)
    _seed_missing_report_record_caches_from_jsonl(
        state_path,
        report_path,
        candidate_targets=set(state.units),
    )

    assert _write_report_jsonl_from_record_sources(
        state_path,
        units=state.units,
        inline_records_by_unit={},
        output_path=report_path,
    )
    records = [json.loads(line) for line in report_path.read_text(encoding="utf-8").splitlines()]
    process_pairs = [
        (record["observation"]["target"], record["observation"]["attempt"])
        for record in records
        if record["$report_type"] == "ProcessReport"
    ]
    assert process_pairs == [("old.py", 0), ("old.py", 1), ("new.py", 0)]

    details = _build_per_unit_details_from_record_sources(
        state_path,
        units=state.units,
        inline_records_by_unit={},
    )
    payload = _build_isolated_json_payload(state, per_unit_details=details)
    execution_pairs = [
        (execution["target"], execution["attempt"])
        for unit in payload["units"]
        for execution in unit.get("executions", [])
    ]
    assert execution_pairs == [("old.py", 0), ("old.py", 1), ("new.py", 0)]


def test_resume_same_unit_state_and_cache_keep_attempt_multiplicity(tmp_path: Path) -> None:
    old_zero = build_process_observation("a.py", "unit", 0, -11)
    old_one = dict(old_zero, attempt=1)
    state = FileRunState(
        units=["a.py"],
        fingerprint="",
        results=[FileRunResult("a.py", "crashed", 11, 0.1)],
        process_observations=[old_zero],
        process_observations_complete=False,
    )
    state_path = tmp_path / "state.json"
    state_path.write_text(
        json.dumps(
            {
                "units": state.units,
                "fingerprint": state.fingerprint,
                "results": [result.__dict__ for result in state.results],
                "process_observations": state.process_observations,
            }
        ),
        encoding="utf-8",
    )
    report_path = tmp_path / "report.jsonl"
    _write_jsonl(
        report_path,
        [
            {"$report_type": "ProcessReport", "target": "a.py", "observation": old_zero},
            {"$report_type": "ProcessReport", "target": "a.py", "observation": old_one},
        ],
    )
    _seed_missing_report_record_caches_from_jsonl(
        state_path,
        report_path,
        candidate_targets=set(state.units),
    )

    assert _write_report_jsonl_from_record_sources(
        state_path,
        units=state.units,
        inline_records_by_unit={},
        output_path=report_path,
    )
    records = [json.loads(line) for line in report_path.read_text(encoding="utf-8").splitlines()]
    assert [record["observation"]["attempt"] for record in records] == [0, 1]

    details = _build_per_unit_details_from_record_sources(
        state_path,
        units=state.units,
        inline_records_by_unit={},
    )
    payload = _build_isolated_json_payload(state, per_unit_details=details)
    assert [execution["attempt"] for execution in payload["units"][0].get("executions", [])] == [
        0,
        1,
    ]


def test_incomplete_cache_attempt_is_reconciled_with_saved_state_attempt(
    tmp_path: Path,
) -> None:
    state_observation = build_process_observation("a.py", "unit", 0, -11)
    cached_observation = dict(state_observation, attempt=1)
    state_path = tmp_path / "state.json"
    state_path.write_text(
        json.dumps(
            {
                "units": ["a.py"],
                "fingerprint": "",
                "results": [FileRunResult("a.py", "crashed", 11, 0.1).__dict__],
                "process_observations": [state_observation],
            }
        ),
        encoding="utf-8",
    )
    report_path = tmp_path / "report.jsonl"
    _write_jsonl(
        report_path,
        [{"$report_type": "ProcessReport", "target": "a.py", "observation": cached_observation}],
    )
    _seed_missing_report_record_caches_from_jsonl(
        state_path,
        report_path,
        candidate_targets={"a.py"},
    )

    assert _write_report_jsonl_from_record_sources(
        state_path,
        units=["a.py"],
        inline_records_by_unit={},
        output_path=report_path,
    )
    records = [json.loads(line) for line in report_path.read_text(encoding="utf-8").splitlines()]
    assert [record["observation"]["attempt"] for record in records] == [0, 1]

    details = _build_per_unit_details_from_record_sources(
        state_path,
        units=["a.py"],
        inline_records_by_unit={},
    )
    payload = _build_isolated_json_payload(
        FileRunState(
            units=["a.py"],
            fingerprint="",
            results=[FileRunResult("a.py", "crashed", 11, 0.1)],
            process_observations=[state_observation],
            process_observations_complete=False,
        ),
        per_unit_details=details,
    )
    assert [execution["attempt"] for execution in payload["units"][0]["executions"]] == [0, 1]


def test_reconcile_preserves_raw_ordered_attempts() -> None:
    cached = build_process_observation("a.py", "unit", 1, -11)
    saved = build_process_observation("a.py", "unit", 0, -11)

    reconciled = report_records_mod._reconcile_process_observations([cached], [saved])

    assert [observation["attempt"] for observation in reconciled] == [1, 0]


@pytest.mark.parametrize("complete", [False, True])
def test_nested_execution_uses_parent_file_and_discards_empty_parent(
    complete: bool, tmp_path: Path
) -> None:
    valid = build_process_observation("probe-valid", "probe", 0, 0, parent_nodeid="a.py::test_a")
    foreign = build_process_observation(
        "probe-foreign", "probe", 0, 0, parent_nodeid="b.py::test_b"
    )
    empty = build_process_observation("probe-empty", "probe", 0, 0, parent_nodeid=" ")
    missing = build_process_observation("probe-missing", "probe", 0, 0)
    state = FileRunState(
        units=["a.py", "b.py"],
        fingerprint="",
        results=[
            FileRunResult("a.py", "passed", 0, 0.1),
            FileRunResult("b.py", "passed", 0, 0.1),
        ],
        process_observations=[],
        process_observations_complete=complete,
    )
    details = {
        "a.py::test_a": {
            "counts": {"passed": 1},
            "tests": [],
            "executions": [foreign, empty, missing, valid],
        }
    }

    payload = _build_isolated_json_payload(state, per_unit_details=details)
    executions_by_unit = {
        unit["target"]: [execution["target"] for execution in unit.get("executions", [])]
        for unit in payload["units"]
    }
    assert executions_by_unit["a.py"] == ["probe-valid"]
    assert executions_by_unit["b.py"] == ["probe-foreign"]

    call = {
        "$report_type": "TestReport",
        "nodeid": "a.py::test_a",
        "when": "call",
        "outcome": "passed",
        "user_properties": [
            [
                "pkcs11_process_observations",
                [foreign, empty, missing, valid],
            ]
        ],
    }
    path = tmp_path / "report.jsonl"
    _write_jsonl(path, [call, {"$report_type": "SessionFinish", "exitstatus": 0}])
    plain_payload = postprocess_jsonl_to_unified(path, tmp_path / "results.json")
    plain_executions = {
        unit["target"]: [execution["target"] for execution in unit.get("executions", [])]
        for unit in plain_payload["units"]
    }
    assert plain_executions["a.py"] == ["probe-valid"]
    assert plain_executions["b.py"] == ["probe-foreign"]
    assert "probe-empty" not in plain_executions
    assert "probe-missing" not in plain_executions


def test_complete_state_ignores_shuffled_cache_process_reports(tmp_path: Path) -> None:
    old = build_process_observation("old.py", "unit", 0, -11)
    new = build_process_observation("new.py", "unit", 0, -9)
    state = FileRunState(
        units=["old.py", "new.py"],
        fingerprint="",
        results=[
            FileRunResult("old.py", "crashed", 11, 0.1),
            FileRunResult("new.py", "crashed", 9, 0.1),
        ],
        process_observations=[old, new],
    )
    state_path = tmp_path / "state.json"
    state_path.write_text(
        json.dumps(
            {
                "units": state.units,
                "fingerprint": state.fingerprint,
                "results": [result.__dict__ for result in state.results],
                "process_observations": state.process_observations,
                "process_observations_complete": True,
            }
        ),
        encoding="utf-8",
    )
    report_path = tmp_path / "report.jsonl"
    _write_jsonl(
        report_path,
        [
            {"$report_type": "ProcessReport", "target": "new.py", "observation": new},
            {"$report_type": "ProcessReport", "target": "old.py", "observation": old},
        ],
    )
    _seed_missing_report_record_caches_from_jsonl(
        state_path,
        report_path,
        candidate_targets=set(state.units),
    )

    assert _write_report_jsonl_from_record_sources(
        state_path,
        units=["new.py", "old.py"],
        inline_records_by_unit={},
        output_path=report_path,
    )
    records = [json.loads(line) for line in report_path.read_text(encoding="utf-8").splitlines()]
    assert [record["observation"]["target"] for record in records] == ["old.py", "new.py"]

    details = _build_per_unit_details_from_record_sources(
        state_path,
        units=state.units,
        inline_records_by_unit={},
    )
    payload = _build_isolated_json_payload(state, per_unit_details=details)
    assert [
        execution["target"] for unit in payload["units"] for execution in unit.get("executions", [])
    ] == ["old.py", "new.py"]


def test_incomplete_legacy_jsonl_appends_unmatched_saved_process_history(tmp_path: Path) -> None:
    exit_observation = build_process_observation("a.py", "unit", 0, 0)
    signal_observation = build_process_observation("a.py", "unit", 1, -11, platform="linux")
    timeout_observation = build_process_observation("a.py", "unit", 2, None, timed_out=True)
    state_path = tmp_path / "state.json"
    state_path.write_text(
        json.dumps(
            {
                "units": ["a.py"],
                "fingerprint": "",
                "results": [],
                "process_observations": [exit_observation, timeout_observation],
            }
        ),
        encoding="utf-8",
    )
    source_records = [
        {"$report_type": "ProcessReport", "target": "a.py", "observation": exit_observation},
        {"$report_type": "ProcessReport", "target": "a.py", "observation": signal_observation},
    ]
    report_path = tmp_path / "report.jsonl"

    assert _write_report_jsonl_from_record_sources(
        state_path,
        units=["a.py"],
        inline_records_by_unit={"a.py": source_records},
        output_path=report_path,
    )
    records = [json.loads(line) for line in report_path.read_text(encoding="utf-8").splitlines()]
    assert [
        record["observation"]["termination"]["kind"]
        for record in records
        if record["$report_type"] == "ProcessReport"
    ] == ["exit", "signal", "timeout"]


def test_complete_test_granularity_places_all_nested_details_after_outers() -> None:
    outer_one = build_process_observation("a.py", "unit", 0, -11)
    outer_two = dict(outer_one, attempt=1)
    stale_outer = build_process_observation("a.py", "unit", 0, -9)
    nested_one = build_process_observation(
        "probe-one", "probe", 0, 0, parent_nodeid="a.py::test_one"
    )
    nested_two = build_process_observation(
        "probe-two", "probe", 0, 0, parent_nodeid="a.py::test_two"
    )
    state = FileRunState(
        units=["a.py"],
        fingerprint="",
        results=[
            FileRunResult("a.py::test_one", "passed", 0, 0.1),
            FileRunResult("a.py::test_two", "passed", 0, 0.1),
        ],
        process_observations=[outer_one, outer_two],
    )
    details = {
        "a.py::test_one": {
            "counts": {"passed": 1},
            "tests": [],
            "executions": [stale_outer, nested_one],
        },
        "a.py::test_two": {
            "counts": {"passed": 1},
            "tests": [],
            "executions": [outer_two, nested_two],
        },
    }

    payload = _build_isolated_json_payload(state, per_unit_details=details)
    executions = payload["units"][0]["executions"]
    assert [(execution["target"], execution["parent_nodeid"]) for execution in executions] == [
        ("a.py", None),
        ("a.py", None),
        ("probe-one", "a.py::test_one"),
        ("probe-two", "a.py::test_two"),
    ]


def test_distinct_test_reports_keep_identical_observation_attempts(tmp_path: Path) -> None:
    probe = build_process_observation("probe", "probe", 0, -9)
    probe["parent_nodeid"] = "a.py::test_probe"
    base = {
        "$report_type": "TestReport",
        "nodeid": "a.py::test_probe",
        "when": "call",
        "outcome": "passed",
        "user_properties": [["pkcs11_process_observations", [probe]]],
    }
    distinct = dict(base, duration=0.2)
    duplicate = dict(distinct)
    path = tmp_path / "report.jsonl"
    _write_jsonl(
        path,
        [base, distinct, duplicate, {"$report_type": "SessionFinish", "exitstatus": 0}],
    )

    payload = postprocess_jsonl_to_unified(path, tmp_path / "results.json")

    executions = payload["units"][0]["executions"]
    assert len(executions) == 2
    assert [execution["attempt"] for execution in executions] == [0, 1]


def test_report_crashed_status_selects_crash_after_timeout_retry(tmp_path: Path) -> None:
    timeout = build_process_observation("a.py", "unit", 0, None, timed_out=True)
    crash = build_process_observation("a.py", "retry", 1, -11)
    path = tmp_path / "results.json"
    path.write_text(
        json.dumps(
            {
                "units": [
                    {
                        "target": "a.py",
                        "status": "crashed",
                        "returncode": 11,
                        "executions": [timeout, crash],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    crashes = crashes_from_results(path)

    assert crashes[0]["detail"] == {"observation": crash}


def test_report_timeout_status_selects_timeout_observation(tmp_path: Path) -> None:
    crash = build_process_observation("a.py", "unit", 0, -11)
    timeout = build_process_observation("a.py", "retry", 1, None, timed_out=True)
    path = tmp_path / "results.json"
    path.write_text(
        json.dumps(
            {
                "units": [
                    {
                        "target": "a.py",
                        "status": "timeout",
                        "returncode": 124,
                        "executions": [crash, timeout],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    crashes = crashes_from_results(path)

    assert crashes[0]["detail"] == {"observation": timeout}


def test_saved_process_observations_emit_once_and_feed_unified_executions(tmp_path: Path) -> None:
    outer = build_process_observation("a.py", "unit", 0, -9)
    probe = build_process_observation("probe", "probe", 0, 0)
    probe["parent_nodeid"] = "a.py::test_pass"
    state = FileRunState(
        units=["a.py"],
        fingerprint="",
        results=[FileRunResult("a.py", "crashed", 9, 0.1)],
        process_observations=[outer],
    )
    state_path = tmp_path / "state.json"
    state_path.write_text(
        json.dumps(
            {
                "units": state.units,
                "fingerprint": state.fingerprint,
                "results": [state.results[0].__dict__],
                "process_observations": state.process_observations,
            }
        ),
        encoding="utf-8",
    )
    report_path = tmp_path / "report.jsonl"
    call = {
        "$report_type": "TestReport",
        "nodeid": "a.py::test_pass",
        "when": "call",
        "outcome": "passed",
        "user_properties": [["pkcs11_process_observations", [probe]]],
    }

    assert _write_report_jsonl_from_record_sources(
        state_path,
        units=["a.py"],
        inline_records_by_unit={"a.py": [call]},
        output_path=report_path,
    )
    records = [json.loads(line) for line in report_path.read_text(encoding="utf-8").splitlines()]
    assert records[0] == {"$report_type": "ProcessReport", "target": "a.py", "observation": outer}
    assert records[1] == call

    payload = _build_isolated_json_payload(
        state,
        per_unit_details={"a.py": {"counts": {"passed": 1}, "tests": [], "executions": [probe]}},
    )
    assert payload["units"][0]["executions"] == [outer, probe]
    assert payload["units"][0]["returncode"] == 9
