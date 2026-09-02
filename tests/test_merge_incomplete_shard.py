"""Regression tests for shard-merge robustness (review finding R1).

A shard is finalized by writing ``report.jsonl`` incrementally and
``results.json`` last. If a shard is killed (OOM, host kill) between the two, it
has real failed/crashed records in its JSONL but no — or a truncated —
``results.json``. The merge must never drop such a shard's findings from the
summed summary (cardinal rule: never hide a finding), and one corrupt
``results.json`` must not abort the whole merge.
"""

from __future__ import annotations

import json
from pathlib import Path

from pkcs11_check.core.file_runner import postprocess_jsonl_to_unified
from pkcs11_check.core.merge import merge_results_payloads, merge_shard_dirs
from pkcs11_check.core.process_observation import build_process_observation


def _write_jsonl(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")


def _call(nodeid: str, outcome: str) -> dict[str, object]:
    return {
        "$report_type": "TestReport",
        "nodeid": nodeid,
        "when": "call",
        "outcome": outcome,
        "duration": 0.01,
    }


def _ok_results(target: str) -> dict[str, object]:
    return {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": {
            "passed": 1,
            "failed": 0,
            "skipped": 0,
            "xfailed": 0,
            "xpassed": 0,
            "error": 0,
            "crashed": 0,
            "timeout": 0,
            "total": 1,
        },
        "units": [{"target": target, "status": "passed", "returncode": 0, "duration_s": 0.1}],
    }


def _make_shard(root: Path, name: str, *, results: bool, jsonl: list[dict[str, object]]) -> Path:
    d = root / name
    d.mkdir()
    _write_jsonl(d / "report.jsonl", jsonl)
    if results:
        (d / "results.json").write_text(json.dumps(_ok_results("test_ok.py")), encoding="utf-8")
    return d


def test_shard_without_results_json_is_not_dropped_from_summary(tmp_path: Path) -> None:
    # shard0: complete (results.json + report.jsonl, one pass).
    s0 = _make_shard(
        tmp_path, "shard-0", results=True, jsonl=[_call("test_ok.py::test_pass", "passed")]
    )
    # shard1: killed before results.json — only report.jsonl with a real failure.
    s1 = _make_shard(
        tmp_path, "shard-1", results=False, jsonl=[_call("test_bad.py::test_fail", "failed")]
    )

    merged = merge_shard_dirs([s0, s1], tmp_path / "out")

    # The failure from shard1 MUST survive into the merged summary.
    assert merged["summary"]["failed"] >= 1, merged["summary"]
    assert merged["summary"]["passed"] >= 1
    # And it is surfaced as a warning, not hidden.
    warnings = merged.get("shards", {}).get("warnings", [])
    assert any("reconstructed" in w for w in warnings), warnings
    assert merged["summary"]["timeout"] == 0
    assert merged["summary"]["incomplete"] is True


def test_corrupt_results_json_does_not_abort_merge(tmp_path: Path) -> None:
    s0 = _make_shard(
        tmp_path, "shard-0", results=True, jsonl=[_call("test_ok.py::test_pass", "passed")]
    )
    # shard1 has a truncated/corrupt results.json but a valid report.jsonl.
    s1 = tmp_path / "shard-1"
    s1.mkdir()
    _write_jsonl(s1 / "report.jsonl", [_call("test_bad.py::test_fail", "failed")])
    (s1 / "results.json").write_text(
        '{"summary": {"failed": 1, ', encoding="utf-8"
    )  # truncated JSON

    merged = merge_shard_dirs([s0, s1], tmp_path / "out")

    # Merge completed (did not raise) and the failure was salvaged from JSONL.
    assert merged["summary"]["failed"] >= 1, merged["summary"]
    warnings = merged.get("shards", {}).get("warnings", [])
    assert any("unreadable" in w for w in warnings), warnings
    assert merged["summary"]["timeout"] == 0
    assert merged["summary"]["incomplete"] is True


def test_incomplete_shard_salvage_preserves_process_and_passing_probe_evidence(
    tmp_path: Path,
) -> None:
    s0 = _make_shard(
        tmp_path, "shard-0", results=True, jsonl=[_call("test_ok.py::test_pass", "passed")]
    )
    outer = build_process_observation("test_partial.py", "unit", 0, -9)
    probe = build_process_observation(
        "probe", "probe", 0, 0, parent_nodeid="test_partial.py::test_pass"
    )
    s1 = _make_shard(
        tmp_path,
        "shard-1",
        results=False,
        jsonl=[
            {"$report_type": "ProcessReport", "target": "test_partial.py", "observation": outer},
            {
                "$report_type": "TestReport",
                "nodeid": "test_partial.py::test_pass",
                "when": "call",
                "outcome": "passed",
                "user_properties": [["pkcs11_process_observations", [probe]]],
            },
        ],
    )

    merged = merge_shard_dirs([s0, s1], tmp_path / "out")

    partial = next(unit for unit in merged["units"] if unit["target"] == "test_partial.py")
    assert partial["status"] == "passed"
    assert [execution["target"] for execution in partial["executions"]] == [
        "test_partial.py",
        "probe",
    ]
    merged_records = [
        json.loads(line)
        for line in (tmp_path / "out" / "report.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert any(record.get("$report_type") == "ProcessReport" for record in merged_records)
    assert merged["summary"]["incomplete"] is True


def test_partial_shard_results_are_warned_not_silent(tmp_path: Path) -> None:
    s0 = _make_shard(
        tmp_path, "shard-0", results=True, jsonl=[_call("test_ok.py::test_pass", "passed")]
    )
    s1 = _make_shard(
        tmp_path, "shard-1", results=True, jsonl=[_call("test_partial.py::test_fail", "failed")]
    )
    payload = _ok_results("test_partial.py")
    payload["partial"] = {
        "reason": "OP-TEE guest runner exited before final report generation",
        "completed_units": 223,
        "planned_units": 246,
    }
    (s1 / "results.json").write_text(json.dumps(payload), encoding="utf-8")

    merged = merge_shard_dirs([s0, s1], tmp_path / "out")

    warnings = merged.get("shards", {}).get("warnings", [])
    assert any("partial" in w and "223/246" in w for w in warnings), warnings
    assert merged["summary"]["timeout"] == 0
    assert merged["summary"]["incomplete"] is True


def test_total_loss_shard_is_warned_not_silent(tmp_path: Path) -> None:
    s0 = _make_shard(
        tmp_path, "shard-0", results=True, jsonl=[_call("test_ok.py::test_pass", "passed")]
    )
    # shard1: corrupt results.json AND no report.jsonl to salvage from.
    s1 = tmp_path / "shard-1"
    s1.mkdir()
    (s1 / "results.json").write_text("not json at all", encoding="utf-8")

    merged = merge_shard_dirs([s0, s1], tmp_path / "out")

    # Merge still completes, and the loss is loudly recorded (never silent).
    warnings = merged.get("shards", {}).get("warnings", [])
    assert any("LOST" in w for w in warnings), warnings
    assert merged["summary"]["timeout"] == 0
    assert merged["summary"]["incomplete"] is True


def test_corrupt_results_with_empty_jsonl_is_warned_lost(tmp_path: Path) -> None:
    s0 = _make_shard(
        tmp_path, "shard-0", results=True, jsonl=[_call("test_ok.py::test_pass", "passed")]
    )
    # shard1: corrupt results.json (proof the shard RAN) but an EMPTY report.jsonl -> the
    # zero-count salvage is a genuine loss and must be warned, not silently accepted.
    s1 = tmp_path / "shard-1"
    s1.mkdir()
    (s1 / "report.jsonl").write_text("", encoding="utf-8")
    (s1 / "results.json").write_text("{ truncated", encoding="utf-8")

    merged = merge_shard_dirs([s0, s1], tmp_path / "out")

    warnings = merged.get("shards", {}).get("warnings", [])
    assert any("LOST" in w for w in warnings), warnings
    assert merged["summary"]["timeout"] == 0
    assert merged["summary"]["incomplete"] is True


def test_missing_shard_artifacts_are_lost_and_incomplete(tmp_path: Path) -> None:
    s0 = _make_shard(
        tmp_path, "shard-0", results=True, jsonl=[_call("test_ok.py::test_pass", "passed")]
    )
    s1 = tmp_path / "shard-1"
    s1.mkdir()

    merged = merge_shard_dirs([s0, s1], tmp_path / "out")

    warnings = merged.get("shards", {}).get("warnings", [])
    assert any("LOST" in warning for warning in warnings), warnings
    assert merged["summary"]["timeout"] == 0
    assert merged["summary"]["incomplete"] is True


def test_jsonl_without_session_finish_is_incomplete_without_timeout(tmp_path: Path) -> None:
    report_log = tmp_path / "report.jsonl"
    _write_jsonl(report_log, [_call("test_partial.py::test_pass", "passed")])

    payload = postprocess_jsonl_to_unified(report_log, tmp_path / "results.json")

    assert payload["summary"]["passed"] == 1
    assert payload["summary"]["timeout"] == 0
    assert payload["summary"]["incomplete"] is True


def test_jsonl_with_session_finish_is_complete(tmp_path: Path) -> None:
    report_log = tmp_path / "report.jsonl"
    _write_jsonl(
        report_log,
        [
            {"$report_type": "SessionStart"},
            _call("test_complete.py::test_pass", "passed"),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )

    payload = postprocess_jsonl_to_unified(report_log, tmp_path / "results.json")

    assert payload["summary"]["timeout"] == 0
    assert payload["summary"]["incomplete"] is False


def _summary(**over: int) -> dict[str, object]:
    base = {
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
        "error": 0,
        "crashed": 0,
        "timeout": 0,
        "crash_limited": 0,
        "total": 0,
    }
    base.update(over)
    return {"summary": base, "units": []}


def test_incomplete_set_on_timeout_even_without_crash_limit() -> None:
    merged = merge_results_payloads([_summary(passed=1, timeout=2)], coverage=None)
    assert merged["summary"]["incomplete"] is True


def test_merge_preserves_incoming_incomplete_without_timeout() -> None:
    payload = _summary(passed=1)
    payload["summary"]["incomplete"] = True

    merged = merge_results_payloads([payload], coverage=None)

    assert merged["summary"]["timeout"] == 0
    assert merged["summary"]["incomplete"] is True


def test_incomplete_set_on_watchdog_unit_timeout_without_test_timeout() -> None:
    payload = _summary(passed=3809)
    payload["units"] = [
        {
            "target": "test_wycheproof_ecdsa.py",
            "status": "timeout",
            "returncode": 124,
            "duration_s": 5400.1,
        }
    ]

    merged = merge_results_payloads([payload], coverage=None)

    assert merged["summary"]["timeout"] == 0
    assert merged["summary"]["incomplete"] is True


def test_incomplete_set_on_crash_limit() -> None:
    merged = merge_results_payloads([_summary(passed=1, crash_limited=5)], coverage=None)
    assert merged["summary"]["incomplete"] is True


def test_incomplete_false_when_clean() -> None:
    merged = merge_results_payloads([_summary(passed=3)], coverage=None)
    assert merged["summary"]["incomplete"] is False
