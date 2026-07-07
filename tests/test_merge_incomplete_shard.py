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

from pkcs11_check.core.merge import merge_results_payloads, merge_shard_dirs


def _write_jsonl(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in records))


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
        (d / "results.json").write_text(json.dumps(_ok_results("test_ok.py")))
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


def test_corrupt_results_json_does_not_abort_merge(tmp_path: Path) -> None:
    s0 = _make_shard(
        tmp_path, "shard-0", results=True, jsonl=[_call("test_ok.py::test_pass", "passed")]
    )
    # shard1 has a truncated/corrupt results.json but a valid report.jsonl.
    s1 = tmp_path / "shard-1"
    s1.mkdir()
    _write_jsonl(s1 / "report.jsonl", [_call("test_bad.py::test_fail", "failed")])
    (s1 / "results.json").write_text('{"summary": {"failed": 1, ')  # truncated JSON

    merged = merge_shard_dirs([s0, s1], tmp_path / "out")

    # Merge completed (did not raise) and the failure was salvaged from JSONL.
    assert merged["summary"]["failed"] >= 1, merged["summary"]
    warnings = merged.get("shards", {}).get("warnings", [])
    assert any("unreadable" in w for w in warnings), warnings


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
    (s1 / "results.json").write_text(json.dumps(payload))

    merged = merge_shard_dirs([s0, s1], tmp_path / "out")

    warnings = merged.get("shards", {}).get("warnings", [])
    assert any("partial" in w and "223/246" in w for w in warnings), warnings


def test_total_loss_shard_is_warned_not_silent(tmp_path: Path) -> None:
    s0 = _make_shard(
        tmp_path, "shard-0", results=True, jsonl=[_call("test_ok.py::test_pass", "passed")]
    )
    # shard1: corrupt results.json AND no report.jsonl to salvage from.
    s1 = tmp_path / "shard-1"
    s1.mkdir()
    (s1 / "results.json").write_text("not json at all")

    merged = merge_shard_dirs([s0, s1], tmp_path / "out")

    # Merge still completes, and the loss is loudly recorded (never silent).
    warnings = merged.get("shards", {}).get("warnings", [])
    assert any("LOST" in w for w in warnings), warnings


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


def test_incomplete_set_on_crash_limit() -> None:
    merged = merge_results_payloads([_summary(passed=1, crash_limited=5)], coverage=None)
    assert merged["summary"]["incomplete"] is True


def test_incomplete_false_when_clean() -> None:
    merged = merge_results_payloads([_summary(passed=3)], coverage=None)
    assert merged["summary"]["incomplete"] is False
