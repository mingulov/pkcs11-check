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

import pytest

from pkcs11_check.core.file_runner import postprocess_jsonl_to_unified
from pkcs11_check.core.merge import merge_results_payloads, merge_shard_dirs
from pkcs11_check.core.process_observation import build_process_observation
from pkcs11_check.core.test_selection import CaseSelection, compute_batch_id


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


def test_salvage_missing_results_json_recovers_canonical_selection_from_sidecar(
    tmp_path: Path,
) -> None:
    source = "wycheproof/test_wycheproof_ecdsa.py"
    nodeids = (f"{source}::test_verify[c1]", f"{source}::test_verify[c2]")
    batch_id = compute_batch_id(
        source=source,
        source_collection_count=2,
        source_collection_sha256="a" * 64,
        nodeids=nodeids,
    )
    sel = CaseSelection(
        schema=1,
        plan_id="b" * 64,
        batch_id=batch_id,
        source=source,
        source_collection_count=2,
        source_collection_sha256="a" * 64,
        nodeids=nodeids,
    )

    s0 = _make_shard(
        tmp_path, "shard-0", results=True, jsonl=[_call("test_ok.py::test_pass", "passed")]
    )

    s1 = tmp_path / "shard-1"
    s1.mkdir()
    # Shard 1 has valid report.jsonl (intact streaming log)
    _write_jsonl(s1 / "report.jsonl", [_call(f"{source}::test_verify[c1]", "passed")])
    # Shard 1 has valid selection.json sidecar
    (s1 / "selection.json").write_text(json.dumps(sel.to_dict(), indent=2), encoding="utf-8")
    # But results.json is MISSING

    merged = merge_shard_dirs([s0, s1], tmp_path / "out")

    # Incomplete is True due to missing results.json
    assert merged["summary"]["incomplete"] is True
    warnings = merged.get("shards", {}).get("warnings", [])
    assert any("reconstructed" in w for w in warnings), warnings

    # Unit for source was salvaged and got selection_batch_id
    ecdsa_unit = next(u for u in merged["units"] if u["target"] == source)
    assert ecdsa_unit["selection_batch_id"] == sel.batch_id

    # The raw report record survived
    merged_records = [
        json.loads(line)
        for line in (tmp_path / "out" / "report.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(
        r.get("$report_type") == "TestReport" and r.get("nodeid") == f"{source}::test_verify[c1]"
        for r in merged_records
    )


def test_salvage_corrupt_results_json_recovers_canonical_selection_from_sidecar(
    tmp_path: Path,
) -> None:
    source = "wycheproof/test_wycheproof_ecdsa.py"
    nodeids = (f"{source}::test_verify[c1]", f"{source}::test_verify[c2]")
    batch_id = compute_batch_id(
        source=source,
        source_collection_count=2,
        source_collection_sha256="a" * 64,
        nodeids=nodeids,
    )
    sel = CaseSelection(
        schema=1,
        plan_id="b" * 64,
        batch_id=batch_id,
        source=source,
        source_collection_count=2,
        source_collection_sha256="a" * 64,
        nodeids=nodeids,
    )

    s0 = _make_shard(
        tmp_path, "shard-0", results=True, jsonl=[_call("test_ok.py::test_pass", "passed")]
    )

    s1 = tmp_path / "shard-1"
    s1.mkdir()
    _write_jsonl(s1 / "report.jsonl", [_call(f"{source}::test_verify[c1]", "passed")])
    (s1 / "selection.json").write_text(json.dumps(sel.to_dict(), indent=2), encoding="utf-8")
    (s1 / "results.json").write_text('{"summary": {"failed": 1, ', encoding="utf-8")  # corrupt

    merged = merge_shard_dirs([s0, s1], tmp_path / "out")

    assert merged["summary"]["incomplete"] is True
    warnings = merged.get("shards", {}).get("warnings", [])
    assert any("unreadable" in w for w in warnings), warnings

    ecdsa_unit = next(u for u in merged["units"] if u["target"] == source)
    assert ecdsa_unit["selection_batch_id"] == sel.batch_id


def test_salvage_does_not_infer_selection_membership_from_truncated_reports(
    tmp_path: Path,
) -> None:
    # 5 planned cases in selection manifest, but only 2 executed before crash/kill
    source = "wycheproof/test_wycheproof_ecdsa.py"
    nodeids = tuple(f"{source}::test_verify[c{i}]" for i in range(5))
    batch_id = compute_batch_id(
        source=source,
        source_collection_count=5,
        source_collection_sha256="a" * 64,
        nodeids=nodeids,
    )
    sel = CaseSelection(
        schema=1,
        plan_id="b" * 64,
        batch_id=batch_id,
        source=source,
        source_collection_count=5,
        source_collection_sha256="a" * 64,
        nodeids=nodeids,
    )

    s1 = tmp_path / "shard-1"
    s1.mkdir()
    # report.jsonl only contains 2 cases
    _write_jsonl(
        s1 / "report.jsonl",
        [
            _call(f"{source}::test_verify[c0]", "passed"),
            _call(f"{source}::test_verify[c1]", "passed"),
        ],
    )
    (s1 / "selection.json").write_text(json.dumps(sel.to_dict(), indent=2), encoding="utf-8")
    # results.json missing

    warnings: list[str] = []
    from pkcs11_check.core.merge import _load_shard_payload

    payload = _load_shard_payload(s1, warnings)
    assert payload is not None
    # Selection must contain all 5 planned nodeids from selection.json, NOT just the 2 observed
    assert payload["selection"]["nodeids"] == list(nodeids)
    assert payload["selection"]["batch_id"] == sel.batch_id
    assert payload["units"][0]["selection_batch_id"] == sel.batch_id


def test_lost_shard_with_only_selection_json_aborts_on_conflicting_plan_id(
    tmp_path: Path,
) -> None:
    source = "wycheproof/test_wycheproof_ecdsa.py"
    nodeids1 = (f"{source}::test_verify[c1]",)
    batch_id1 = compute_batch_id(
        source=source,
        source_collection_count=1,
        source_collection_sha256="a" * 64,
        nodeids=nodeids1,
    )
    sel1 = CaseSelection(
        schema=1,
        plan_id="1" * 64,
        batch_id=batch_id1,
        source=source,
        source_collection_count=1,
        source_collection_sha256="a" * 64,
        nodeids=nodeids1,
    )
    nodeids2 = (f"{source}::test_verify[c2]",)
    batch_id2 = compute_batch_id(
        source=source,
        source_collection_count=1,
        source_collection_sha256="a" * 64,
        nodeids=nodeids2,
    )
    sel2 = CaseSelection(
        schema=1,
        plan_id="2" * 64,  # Conflicting plan ID!
        batch_id=batch_id2,
        source=source,
        source_collection_count=1,
        source_collection_sha256="a" * 64,
        nodeids=nodeids2,
    )

    s0 = _make_shard(
        tmp_path, "shard-0", results=True, jsonl=[_call(f"{source}::test_verify[c1]", "passed")]
    )
    (s0 / "selection.json").write_text(json.dumps(sel1.to_dict(), indent=2), encoding="utf-8")
    payload0 = json.loads((s0 / "results.json").read_text(encoding="utf-8"))
    payload0["selection"] = sel1.to_dict()
    payload0["units"][0]["selection_batch_id"] = sel1.batch_id
    (s0 / "results.json").write_text(json.dumps(payload0), encoding="utf-8")

    # Shard 1 has ONLY selection.json (lost shard)
    s1 = tmp_path / "shard-1"
    s1.mkdir()
    (s1 / "selection.json").write_text(json.dumps(sel2.to_dict(), indent=2), encoding="utf-8")

    out = tmp_path / "out"
    with pytest.raises(ValueError, match="conflicting selection plan IDs"):
        merge_shard_dirs([s0, s1], out)

    # Output directory must not have report.jsonl written
    assert not (out / "report.jsonl").exists()


def test_lost_shard_with_only_selection_json_aborts_on_duplicate_batch_id(
    tmp_path: Path,
) -> None:
    source = "wycheproof/test_wycheproof_ecdsa.py"
    nodeids = (f"{source}::test_verify[c1]",)
    batch_id = compute_batch_id(
        source=source,
        source_collection_count=1,
        source_collection_sha256="a" * 64,
        nodeids=nodeids,
    )
    sel = CaseSelection(
        schema=1,
        plan_id="1" * 64,
        batch_id=batch_id,
        source=source,
        source_collection_count=1,
        source_collection_sha256="a" * 64,
        nodeids=nodeids,
    )

    s0 = _make_shard(
        tmp_path, "shard-0", results=True, jsonl=[_call(f"{source}::test_verify[c1]", "passed")]
    )
    (s0 / "selection.json").write_text(json.dumps(sel.to_dict(), indent=2), encoding="utf-8")
    payload0 = json.loads((s0 / "results.json").read_text(encoding="utf-8"))
    payload0["selection"] = sel.to_dict()
    payload0["units"][0]["selection_batch_id"] = sel.batch_id
    (s0 / "results.json").write_text(json.dumps(payload0), encoding="utf-8")

    # Shard 1 has ONLY selection.json with the EXACT SAME batch_id (duplicate!)
    s1 = tmp_path / "shard-1"
    s1.mkdir()
    (s1 / "selection.json").write_text(json.dumps(sel.to_dict(), indent=2), encoding="utf-8")

    out = tmp_path / "out"
    with pytest.raises(ValueError, match="duplicate selection batch ID"):
        merge_shard_dirs([s0, s1], out)

    assert not (out / "report.jsonl").exists()


def _selection_for(
    source: str, nodeids: tuple[str, ...], *, plan_id: str = "b" * 64
) -> CaseSelection:
    batch_id = compute_batch_id(
        source=source,
        source_collection_count=len(nodeids),
        source_collection_sha256="a" * 64,
        nodeids=nodeids,
    )
    return CaseSelection(
        schema=1,
        plan_id=plan_id,
        batch_id=batch_id,
        source=source,
        source_collection_count=len(nodeids),
        source_collection_sha256="a" * 64,
        nodeids=nodeids,
    )


def test_intact_results_without_selection_block_is_a_selection_integrity_error(
    tmp_path: Path,
) -> None:
    """State (b): an intact results.json must prove batch membership itself.

    The framework emits the top-level ``selection`` block whenever
    ``--selection-manifest`` was honored. An intact, non-salvaged payload that
    lacks it is proof the manifest never reached the child: that run executed
    the FULL source file, not the assigned slice. Stamping it from the sidecar
    would forge the membership evidence the promotion gate relies on.
    """
    source = "wycheproof/test_wycheproof_ecdsa.py"
    sel = _selection_for(source, (f"{source}::test_verify[c1]", f"{source}::test_verify[c2]"))

    s0 = tmp_path / "shard-0"
    s0.mkdir()
    _write_jsonl(s0 / "report.jsonl", [_call(f"{source}::test_verify[c1]", "passed")])
    (s0 / "selection.json").write_text(json.dumps(sel.to_dict(), indent=2), encoding="utf-8")
    # results.json is intact and complete, but carries NO selection block.
    (s0 / "results.json").write_text(json.dumps(_ok_results(source)), encoding="utf-8")

    out = tmp_path / "out"
    with pytest.raises(ValueError, match="no selection block"):
        merge_shard_dirs([s0], out)

    # Validation happens before any output write.
    assert not (out / "report.jsonl").exists()
    assert not (out / "results.json").exists()


def test_intact_results_without_selection_block_and_without_sidecar_still_merges(
    tmp_path: Path,
) -> None:
    """An ordinary (unbatched) shard is untouched: no sidecar, no stamping, no error."""
    s0 = _make_shard(
        tmp_path, "shard-0", results=True, jsonl=[_call("test_ok.py::test_pass", "passed")]
    )

    merged = merge_shard_dirs([s0], tmp_path / "out")

    assert merged["summary"]["passed"] == 1
    assert "selection_batch_id" not in merged["units"][0]


def test_partial_salvaged_results_recover_selection_from_sidecar(tmp_path: Path) -> None:
    """A salvaged payload (``partial`` marker) keeps sidecar recovery and stays incomplete.

    ``docker/optee-pkcs11/salvage-artifacts.py`` reconstructs a results.json from
    state.json when the guest died before the final report; that payload parses
    as an object but legitimately has no ``selection`` block, while the CLI wrote
    the sidecar before execution. This is salvage, not a missing manifest.
    """
    source = "wycheproof/test_wycheproof_ecdsa.py"
    sel = _selection_for(source, (f"{source}::test_verify[c1]", f"{source}::test_verify[c2]"))

    s0 = tmp_path / "shard-0"
    s0.mkdir()
    _write_jsonl(s0 / "report.jsonl", [_call(f"{source}::test_verify[c1]", "passed")])
    (s0 / "selection.json").write_text(json.dumps(sel.to_dict(), indent=2), encoding="utf-8")
    payload = _ok_results(source)
    payload["partial"] = {
        "reason": "OP-TEE guest runner exited before final report generation",
        "completed_units": 1,
        "planned_units": 2,
    }
    (s0 / "results.json").write_text(json.dumps(payload), encoding="utf-8")

    merged = merge_shard_dirs([s0], tmp_path / "out")

    assert merged["summary"]["incomplete"] is True
    unit = next(u for u in merged["units"] if u["target"] == source)
    assert unit["selection_batch_id"] == sel.batch_id
    warnings = merged.get("shards", {}).get("warnings", [])
    assert any("partial" in w and "1/2" in w for w in warnings), warnings
    assert any("unproven" in w for w in warnings), warnings


def test_salvaged_selection_recovery_is_warned_as_unproven(tmp_path: Path) -> None:
    """State (c): crash salvage keeps the recovery, but never claims it is proof."""
    source = "wycheproof/test_wycheproof_ecdsa.py"
    sel = _selection_for(source, (f"{source}::test_verify[c1]", f"{source}::test_verify[c2]"))

    s0 = tmp_path / "shard-0"
    s0.mkdir()
    _write_jsonl(s0 / "report.jsonl", [_call(f"{source}::test_verify[c1]", "passed")])
    (s0 / "selection.json").write_text(json.dumps(sel.to_dict(), indent=2), encoding="utf-8")
    (s0 / "results.json").write_text('{"summary": {"failed": 1, ', encoding="utf-8")  # corrupt

    merged = merge_shard_dirs([s0], tmp_path / "out")

    assert merged["summary"]["incomplete"] is True
    unit = next(u for u in merged["units"] if u["target"] == source)
    assert unit["selection_batch_id"] == sel.batch_id
    warnings = merged.get("shards", {}).get("warnings", [])
    assert any("unproven" in w for w in warnings), warnings


def test_sidecar_only_shard_keeps_synthetic_incomplete_payload(tmp_path: Path) -> None:
    """State (d): no results.json and no report.jsonl, sidecar only."""
    source = "wycheproof/test_wycheproof_ecdsa.py"
    sel = _selection_for(source, (f"{source}::test_verify[c1]",))

    s0 = _make_shard(
        tmp_path, "shard-0", results=True, jsonl=[_call("test_ok.py::test_pass", "passed")]
    )
    s1 = tmp_path / "shard-1"
    s1.mkdir()
    (s1 / "selection.json").write_text(json.dumps(sel.to_dict(), indent=2), encoding="utf-8")

    merged = merge_shard_dirs([s0, s1], tmp_path / "out")

    assert merged["summary"]["incomplete"] is True
    warnings = merged.get("shards", {}).get("warnings", [])
    assert any("LOST" in w for w in warnings), warnings
    assert any("unproven" in w for w in warnings), warnings
    assert all(u["target"] != source for u in merged["units"])


def test_salvage_recovery_leaves_daemon_recovery_units_unstamped(tmp_path: Path) -> None:
    """The sidecar-recovery path also honors the ``::daemon-recovery-`` skip.

    Recovery stamping overwrites, so this is the one stamping path that would
    silently annotate a synthetic daemon-death unit if the skip were dropped.
    """
    source = "wycheproof/test_wycheproof_ecdsa.py"
    sel = _selection_for(source, (f"{source}::test_verify[c1]",))

    s0 = tmp_path / "shard-0"
    s0.mkdir()
    _write_jsonl(s0 / "report.jsonl", [_call(f"{source}::test_verify[c1]", "passed")])
    (s0 / "selection.json").write_text(json.dumps(sel.to_dict(), indent=2), encoding="utf-8")
    payload = _ok_results(source)
    payload["units"] = [
        {"target": source, "status": "passed", "returncode": 0, "duration_s": 0.1},
        {"target": f"{source}::daemon-recovery-1", "status": "crashed", "returncode": 1},
    ]
    payload["partial"] = {
        "reason": "guest runner exited before final report generation",
        "completed_units": 1,
        "planned_units": 2,
    }
    (s0 / "results.json").write_text(json.dumps(payload), encoding="utf-8")

    merged = merge_shard_dirs([s0], tmp_path / "out")

    real_unit = next(u for u in merged["units"] if u["target"] == source)
    recovery_unit = next(u for u in merged["units"] if u["target"].endswith("daemon-recovery-1"))
    assert real_unit["selection_batch_id"] == sel.batch_id
    assert "selection_batch_id" not in recovery_unit


def test_sidecar_recovery_refuses_to_overwrite_a_conflicting_batch_id() -> None:
    """Pin the fail-closed strictening on the overwriting (salvage) stamping path.

    The pre-refactor JSONL-salvage path assigned ``selection_batch_id``
    unconditionally; it now raises when a unit already carries a *different*
    truthy batch id. This is unreachable in production today because
    ``postprocess_jsonl_to_unified`` never emits ``selection_batch_id`` (only the
    intact-payload writer does), so the behavior is pinned at the helper. It must
    stay fail-closed: silently rewriting a foreign batch identity would forge
    exactly the membership evidence this module refuses to invent.
    """
    from pkcs11_check.core.merge import _stamp_selection_batch_id

    units = [{"target": "test_x.py", "selection_batch_id": "9" * 64}]
    with pytest.raises(ValueError, match="unit selection_batch_id .* does not match"):
        _stamp_selection_batch_id(
            units,
            "a" * 64,
            conflict_label="sidecar batch_id",
            shard_name="shard-0",
            overwrite=True,
        )
    assert units[0]["selection_batch_id"] == "9" * 64

    # An identical value is not a conflict, and an unstamped unit is filled in.
    same = [{"target": "test_x.py", "selection_batch_id": "a" * 64}, {"target": "test_y.py"}]
    _stamp_selection_batch_id(
        same,
        "a" * 64,
        conflict_label="sidecar batch_id",
        shard_name="shard-0",
        overwrite=True,
    )
    assert [u["selection_batch_id"] for u in same] == ["a" * 64, "a" * 64]
