"""Tests for the run-level call_counters block in results.json (fw#73 Task 5).

Covers the threewriter paths (isolated, none, merge): the new
``call_counters`` payload key, its absence when the JSONL carries no counters
data, the split→merge round-trip exactness, and the ``PKCS11_CHECK_ISOLATION``
environment plumbing for unit children.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

from pkcs11_check.core._jsonl_extract import extract_call_counters_from_jsonl
from pkcs11_check.core.call_counters import ISOLATION_ENV, RUN_ID_ENV
from pkcs11_check.core.file_runner import (
    FileRunState,
    _subprocess_plugin_env,
    postprocess_jsonl_to_unified,
    run_isolated_pytest_units,
    write_isolated_json_report,
)
from pkcs11_check.core.merge import merge_results_payloads, merge_shard_dirs


def _counters_block(total: int = 10) -> dict[str, Any]:
    return {
        "complete": True,
        "total_calls": total,
        "by_module": {
            "total_calls": total,
            "by_module": {
                "": {
                    "calls": total,
                    "buckets": {
                        "test": {
                            "calls": total,
                            "by_fn": {
                                "C_Sign": {
                                    "calls": total,
                                    "by_rv": {"0": {"name": "CKR_OK", "count": total}},
                                }
                            },
                        }
                    },
                }
            },
        },
        "probes_lost": 0,
        "by_process": [{"pid": 100, "isolation": "file", "total_calls": total, "complete": True}],
    }


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> Path:
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    return path


def _session_record(pid: int, total: int) -> dict[str, Any]:
    return {
        "$report_type": "CallCountersReport",
        "pid": pid,
        "isolation": "none",
        "probes_lost": 0,
        "total_calls": total,
        "buckets": {
            "test": {
                "calls": total,
                "by_fn": {
                    "C_Sign": {"calls": total, "by_rv": {"0": {"name": "CKR_OK", "count": total}}}
                },
            }
        },
    }


def _round_session_record(pid: int, total: int, run_id: str) -> dict[str, Any]:
    record = _session_record(pid, total)
    record["run_id"] = run_id
    return record


def _write_shard(
    d: Path,
    units: list[dict[str, Any]],
    summary: dict[str, int],
    records: list[dict[str, Any]],
) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / "results.json").write_text(
        json.dumps(
            {"tool": "pkcs11-check", "kind": "test-run", "summary": summary, "units": units}
        ),
        encoding="utf-8",
    )
    (d / "report.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in records), encoding="utf-8"
    )


def test_write_isolated_json_report_embeds_call_counters(tmp_path: Path) -> None:
    state = FileRunState(units=[], fingerprint="", results=[])
    payload = write_isolated_json_report(
        tmp_path / "results.json", state, call_counters=_counters_block()
    )
    assert payload["call_counters"]["total_calls"] == 10
    on_disk = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    assert on_disk["call_counters"]["complete"] is True


def test_write_isolated_json_report_omits_key_when_absent(tmp_path: Path) -> None:
    state = FileRunState(units=[], fingerprint="", results=[])
    assert "call_counters" not in write_isolated_json_report(tmp_path / "a.json", state)
    assert "call_counters" not in write_isolated_json_report(
        tmp_path / "b.json", state, call_counters=None
    )


def test_postprocess_embeds_call_counters_from_jsonl(tmp_path: Path) -> None:
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            {"$report_type": "SessionStart"},
            {
                "$report_type": "TestReport",
                "nodeid": "a.py::t1",
                "when": "call",
                "outcome": "passed",
                "duration": 0.1,
            },
            _session_record(100, 10),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    payload = postprocess_jsonl_to_unified(jsonl, tmp_path / "results.json")
    assert payload["call_counters"]["total_calls"] == 10
    assert payload["call_counters"]["complete"] is True
    on_disk = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    assert on_disk["call_counters"]["by_process"][0]["pid"] == 100


def test_postprocess_omits_key_for_old_jsonl(tmp_path: Path) -> None:
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            {"$report_type": "SessionStart"},
            {
                "$report_type": "TestReport",
                "nodeid": "a.py::t1",
                "when": "call",
                "outcome": "passed",
                "duration": 0.1,
            },
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    payload = postprocess_jsonl_to_unified(jsonl, tmp_path / "results.json")
    assert "call_counters" not in payload


def test_merge_results_payloads_embeds_call_counters(tmp_path: Path) -> None:
    del tmp_path
    payload = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": {"passed": 1},
        "units": [{"target": "a.py", "status": "passed"}],
    }
    merged = merge_results_payloads([payload], coverage=None, call_counters=_counters_block(7))
    assert merged["call_counters"]["total_calls"] == 7
    # Backward compat: the old two-argument call shape is unchanged.
    legacy = merge_results_payloads([payload], coverage=None)
    assert "call_counters" not in legacy


def test_merge_shard_dirs_recomputes_call_counters_exactly(tmp_path: Path) -> None:
    s0 = tmp_path / "shard0"
    s1 = tmp_path / "shard1"
    _write_shard(
        s0,
        units=[{"target": "a.py", "status": "passed"}],
        summary={"passed": 1, "failed": 0},
        records=[
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "a.py", "attempt": 0},
            _session_record(100, 10),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    _write_shard(
        s1,
        units=[{"target": "b.py", "status": "passed"}],
        summary={"passed": 1, "failed": 0},
        records=[
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "b.py", "attempt": 0},
            _session_record(200, 5),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    out = tmp_path / "merged"
    merged = merge_shard_dirs([s0, s1], out)
    # C3b: merged from the per-shard extracts (fresh provenance per shard),
    # never from the concatenated stream -- so by_process rows carry the
    # shard they came from and the block is NOT extract(merged_report).
    block = merged["call_counters"]
    assert block["total_calls"] == 15
    assert block["complete"] is True
    assert block["probes_lost"] == 0
    assert block["by_process"] == [
        {
            "pid": 100,
            "isolation": "none",
            "total_calls": 10,
            "complete": True,
            "shard": "shard0",
        },
        {
            "pid": 200,
            "isolation": "none",
            "total_calls": 5,
            "complete": True,
            "shard": "shard1",
        },
    ]
    assert block["by_module"]["total_calls"] == 15
    assert block["by_module"]["by_module"][""]["buckets"]["test"]["calls"] == 15


def test_merge_shard_dirs_omits_key_without_counters_data(tmp_path: Path) -> None:
    s0 = tmp_path / "shard0"
    _write_shard(
        s0,
        units=[{"target": "a.py", "status": "passed"}],
        summary={"passed": 1, "failed": 0},
        records=[
            {"$report_type": "SessionStart"},
            {
                "$report_type": "TestReport",
                "nodeid": "a.py::t1",
                "when": "call",
                "outcome": "passed",
                "duration": 0.1,
            },
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    merged = merge_shard_dirs([s0], tmp_path / "merged")
    assert "call_counters" not in merged


def test_postprocess_embeds_unattributed_segments(tmp_path: Path) -> None:
    jsonl = _write_jsonl(
        tmp_path / "report.jsonl",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "a.py", "attempt": 0},
            _round_session_record(100, 10, _MR1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "b.py", "attempt": 0},
            {
                "$report_type": "TestReport",
                "nodeid": "b.py::t1",
                "when": "call",
                "outcome": "passed",
                "duration": 0.1,
            },
        ],
    )
    payload = postprocess_jsonl_to_unified(jsonl, tmp_path / "results.json")
    assert payload["call_counters"]["complete"] is False
    assert payload["call_counters"]["unattributed_segments"] == [
        {"scope_index": 2, "unit": "b.py", "attempt": 0}
    ]
    assert "" not in payload["call_counters"]["by_round"]
    on_disk = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    assert on_disk["call_counters"]["unattributed_segments"] == [
        {"scope_index": 2, "unit": "b.py", "attempt": 0}
    ]


def test_merge_shard_dirs_concatenates_segments_with_shard_tags(tmp_path: Path) -> None:
    s0 = tmp_path / "shard0"
    s1 = tmp_path / "shard1"
    for shard, unit in ((s0, "a.py"), (s1, "b.py")):
        _write_shard(
            shard,
            units=[{"target": unit, "status": "passed"}],
            summary={"passed": 1, "failed": 0},
            records=[
                {"$report_type": "SessionStart"},
                {"$report_type": "IsolatedUnitReport", "target": unit, "attempt": 0},
                _session_record(100, 10),
                {"$report_type": "SessionFinish", "exitstatus": 0},
                {"$report_type": "SessionStart"},
                {"$report_type": "IsolatedUnitReport", "target": "zzz.py", "attempt": 0},
                {
                    "$report_type": "TestReport",
                    "nodeid": "zzz.py::t1",
                    "when": "call",
                    "outcome": "passed",
                    "duration": 0.1,
                },
            ],
        )
    merged = merge_shard_dirs([s0, s1], tmp_path / "merged")
    block = merged["call_counters"]
    # Totals conserved; segments (shard-local scopes) concatenate tagged.
    assert block["total_calls"] == 20
    assert block["complete"] is False
    assert block["unattributed_segments"] == [
        {"scope_index": 2, "unit": "zzz.py", "attempt": 0, "shard": "shard0"},
        {"scope_index": 2, "unit": "zzz.py", "attempt": 0, "shard": "shard1"},
    ]
    # Merge-order independence: reversed input yields identical segments.
    flipped = merge_shard_dirs([s1, s0], tmp_path / "merged-rev")
    assert flipped["call_counters"]["unattributed_segments"] == block["unattributed_segments"]


def test_merge_single_shard_segments_carry_no_shard_tag(tmp_path: Path) -> None:
    s0 = tmp_path / "shard0"
    _write_shard(
        s0,
        units=[{"target": "a.py", "status": "passed"}],
        summary={"passed": 1, "failed": 0},
        records=[
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "a.py", "attempt": 0},
            {
                "$report_type": "TestReport",
                "nodeid": "a.py::t1",
                "when": "call",
                "outcome": "passed",
                "duration": 0.1,
            },
        ],
    )
    merged = merge_shard_dirs([s0], tmp_path / "merged")
    block = merged["call_counters"]
    assert block["total_calls"] == 0
    assert block["complete"] is False
    assert block["unattributed_segments"] == [{"scope_index": 1, "unit": "a.py", "attempt": 0}]


def test_subprocess_plugin_env_sets_isolation_value() -> None:
    env = _subprocess_plugin_env({}, "test_anything.py", isolation="file")
    assert env["PKCS11_CHECK_UNIT_CHILD"] == "1"
    assert env[ISOLATION_ENV] == "file"


def test_subprocess_plugin_env_omits_isolation_when_not_given() -> None:
    env = _subprocess_plugin_env({"FOO": "bar"}, "test_anything.py")
    assert ISOLATION_ENV not in env
    assert env["PKCS11_CHECK_UNIT_CHILD"] == "1"


def test_subprocess_plugin_env_preserves_preset_isolation() -> None:
    env = _subprocess_plugin_env({ISOLATION_ENV: "test"}, "test_anything.py")
    assert env[ISOLATION_ENV] == "test"


def test_run_isolated_excludes_seeded_isolation_from_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Resume state predating fw#73 carries no ISOLATION key: reseeding it must
    # not invalidate the fingerprint (else every upgrade breaks --resume).
    from pkcs11_check.core._run_state import build_state_fingerprint, save_run_state
    from pkcs11_check.core.file_runner import FileRunResult

    units = ["a.py"]
    clean_env = {k: v for k, v in os.environ.items() if k != ISOLATION_ENV}
    fingerprint = build_state_fingerprint(units, [], clean_env)
    state_file = tmp_path / "state.json"
    save_run_state(
        state_file,
        FileRunState(
            units=units,
            fingerprint=fingerprint,
            results=[FileRunResult(target="a.py", status="passed", returncode=0, duration_s=0.0)],
        ),
    )
    monkeypatch.setenv(ISOLATION_ENV, "file")
    # Raises ValueError ("belongs to a different isolated run") if the seeded
    # key leaks into the fingerprint computation.
    exit_code = run_isolated_pytest_units(
        units,
        [],
        timeout=60,
        state_file=state_file,
        policy_file=None,
        report_config=None,
        resume=True,
        stop_on_failure=False,
        console=Console(),
    )
    assert isinstance(exit_code, int)


def test_isolated_path_seeds_isolation_env_for_unit_children(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # End-to-end pin of the test_cmd -> file_runner env bridge: the --isolation
    # flag value is visible to run_isolated_pytest_units via os.environ.
    from pkcs11_check.cli import test_cmd
    from pkcs11_check.cli.app import app
    from pkcs11_check.core.preflight import CapabilityManifest
    from tests._plain_cli_runner import PlainCliRunner

    module = tmp_path / "dummy.so"
    module.write_text("", encoding="utf-8")
    seen: dict[str, object] = {}

    def fake_run(
        units: list[str],
        pytest_args: list[str],
        *,
        timeout: int,
        state_file: Path,
        policy_file: Path | None,
        report_config: object | None,
        resume: bool,
        stop_on_failure: bool,
        console: object,
        granularity: str,
        max_crashes_per_file: int,
        deselect_by_file: dict[str, set[str]] | None = None,
        baseline_fingerprint: str | None = None,
        provenance: object = None,
        recovery_config: object = None,
        counters_barrier_plan: object = None,
    ) -> int:
        del (
            units,
            pytest_args,
            timeout,
            state_file,
            policy_file,
            report_config,
            resume,
            stop_on_failure,
            console,
            granularity,
            max_crashes_per_file,
            deselect_by_file,
            baseline_fingerprint,
            provenance,
            recovery_config,
        )
        seen["isolation"] = os.environ.get(ISOLATION_ENV)
        return 0

    monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)
    monkeypatch.setattr(
        test_cmd,
        "discover_pytest_units",
        lambda targets, default_root, *, granularity, pytest_args: [
            str(default_root / "test_alpha.py")
        ],
    )
    monkeypatch.setattr(
        test_cmd,
        "run_preflight_subprocess",
        lambda module, *, interface, slot, timeout, output_path, counters=None: (
            output_path.write_text("{}", encoding="utf-8"),
            CapabilityManifest(
                status="ok",
                module_path=str(module),
                requested_interface=interface,
                interface_version="3.2",
                slot_index=slot,
                slot_count=1,
                mechanisms=[],
            ),
        )[1],
    )
    monkeypatch.delenv(ISOLATION_ENV, raising=False)
    try:
        result = PlainCliRunner().invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                "--isolation",
                "file",
                "--ignore-disabled-tests",
            ],
        )
        # Restore bookkeeping: the seeded value must not leak into the caller.
        seen["leaked"] = os.environ.get(ISOLATION_ENV)
    finally:
        os.environ.pop(ISOLATION_ENV, None)
    assert result.exit_code == 0
    assert seen["isolation"] == "file"
    assert seen["leaked"] is None


def test_crash_limit_rewrite_stays_resumable_with_seeded_isolation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Fix round 1 (Critical): the mid-run crash-limit rewrite goes through
    # _refresh_state_plan with the runner base env (isolation key restored), so
    # the saved fingerprint must exclude the key exactly like the start-of-run
    # fingerprint does -- else the run becomes unresumable (ValueError).
    from pkcs11_check.core._escalation import _limit_remaining_units_for_file
    from pkcs11_check.core._run_state import save_run_state
    from pkcs11_check.core.file_runner import FileRunResult

    units = ["a.py::t1", "a.py::t2", "a.py::t3"]
    state = FileRunState(
        units=list(units),
        fingerprint="",
        results=[
            FileRunResult(target="a.py::t1", status="crashed", returncode=-11, duration_s=1.0)
        ],
    )
    runner_env = dict(os.environ)
    runner_env[ISOLATION_ENV] = "file"
    pending = ["a.py::t2", "a.py::t3"]
    limited = _limit_remaining_units_for_file(
        unit="a.py::t1",
        units=list(units),
        index=0,
        pending_units=pending,
        state=state,
        pytest_args=[],
        env=runner_env,
        console=Console(),
        max_crashes_per_file=1,
    )
    assert limited == ["a.py::t2", "a.py::t3"]
    state_file = tmp_path / "state.json"
    save_run_state(state_file, state)

    monkeypatch.setenv(ISOLATION_ENV, "file")
    # Raises ValueError ("belongs to a different isolated run") if the rewrite
    # admitted the key while the resume-time fingerprint excludes it.
    exit_code = run_isolated_pytest_units(
        units,
        [],
        timeout=60,
        state_file=state_file,
        policy_file=None,
        report_config=None,
        resume=True,
        stop_on_failure=False,
        console=Console(),
    )
    assert isinstance(exit_code, int)


def test_promotion_written_with_seeded_isolation_loads_without_it(tmp_path: Path) -> None:
    # Fix round 1 (Important): the policy WRITE path runs with the seeded key
    # while the READ path (discovery, pre-seed) runs without it; the key must
    # be ignored on both so a promotion is found on the next run.
    from pkcs11_check.core._escalation import _promote_crashing_unit
    from pkcs11_check.core._unit_discovery import load_promoted_files
    from pkcs11_check.core.file_runner import normalize_policy_file_key

    policy_file = tmp_path / "policy.json"
    runner_env = dict(os.environ)
    runner_env[ISOLATION_ENV] = "file"
    _promote_crashing_unit(policy_file, [], runner_env, "a.py", "file", "crashed", Console())
    reader_env = {k: v for k, v in os.environ.items() if k != ISOLATION_ENV}
    assert normalize_policy_file_key("a.py") in load_promoted_files(policy_file, [], reader_env)


# --- Codex R1 fix round (C3): per-shard merge commutativity ---


def _entry_report(nodeid: str, pid: int, total: int) -> dict[str, Any]:
    """One teardown TestReport carrying a per-test counters entry."""
    return {
        "$report_type": "TestReport",
        "nodeid": nodeid,
        "when": "teardown",
        "outcome": "passed",
        "duration": 0.1,
        "user_properties": [
            [
                "pkcs11_call_counters",
                {
                    "pid": pid,
                    "total_calls": total,
                    "buckets": {
                        "test": {
                            "calls": total,
                            "by_fn": {
                                "C_Sign": {
                                    "calls": total,
                                    "by_rv": {"0": {"name": "CKR_OK", "count": total}},
                                }
                            },
                        }
                    },
                },
            ]
        ],
    }


def test_merge_shard_order_reversed_with_pid_collision_and_truncation(
    tmp_path: Path,
) -> None:
    # C3 (codex counterexample): shard A ends under marker (a.py, 0) with pid
    # 100's session total of 10; head-truncated shard B holds only an
    # UNMARKED pid-100 delta of 5 (its marker was cut off with the head).
    # Concatenated extraction leaks A's marker into B (order-dependent loss);
    # per-shard extraction reconciles each shard in fresh state, so both
    # merge orders yield the identical block.
    shard_a = tmp_path / "shardA"
    shard_b = tmp_path / "shardB"
    _write_shard(
        shard_a,
        units=[{"target": "a.py", "status": "passed"}],
        summary={"passed": 1, "failed": 0},
        records=[
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "a.py", "attempt": 0},
            _session_record(100, 10),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    _write_shard(
        shard_b,
        units=[{"target": "b.py", "status": "passed"}],
        summary={"passed": 1, "failed": 0},
        records=[_entry_report("b.py::t1", 100, 5)],
    )
    block_a = extract_call_counters_from_jsonl(shard_a / "report.jsonl")
    block_b = extract_call_counters_from_jsonl(shard_b / "report.jsonl")
    assert block_a is not None and block_a["total_calls"] == 10
    assert block_a["complete"] is True
    assert block_b is not None and block_b["total_calls"] == 5
    assert block_b["complete"] is False
    merged_ab = merge_shard_dirs([shard_a, shard_b], tmp_path / "merged_ab")
    merged_ba = merge_shard_dirs([shard_b, shard_a], tmp_path / "merged_ba")
    assert merged_ab["call_counters"] == merged_ba["call_counters"]
    # Byte-identical across merge orders (no sort_keys: key-insertion order
    # must match too, not just the content).
    assert json.dumps(merged_ab["call_counters"]) == json.dumps(merged_ba["call_counters"])
    block = merged_ab["call_counters"]
    assert block["total_calls"] == 15
    assert block["complete"] is False
    assert block["by_process"] == [
        {
            "pid": 100,
            "isolation": "none",
            "total_calls": 10,
            "complete": True,
            "shard": "shardA",
        },
        {
            "pid": 100,
            "isolation": "unknown",
            "total_calls": 5,
            "complete": False,
            "shard": "shardB",
        },
    ]


# --- Per-round (run_id) dimension: merge namespacing ---

_MR1 = "20261115T120000000000Z-p100"
_MR2 = "20261115T130000000000Z-p200"


def _round_shard(
    d: Path,
    target: str,
    records: list[dict[str, Any]],
    *,
    passed: int = 1,
) -> None:
    _write_shard(
        d,
        units=[{"target": target, "status": "passed"}],
        summary={"passed": passed, "failed": 0},
        records=records,
    )


def test_merge_namespaces_same_run_id_across_shards(tmp_path: Path) -> None:
    # CI-matrix same-second same-pid collisions must not fuse: identical
    # run_ids on two shards merge under shard-namespaced by_round keys.
    shard_a = tmp_path / "shardA"
    shard_b = tmp_path / "shardB"
    _round_shard(
        shard_a,
        "a.py",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "a.py", "attempt": 0},
            _round_session_record(100, 10, _MR1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    _round_shard(
        shard_b,
        "b.py",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "b.py", "attempt": 0},
            _round_session_record(100, 5, _MR1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    merged_ab = merge_shard_dirs([shard_a, shard_b], tmp_path / "merged_ab")
    merged_ba = merge_shard_dirs([shard_b, shard_a], tmp_path / "merged_ba")
    assert merged_ab["call_counters"] == merged_ba["call_counters"]
    block = merged_ab["call_counters"]
    assert block["total_calls"] == 15
    assert block["complete"] is True
    assert sorted(block["by_round"]) == [f"shardA/{_MR1}", f"shardB/{_MR1}"]
    assert block["by_round"][f"shardA/{_MR1}"]["total_calls"] == 10
    assert block["by_round"][f"shardB/{_MR1}"]["total_calls"] == 5
    # One distinct round across rows: rows disambiguate by shard alone.
    assert block["by_process"] == [
        {"pid": 100, "isolation": "none", "total_calls": 10, "complete": True, "shard": "shardA"},
        {"pid": 100, "isolation": "none", "total_calls": 5, "complete": True, "shard": "shardB"},
    ]


def test_merge_rows_carry_round_and_shard_for_distinct_rounds(
    tmp_path: Path,
) -> None:
    shard_a = tmp_path / "shardA"
    shard_b = tmp_path / "shardB"
    _round_shard(
        shard_a,
        "a.py",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "a.py", "attempt": 0},
            _round_session_record(100, 10, _MR1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    _round_shard(
        shard_b,
        "b.py",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "b.py", "attempt": 0},
            _round_session_record(200, 5, _MR2),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    block = merge_shard_dirs([shard_a, shard_b], tmp_path / "merged")["call_counters"]
    assert block["total_calls"] == 15
    assert sorted(block["by_round"]) == [f"shardA/{_MR1}", f"shardB/{_MR2}"]
    assert block["by_process"] == [
        {
            "pid": 100,
            "isolation": "none",
            "total_calls": 10,
            "complete": True,
            "round": _MR1,
            "shard": "shardA",
        },
        {
            "pid": 200,
            "isolation": "none",
            "total_calls": 5,
            "complete": True,
            "round": _MR2,
            "shard": "shardB",
        },
    ]


def test_merge_single_shard_single_round_matches_extract_shape(
    tmp_path: Path,
) -> None:
    # Conditional keys: one shard + one round reads exactly like a single
    # extract (no shard/round keys on rows); only by_round namespacing is new.
    shard_a = tmp_path / "shardA"
    _round_shard(
        shard_a,
        "a.py",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "a.py", "attempt": 0},
            _round_session_record(100, 10, _MR1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    block = merge_shard_dirs([shard_a], tmp_path / "merged")["call_counters"]
    assert block["total_calls"] == 10
    assert block["by_process"] == [
        {"pid": 100, "isolation": "none", "total_calls": 10, "complete": True}
    ]
    assert list(block["by_round"]) == [f"shardA/{_MR1}"]
    assert block["by_round"][f"shardA/{_MR1}"]["total_calls"] == 10


def test_merge_multi_round_shard_keeps_rounds_split(tmp_path: Path) -> None:
    # A resumed shard (two rounds) merged with a second shard: three
    # namespaced rounds, rows sorted by (shard, round, pid).
    shard_a = tmp_path / "shardA"
    shard_b = tmp_path / "shardB"
    _round_shard(
        shard_a,
        "a.py",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "a.py", "attempt": 0},
            _round_session_record(100, 10, _MR1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "c.py", "attempt": 0},
            _round_session_record(100, 4, _MR2),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
        passed=2,
    )
    _round_shard(
        shard_b,
        "b.py",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "b.py", "attempt": 0},
            _round_session_record(200, 5, _MR2),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    merged_ab = merge_shard_dirs([shard_a, shard_b], tmp_path / "merged_ab")
    merged_ba = merge_shard_dirs([shard_b, shard_a], tmp_path / "merged_ba")
    assert merged_ab["call_counters"] == merged_ba["call_counters"]
    block = merged_ab["call_counters"]
    assert block["total_calls"] == 19
    assert sorted(block["by_round"]) == [
        f"shardA/{_MR1}",
        f"shardA/{_MR2}",
        f"shardB/{_MR2}",
    ]
    assert block["by_process"] == [
        {
            "pid": 100,
            "isolation": "none",
            "total_calls": 10,
            "complete": True,
            "round": _MR1,
            "shard": "shardA",
        },
        {
            "pid": 100,
            "isolation": "none",
            "total_calls": 4,
            "complete": True,
            "round": _MR2,
            "shard": "shardA",
        },
        {
            "pid": 200,
            "isolation": "none",
            "total_calls": 5,
            "complete": True,
            "round": _MR2,
            "shard": "shardB",
        },
    ]


def test_merge_attributes_untagged_rows_to_round_with_rows(tmp_path: Path) -> None:
    # I1: a shard with an attributed round R1 (rows) plus a C2 segment (no
    # round) emits untagged rows; on merge they belong to R1, and the
    # segment concatenates with its shard tag.
    shard_a = tmp_path / "shardA"
    shard_b = tmp_path / "shardB"
    _round_shard(
        shard_a,
        "a.py",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "a.py", "attempt": 0},
            _round_session_record(100, 10, _MR1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "c.py", "attempt": 0},
            {
                "$report_type": "TestReport",
                "nodeid": "c.py::t1",
                "when": "call",
                "outcome": "passed",
                "duration": 0.1,
            },
        ],
        passed=2,
    )
    _round_shard(
        shard_b,
        "b.py",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "b.py", "attempt": 0},
            _round_session_record(200, 5, _MR2),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    # Premise: the C2 shard emits one round plus one segment, yet untagged
    # rows (the conditional tag counts distinct rounds among ROWS).
    degenerate = extract_call_counters_from_jsonl(shard_a / "report.jsonl")
    assert degenerate is not None
    assert sorted(degenerate["by_round"]) == [_MR1]
    assert degenerate["unattributed_segments"] == [{"scope_index": 2, "unit": "c.py", "attempt": 0}]
    assert degenerate["by_process"] == [
        {"pid": 100, "isolation": "none", "total_calls": 10, "complete": True}
    ]
    block = merge_shard_dirs([shard_a, shard_b], tmp_path / "merged")["call_counters"]
    assert block["total_calls"] == 15
    assert block["complete"] is False  # the C2 segment is incomplete
    assert sorted(block["by_round"]) == [f"shardA/{_MR1}", f"shardB/{_MR2}"]
    assert block["unattributed_segments"] == [
        {"scope_index": 2, "unit": "c.py", "attempt": 0, "shard": "shardA"}
    ]
    assert block["by_process"] == [
        {
            "pid": 100,
            "isolation": "none",
            "total_calls": 10,
            "complete": True,
            "round": _MR1,
            "shard": "shardA",
        },
        {
            "pid": 200,
            "isolation": "none",
            "total_calls": 5,
            "complete": True,
            "round": _MR2,
            "shard": "shardB",
        },
    ]


def test_merge_legacy_degenerate_round_still_attributes_to_rows(tmp_path: Path) -> None:
    from pkcs11_check.core.merge import _merge_call_counter_blocks

    # I1 legacy: a pre-C shard block (pid-less C2-only "" round beside an
    # attributed round, untagged rows) still merges with its rows under
    # the round with rows -- old artifacts never misattribute to "".
    legacy = _counters_block(10)
    legacy["complete"] = False
    legacy["by_round"] = {
        "": {
            "complete": False,
            "total_calls": 0,
            "by_module": {"total_calls": 0, "by_module": {}},
            "probes_lost": 0,
            "by_process": [],
        },
        _MR1: {
            "complete": True,
            "total_calls": 10,
            "by_module": legacy["by_module"],
            "probes_lost": 0,
            "by_process": legacy["by_process"],
        },
    }
    other = _counters_block(5)
    other["by_process"][0]["pid"] = 200
    other["by_round"] = {
        _MR2: {
            "complete": True,
            "total_calls": 5,
            "by_module": other["by_module"],
            "probes_lost": 0,
            "by_process": other["by_process"],
        }
    }
    shard_a = tmp_path / "shardA"
    shard_b = tmp_path / "shardB"
    shard_a.mkdir()
    shard_b.mkdir()
    block = _merge_call_counter_blocks([(shard_a, legacy), (shard_b, other)])
    assert block is not None
    assert block["total_calls"] == 15
    assert block["complete"] is False
    assert sorted(block["by_round"]) == ["shardA/", f"shardA/{_MR1}", f"shardB/{_MR2}"]
    assert block["by_process"] == [
        {
            "pid": 100,
            "isolation": "file",
            "total_calls": 10,
            "complete": True,
            "round": _MR1,
            "shard": "shardA",
        },
        {
            "pid": 200,
            "isolation": "file",
            "total_calls": 5,
            "complete": True,
            "round": _MR2,
            "shard": "shardB",
        },
    ]


def _shard_label(shard_dir: Path) -> str:
    # Merge-side disambiguation contract: a colliding basename gains a
    # conditional @sha8(resolved-absolute-path) suffix (order-independent:
    # the suffix derives from the path, never from merge position).
    digest = hashlib.sha256(str(shard_dir.resolve()).encode("utf-8")).hexdigest()[:8]
    return f"{shard_dir.name}@{digest}"


def test_merge_duplicate_shard_basenames_disambiguate(tmp_path: Path) -> None:
    # M2 (codex R2): same shard dir basename + same round + same pid on two
    # shards must NOT fuse (one invocation's loss would contaminate the
    # other's round): colliding basenames gain a conditional @sha8 suffix,
    # rows stay attributable, and both merge orders are byte-identical.
    shard_a = tmp_path / "p1" / "shard"
    shard_b = tmp_path / "p2" / "shard"
    _round_shard(
        shard_a,
        "a.py",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "a.py", "attempt": 0},
            _round_session_record(100, 10, _MR1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    _round_shard(
        shard_b,
        "b.py",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "b.py", "attempt": 0},
            _round_session_record(100, 5, _MR1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    label_a = _shard_label(shard_a)
    label_b = _shard_label(shard_b)
    assert label_a != label_b
    merged_ab = merge_shard_dirs([shard_a, shard_b], tmp_path / "merged_ab")
    merged_ba = merge_shard_dirs([shard_b, shard_a], tmp_path / "merged_ba")
    assert merged_ab["call_counters"] == merged_ba["call_counters"]
    assert json.dumps(merged_ab["call_counters"]) == json.dumps(merged_ba["call_counters"])
    block = merged_ab["call_counters"]
    assert block["total_calls"] == 15
    assert block["complete"] is True
    assert list(block["by_round"]) == sorted([f"{label_a}/{_MR1}", f"{label_b}/{_MR1}"])
    assert block["by_round"][f"{label_a}/{_MR1}"]["total_calls"] == 10
    assert block["by_round"][f"{label_b}/{_MR1}"]["total_calls"] == 5
    # Per-round completeness stays independent: each round keeps its own
    # verdict instead of inheriting the other's.
    assert block["by_round"][f"{label_a}/{_MR1}"]["complete"] is True
    assert block["by_round"][f"{label_b}/{_MR1}"]["complete"] is True
    expected_rows = sorted(
        [
            {
                "pid": 100,
                "isolation": "none",
                "total_calls": 10,
                "complete": True,
                "shard": label_a,
            },
            {
                "pid": 100,
                "isolation": "none",
                "total_calls": 5,
                "complete": True,
                "shard": label_b,
            },
        ],
        key=lambda row: str(row["shard"]),
    )
    assert block["by_process"] == expected_rows


def test_merge_duplicate_basenames_distinct_rounds_stay_attributed(tmp_path: Path) -> None:
    # Duplicate basenames + distinct run_ids: distinct suffixed keys with
    # correct per-round attribution, both orders byte-identical.
    shard_a = tmp_path / "p1" / "shard"
    shard_b = tmp_path / "p2" / "shard"
    _round_shard(
        shard_a,
        "a.py",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "a.py", "attempt": 0},
            _round_session_record(100, 10, _MR1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    _round_shard(
        shard_b,
        "b.py",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "b.py", "attempt": 0},
            _round_session_record(200, 5, _MR2),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    label_a = _shard_label(shard_a)
    label_b = _shard_label(shard_b)
    merged_ab = merge_shard_dirs([shard_a, shard_b], tmp_path / "merged_ab")
    merged_ba = merge_shard_dirs([shard_b, shard_a], tmp_path / "merged_ba")
    assert json.dumps(merged_ab["call_counters"]) == json.dumps(merged_ba["call_counters"])
    block = merged_ab["call_counters"]
    assert list(block["by_round"]) == sorted([f"{label_a}/{_MR1}", f"{label_b}/{_MR2}"])
    assert block["by_round"][f"{label_a}/{_MR1}"]["total_calls"] == 10
    assert block["by_round"][f"{label_b}/{_MR2}"]["total_calls"] == 5
    rows = {(row["shard"], row["round"]): row["total_calls"] for row in block["by_process"]}
    assert rows == {(label_a, _MR1): 10, (label_b, _MR2): 5}


def test_merge_unique_basenames_keep_plain_keys(tmp_path: Path) -> None:
    # The @sha8 suffix is conditional: unique basenames keep "{basename}/..."
    # keys (and untagged rows when nothing else forces tags).
    shard_a = tmp_path / "shardA"
    shard_b = tmp_path / "shardB"
    _round_shard(
        shard_a,
        "a.py",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "a.py", "attempt": 0},
            _round_session_record(100, 10, _MR1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    _round_shard(
        shard_b,
        "b.py",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "b.py", "attempt": 0},
            _round_session_record(200, 5, _MR1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    block = merge_shard_dirs([shard_a, shard_b], tmp_path / "merged")["call_counters"]
    assert list(block["by_round"]) == [f"shardA/{_MR1}", f"shardB/{_MR1}"]
    assert "@" not in json.dumps(block["by_round"])


# --- Per-round (run_id) dimension: generation, forwarding, fingerprints ---

_RUN_ID_RE = r"\d{8}T\d{12}Z-p\d+-[0-9a-f]{8}"


def test_new_run_id_format_and_pid_suffix() -> None:
    from pkcs11_check.cli.test_cmd import _new_run_id

    first = _new_run_id()
    second = _new_run_id()
    for value in (first, second):
        assert re.fullmatch(_RUN_ID_RE, value), value
        assert f"-p{os.getpid()}-" in value
    # Consecutive ids are strictly distinct: the uuid4hex8 nonce survives
    # coarse clock granularity (e.g. Windows) that used to fuse them.
    assert first != second
    # The readable prefix (UTC microseconds + pid) is preserved and still
    # sortable: lexicographic order matches creation order.
    assert first[:-9] <= second[:-9]


def test_new_run_id_frozen_clock_still_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    # A frozen wall clock (same timestamp twice) must still mint distinct
    # ids: the nonce, not the clock, carries uniqueness.
    from pkcs11_check.cli import test_cmd

    frozen = datetime(2026, 11, 15, 12, 0, 0, tzinfo=UTC)

    class _FrozenDateTime:
        @staticmethod
        def now(tz: Any = None) -> datetime:
            assert tz is UTC
            return frozen

    monkeypatch.setattr(test_cmd, "datetime", _FrozenDateTime)
    assert test_cmd._new_run_id() != test_cmd._new_run_id()


def test_new_run_id_rollback_clock_still_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    # Wall-clock rollback (NTP step, DST, manual set) must not fuse ids
    # either: backward-moving timestamps still mint distinct ids.
    from pkcs11_check.cli import test_cmd

    stamps = iter(
        [
            datetime(2026, 11, 15, 12, 0, 1, tzinfo=UTC),
            datetime(2026, 11, 15, 12, 0, 0, tzinfo=UTC),
        ]
    )

    class _RollbackDateTime:
        @staticmethod
        def now(tz: Any = None) -> datetime:
            assert tz is UTC
            return next(stamps)

    monkeypatch.setattr(test_cmd, "datetime", _RollbackDateTime)
    first = test_cmd._new_run_id()
    second = test_cmd._new_run_id()
    assert first != second
    for value in (first, second):
        assert re.fullmatch(_RUN_ID_RE, value), value


def test_subprocess_plugin_env_sets_run_id_value() -> None:
    env = _subprocess_plugin_env({}, "test_anything.py", run_id="20261115T120000Z-p1")
    assert env[RUN_ID_ENV] == "20261115T120000Z-p1"


def test_subprocess_plugin_env_omits_run_id_when_not_given() -> None:
    env = _subprocess_plugin_env({"FOO": "bar"}, "test_anything.py")
    assert RUN_ID_ENV not in env


def test_subprocess_plugin_env_preserves_preset_run_id() -> None:
    env = _subprocess_plugin_env({RUN_ID_ENV: "preset"}, "test_anything.py")
    assert env[RUN_ID_ENV] == "preset"


def test_state_fingerprint_ignores_run_id() -> None:
    from pkcs11_check.core._run_state import build_state_fingerprint

    base = {k: v for k, v in os.environ.items() if k != RUN_ID_ENV}
    probe_a = dict(base)
    probe_a[RUN_ID_ENV] = "20261115T120000000000Z-p100"
    probe_b = dict(base)
    probe_b[RUN_ID_ENV] = "20261115T130000000000Z-p200"
    first = build_state_fingerprint(["a.py"], [], base)
    assert build_state_fingerprint(["a.py"], [], probe_a) == first
    assert build_state_fingerprint(["a.py"], [], probe_b) == first


def test_policy_fingerprint_ignores_run_id() -> None:
    from pkcs11_check.core._run_state import build_policy_fingerprint

    base = {k: v for k, v in os.environ.items() if k != RUN_ID_ENV}
    probe_a = dict(base)
    probe_a[RUN_ID_ENV] = "20261115T120000000000Z-p100"
    probe_b = dict(base)
    probe_b[RUN_ID_ENV] = "20261115T130000000000Z-p200"
    first = build_policy_fingerprint([], base)
    assert build_policy_fingerprint([], probe_a) == first
    assert build_policy_fingerprint([], probe_b) == first


@pytest.mark.parametrize("saved_env", ["absent", "stale-round"])
def test_resume_across_run_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, saved_env: str
) -> None:
    # Mirror of the isolation resume test: state saved without the key
    # (pre-round artifact) or under an older round's id must resume under a
    # fresh run_id without ValueError.
    from pkcs11_check.core._run_state import build_state_fingerprint, save_run_state
    from pkcs11_check.core.file_runner import FileRunResult

    units = ["a.py"]
    clean_env = {k: v for k, v in os.environ.items() if k != RUN_ID_ENV}
    saved = dict(clean_env)
    if saved_env == "stale-round":
        saved[RUN_ID_ENV] = "20261115T120000000000Z-p100"
    fingerprint = build_state_fingerprint(units, [], saved)
    state_file = tmp_path / "state.json"
    save_run_state(
        state_file,
        FileRunState(
            units=units,
            fingerprint=fingerprint,
            results=[FileRunResult(target="a.py", status="passed", returncode=0, duration_s=0.0)],
        ),
    )
    monkeypatch.setenv(RUN_ID_ENV, "20261115T130000000000Z-p200")
    # Raises ValueError ("belongs to a different isolated run") if the fresh
    # id leaks into the fingerprint computation.
    exit_code = run_isolated_pytest_units(
        units,
        [],
        timeout=60,
        state_file=state_file,
        policy_file=None,
        report_config=None,
        resume=True,
        stop_on_failure=False,
        console=Console(),
    )
    assert isinstance(exit_code, int)


def _invoke_isolated_with_env_probes(
    monkeypatch: pytest.MonkeyPatch, module: Path, seen: dict[str, object]
) -> Any:
    """Invoke ``test --isolation file`` with fakes probing run_id visibility."""
    from pkcs11_check.cli import test_cmd
    from pkcs11_check.cli.app import app
    from pkcs11_check.core.preflight import CapabilityManifest
    from tests._plain_cli_runner import PlainCliRunner

    def fake_preflight(
        module_arg: Path,
        *,
        interface: str,
        slot: int,
        timeout: int,
        output_path: Path,
        counters: object = None,
    ) -> CapabilityManifest:
        del module_arg, interface, slot, timeout
        seen["preflight"] = os.environ.get(RUN_ID_ENV)
        seen["preflight_counters"] = counters
        output_path.write_text("{}", encoding="utf-8")
        return CapabilityManifest(
            status="ok",
            module_path="",
            requested_interface="auto",
            interface_version="3.2",
            slot_index=0,
            slot_count=1,
            mechanisms=[],
        )

    def fake_discover(
        targets: object, default_root: Path, *, granularity: str, pytest_args: object
    ) -> list[str]:
        del targets, granularity, pytest_args
        seen["discovery"] = os.environ.get(RUN_ID_ENV)
        return [str(default_root / "test_alpha.py")]

    def fake_run(
        units: list[str],
        pytest_args: list[str],
        *,
        timeout: int,
        state_file: Path,
        policy_file: Path | None,
        report_config: object | None,
        resume: bool,
        stop_on_failure: bool,
        console: object,
        granularity: str,
        max_crashes_per_file: int,
        deselect_by_file: dict[str, set[str]] | None = None,
        baseline_fingerprint: str | None = None,
        provenance: object = None,
        recovery_config: object = None,
        counters_barrier_plan: object = None,
    ) -> int:
        del (
            units,
            pytest_args,
            timeout,
            state_file,
            policy_file,
            report_config,
            resume,
            stop_on_failure,
            console,
            granularity,
            max_crashes_per_file,
            deselect_by_file,
            baseline_fingerprint,
            provenance,
            recovery_config,
        )
        seen["run"] = os.environ.get(RUN_ID_ENV)
        return 0

    monkeypatch.setattr(test_cmd, "run_preflight_subprocess", fake_preflight)
    monkeypatch.setattr(test_cmd, "discover_pytest_units", fake_discover)
    monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)
    return PlainCliRunner().invoke(
        app,
        [
            "test",
            "--module",
            str(module),
            "--isolation",
            "file",
            "--ignore-disabled-tests",
        ],
    )


def test_isolated_path_seeds_one_run_id_without_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pkcs11_check.cli import test_cmd

    module = tmp_path / "dummy.so"
    module.write_text("", encoding="utf-8")
    seen: dict[str, object] = {}
    calls = 0
    real_new_run_id = test_cmd._new_run_id

    def counting_new_run_id() -> str:
        nonlocal calls
        calls += 1
        return real_new_run_id()

    monkeypatch.setattr(test_cmd, "_new_run_id", counting_new_run_id)
    monkeypatch.delenv(RUN_ID_ENV, raising=False)
    try:
        result = _invoke_isolated_with_env_probes(monkeypatch, module, seen)
        seen["leaked"] = os.environ.get(RUN_ID_ENV)
    finally:
        os.environ.pop(RUN_ID_ENV, None)
    assert result.exit_code == 0
    assert calls == 1  # exactly one run_id per CLI invocation
    assert isinstance(seen["run"], str) and re.fullmatch(_RUN_ID_RE, seen["run"])
    assert seen["leaked"] is None


def test_isolated_path_stale_run_id_not_inherited_but_restored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pkcs11_check.core.preflight import PreflightCounters

    module = tmp_path / "dummy.so"
    module.write_text("", encoding="utf-8")
    seen: dict[str, object] = {}
    monkeypatch.setenv(RUN_ID_ENV, "STALE-RUN-ID")
    try:
        result = _invoke_isolated_with_env_probes(monkeypatch, module, seen)
        # Read before monkeypatch teardown: this is the CLI's own restore.
        seen["restored"] = os.environ.get(RUN_ID_ENV)
    finally:
        os.environ.pop(RUN_ID_ENV, None)
    assert result.exit_code == 0
    # One id seeded before preflight: census, collection, and unit children
    # all see the same fresh value, never the stale caller one.
    assert isinstance(seen["preflight"], str) and re.fullmatch(_RUN_ID_RE, seen["preflight"])
    assert seen["preflight"] != "STALE-RUN-ID"
    assert seen["discovery"] == seen["preflight"]
    assert isinstance(seen["run"], str) and re.fullmatch(_RUN_ID_RE, seen["run"])
    assert seen["run"] == seen["preflight"]
    # C1: the census is always counted (run-owned dir, no opt-in).
    assert isinstance(seen["preflight_counters"], PreflightCounters)
    assert seen["restored"] == "STALE-RUN-ID"


def test_none_path_seeds_run_id_and_restores(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pkcs11_check.cli import test_cmd
    from pkcs11_check.cli.app import app
    from pkcs11_check.core.preflight import CapabilityManifest, PreflightCounters
    from tests._plain_cli_runner import PlainCliRunner

    module = tmp_path / "dummy.so"
    module.write_text("", encoding="utf-8")
    seen: dict[str, object] = {}

    def fake_preflight(
        module_arg: Path,
        *,
        interface: str,
        slot: int,
        timeout: int,
        output_path: Path,
        counters: object = None,
    ) -> CapabilityManifest:
        del module_arg, interface, slot, timeout
        seen["preflight"] = os.environ.get(RUN_ID_ENV)
        seen["preflight_counters"] = counters
        output_path.write_text("{}", encoding="utf-8")
        return CapabilityManifest(
            status="ok",
            module_path="",
            requested_interface="auto",
            interface_version="3.2",
            slot_index=0,
            slot_count=1,
            mechanisms=[],
        )

    def fake_main(args: list[str]) -> int:
        seen["run"] = os.environ.get(RUN_ID_ENV)
        Path(args[args.index("--report-log") + 1]).write_text(
            '{"$report_type":"SessionStart"}\n{"$report_type":"SessionFinish","exitstatus":0}\n',
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(test_cmd, "run_preflight_subprocess", fake_preflight)
    monkeypatch.setattr("pkcs11_check.cli.test_cmd.pytest.main", fake_main)
    monkeypatch.setenv(RUN_ID_ENV, "STALE-RUN-ID")
    try:
        result = PlainCliRunner().invoke(
            app,
            [
                "test",
                "--module",
                str(module),
                "--isolation",
                "none",
                "--ignore-disabled-tests",
            ],
        )
        # Read before monkeypatch teardown: this is the CLI's own restore.
        seen["restored"] = os.environ.get(RUN_ID_ENV)
    finally:
        os.environ.pop(RUN_ID_ENV, None)
    assert result.exit_code == 0
    # One id seeded before preflight: census and the in-process run share it.
    assert isinstance(seen["preflight"], str) and re.fullmatch(_RUN_ID_RE, seen["preflight"])
    assert seen["preflight"] != "STALE-RUN-ID"
    assert isinstance(seen["run"], str) and re.fullmatch(_RUN_ID_RE, seen["run"])
    assert seen["run"] == seen["preflight"]
    # C1: the census is always counted (run-owned dir, no opt-in).
    assert isinstance(seen["preflight_counters"], PreflightCounters)
    assert seen["restored"] == "STALE-RUN-ID"


def _het_session_record(
    pid: int, bucket: str, fn: str, rv: str, rv_name: str, total: int, run_id: str
) -> dict[str, Any]:
    return {
        "$report_type": "CallCountersReport",
        "pid": pid,
        "isolation": "none",
        "probes_lost": 0,
        "total_calls": total,
        "run_id": run_id,
        "buckets": {
            bucket: {
                "calls": total,
                "by_fn": {
                    fn: {
                        "calls": total,
                        "by_rv": {rv: {"name": rv_name, "count": total}},
                    }
                },
            }
        },
    }


def test_merge_heterogeneous_counters_is_byte_identical(tmp_path: Path) -> None:
    # Byte-identity (codex R2): shards contributing DISTINCT buckets,
    # functions, and RVs merge to byte-identical output in both orders
    # (plain json.dumps, no sort_keys) -- homogeneous shapes cannot expose
    # first-insertion-order leaks through module-first merging.
    shard_a = tmp_path / "shardA"
    shard_b = tmp_path / "shardB"
    _round_shard(
        shard_a,
        "a.py",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "a.py", "attempt": 0},
            _het_session_record(100, "test", "C_Sign", "0", "CKR_OK", 10, _MR1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    _round_shard(
        shard_b,
        "b.py",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "b.py", "attempt": 0},
            _het_session_record(200, "module_init", "C_Initialize", "1", "CKR_CANCEL", 5, _MR1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    merged_ab = merge_shard_dirs([shard_a, shard_b], tmp_path / "merged_ab")
    merged_ba = merge_shard_dirs([shard_b, shard_a], tmp_path / "merged_ba")
    assert json.dumps(merged_ab["call_counters"]) == json.dumps(merged_ba["call_counters"])
    by_module = merged_ab["call_counters"]["by_module"]
    assert list(by_module["by_module"]) == [""]
    buckets = by_module["by_module"][""]["buckets"]
    assert list(buckets) == ["module_init", "test"]
    assert list(buckets["module_init"]["by_fn"]) == ["C_Initialize"]
    assert list(buckets["test"]["by_fn"]) == ["C_Sign"]
    round_buckets = merged_ab["call_counters"]["by_round"][f"shardA/{_MR1}"]["by_module"]
    assert list(round_buckets["by_module"][""]["buckets"]) == ["test"]


def test_merge_generated_label_collision_with_literal_gets_counter_suffix(
    tmp_path: Path,
) -> None:
    # Important R3: a generated `shard@h` must not collide with a literal
    # `shard@h` basename; final-label collisions resolve deterministically
    # with @2/@3, independent of CLI order.
    host_a = tmp_path / "hostA" / "shard"
    host_b = tmp_path / "hostB" / "shard"
    digest_a = hashlib.sha256(str(host_a.resolve()).encode("utf-8")).hexdigest()[:8]
    digest_b = hashlib.sha256(str(host_b.resolve()).encode("utf-8")).hexdigest()[:8]
    assert digest_a != digest_b
    host_c = tmp_path / "hostC" / f"shard@{digest_a}"
    _round_shard(
        host_a,
        "a.py",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "a.py", "attempt": 0},
            _round_session_record(100, 10, _MR1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    _round_shard(
        host_b,
        "b.py",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "b.py", "attempt": 0},
            _round_session_record(100, 5, _MR1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    _round_shard(
        host_c,
        "c.py",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "c.py", "attempt": 0},
            _round_session_record(100, 7, _MR1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    merged_abc = merge_shard_dirs([host_a, host_b, host_c], tmp_path / "merged_abc")
    merged_cba = merge_shard_dirs([host_c, host_b, host_a], tmp_path / "merged_cba")
    assert merged_abc["call_counters"] == merged_cba["call_counters"]
    assert json.dumps(merged_abc["call_counters"]) == json.dumps(merged_cba["call_counters"])
    block = merged_abc["call_counters"]
    assert block["total_calls"] == 22
    assert block["complete"] is True
    assert len(block["by_round"]) == 3
    assert sorted(b["total_calls"] for b in block["by_round"].values()) == [5, 7, 10]
    assert len(set(block["by_round"])) == 3
    assert any("@2" in key or "@3" in key for key in block["by_round"])


def test_merge_conflicting_rv_names_is_byte_identical(tmp_path: Path) -> None:
    # Important R3: hex vs symbolic names for the same vendor RV merge
    # deterministically (symbolic wins) in both shard orders.
    shard_a = tmp_path / "shardA"
    shard_b = tmp_path / "shardB"
    vendor_rv = str(0x80000001)
    _round_shard(
        shard_a,
        "a.py",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "a.py", "attempt": 0},
            _het_session_record(100, "test", "C_Sign", vendor_rv, "0x80000001", 10, _MR1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    _round_shard(
        shard_b,
        "b.py",
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "b.py", "attempt": 0},
            _het_session_record(200, "test", "C_Sign", vendor_rv, "CKR_VENDOR_FOO", 5, _MR1),
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    merged_ab = merge_shard_dirs([shard_a, shard_b], tmp_path / "merged_ab")
    merged_ba = merge_shard_dirs([shard_b, shard_a], tmp_path / "merged_ba")
    assert merged_ab["call_counters"] == merged_ba["call_counters"]
    assert json.dumps(merged_ab["call_counters"]) == json.dumps(merged_ba["call_counters"])
    leaf = merged_ab["call_counters"]["by_module"]["by_module"][""]["buckets"]["test"]["by_fn"][
        "C_Sign"
    ]["by_rv"][vendor_rv]
    assert leaf == {"name": "CKR_VENDOR_FOO", "count": 15}


# --- I5: same-shard snapshots must agree or refuse ---

_I5_X = "1" * 32
_I5_Y = "2" * 32
_I5_RUN = "20261116T120000000000Z-p100-i5"


def _i5_session(pid: int, total: int, uuid: str) -> dict[str, Any]:
    return {
        "$report_type": "CallCountersReport",
        "pid": pid,
        "isolation": "file",
        "probes_lost": 0,
        "run_id": _I5_RUN,
        "worker_uuid": uuid,
        "total_calls": total,
        "by_module": {
            "m": {
                "calls": total,
                "buckets": {
                    "test": {
                        "calls": total,
                        "by_fn": {
                            "C_Sign": {
                                "calls": total,
                                "by_rv": {"0": {"name": "CKR_OK", "count": total}},
                            }
                        },
                    }
                },
            }
        },
    }


def _i5_block(tmp_path: Path, name: str, *sessions: dict[str, Any]) -> dict[str, Any]:
    from pkcs11_check.core._jsonl_extract import extract_call_counters_from_jsonl

    jsonl = _write_jsonl(
        tmp_path / name,
        [
            {"$report_type": "SessionStart"},
            {"$report_type": "IsolatedUnitReport", "target": "a.py", "attempt": 0},
            *sessions,
            {"$report_type": "SessionFinish", "exitstatus": 0},
        ],
    )
    block = extract_call_counters_from_jsonl(jsonl)
    assert block is not None
    return block


def test_merge_same_shard_inconsistent_snapshots_rejected_both_orders(
    tmp_path: Path,
) -> None:
    from pkcs11_check.core.merge import _merge_call_counter_blocks

    one = _i5_block(tmp_path, "one.jsonl", _i5_session(100, 10, _I5_X))
    two = _i5_block(tmp_path, "two.jsonl", _i5_session(100, 10, _I5_X), _i5_session(200, 5, _I5_Y))
    shard = tmp_path / "shard"
    # One repeated identity plus one new one: a partially overlapping
    # aggregate must refuse loud, never silently fuse or double-count.
    with pytest.raises(ValueError, match="inconsistent"):
        _merge_call_counter_blocks([(shard, one), (shard, two)])
    with pytest.raises(ValueError, match="inconsistent"):
        _merge_call_counter_blocks([(shard, two), (shard, one)])


def test_merge_same_shard_identical_snapshot_still_fuses(tmp_path: Path) -> None:
    import copy

    from pkcs11_check.core.merge import _merge_call_counter_blocks

    one = _i5_block(tmp_path, "one.jsonl", _i5_session(100, 10, _I5_X))
    twin = copy.deepcopy(one)
    assert twin == one and twin is not one
    merged = _merge_call_counter_blocks([(tmp_path / "shard", one), (tmp_path / "shard", twin)])
    assert merged is not None
    assert merged["total_calls"] == 10
    assert merged["complete"] is True
    assert len(merged["by_process"]) == 1
    assert "lost_processes" not in merged
