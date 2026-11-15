"""Tests for the run-level call_counters block in results.json (fw#73 Task 5).

Covers the threewriter paths (isolated, none, merge): the new
``call_counters`` payload key, its absence when the JSONL carries no counters
data, the split→merge round-trip exactness, and the ``PKCS11_CHECK_ISOLATION``
environment plumbing for unit children.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

from pkcs11_check.core._jsonl_extract import extract_call_counters_from_jsonl
from pkcs11_check.core.call_counters import ISOLATION_ENV
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
        "by_bucket": {
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
    expected = extract_call_counters_from_jsonl(out / "report.jsonl")
    assert expected is not None
    assert merged["call_counters"] == expected
    assert merged["call_counters"]["total_calls"] == 15
    assert merged["call_counters"]["complete"] is True


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
        lambda module, *, interface, slot, timeout, output_path: (
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
