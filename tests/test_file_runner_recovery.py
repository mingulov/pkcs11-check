"""Wiring tests for crashing-daemon recovery in the file_runner between-unit hook.

The controller's policy is covered exhaustively in test_recovery.py; these cover the runner-side
glue: building the controller from pytest_args, and feeding completed results to it with a
never-silent banner and an abort signal.
"""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console

from pkcs11_check.core._report_records import (
    _seed_missing_report_record_caches_from_jsonl,
    _write_report_jsonl_from_record_sources,
)
from pkcs11_check.core._report_writers import (
    _build_isolated_json_payload,
    write_isolated_junit_report,
)
from pkcs11_check.core._run_state import load_run_state, save_run_state
from pkcs11_check.core._run_units import FileRunResult, FileRunState
from pkcs11_check.core.file_runner import (
    _apply_recovery_between_units,
    _build_recovery_controller,
    _record_recovery_findings,
    _requeue_units_after_recovery,
)
from pkcs11_check.core.recovery import RecoveryConfig, RecoveryController


def _cfg(**kw) -> RecoveryConfig:
    base = dict(
        mode="wait",
        recover_cmd=None,
        wait_s=0.0,
        max_attempts=3,
        max_total=20,
        hint_rvs=frozenset({"CKR_DEVICE_REMOVED"}),
        consecutive_threshold=3,
        quarantine_after=2,
        cmd_timeout_s=30.0,
        probe_timeout_s=30.0,
    )
    base.update(kw)
    return RecoveryConfig(**base)


def _result(target: str, status: str) -> FileRunResult:
    return FileRunResult(target=target, status=status, returncode=1, duration_s=0.1)


def _console() -> Console:
    return Console(file=StringIO(), width=200, force_terminal=False)


def test_build_controller_off_returns_none() -> None:
    assert _build_recovery_controller(None, []) is None
    assert _build_recovery_controller(_cfg(mode="off"), ["--p11-module", "m.so"]) is None


def test_build_controller_enabled_returns_controller() -> None:
    ctrl = _build_recovery_controller(
        _cfg(mode="wait"), ["--p11-module", "m.so", "--p11-slot", "1"]
    )
    assert isinstance(ctrl, RecoveryController)


def test_apply_recovery_recovers_and_continues() -> None:
    console = _console()
    ctrl = RecoveryController(
        _cfg(consecutive_threshold=3),
        probe=iter([False, True]).__next__,  # dead on confirm, alive after recover
        recover=lambda: True,
    )
    results = [_result("a", "failed"), _result("b", "failed"), _result("c", "failed")]
    action = _apply_recovery_between_units(ctrl, results, console=console)
    out = console.file.getvalue()
    assert action.abort is False
    assert "DAEMON UNREACHABLE" in out
    assert "recovered" in out.lower()


def test_apply_recovery_aborts_when_unrecoverable() -> None:
    console = _console()
    ctrl = RecoveryController(
        _cfg(max_attempts=2),
        probe=lambda: False,  # never comes back
        recover=lambda: True,
    )
    action = _apply_recovery_between_units(ctrl, [_result("t", "crashed")], console=console)
    out = console.file.getvalue()
    assert action.abort is True
    assert "unrecoverable" in out.lower()


def test_apply_recovery_silent_on_healthy_run() -> None:
    console = _console()
    ctrl = RecoveryController(_cfg(), probe=lambda: True, recover=lambda: True)
    results = [_result("a", "passed"), _result("b", "passed"), _result("c", "passed")]
    action = _apply_recovery_between_units(ctrl, results, console=console)
    assert action.abort is False
    assert console.file.getvalue() == ""  # never-silent means noisy only on a real event


def test_probe_reconfirms_before_declaring_dead(monkeypatch) -> None:
    # A single failing probe (slow/timeout blip on a live-but-busy provider) must NOT be treated
    # as dead; the bound probe re-confirms once (M1). First False, reconfirm True -> alive.
    import pkcs11_check.core.file_runner as fr

    seq = iter([False, True])
    monkeypatch.setattr(fr, "probe_provider_liveness", lambda *a, **k: next(seq))
    ctrl = _build_recovery_controller(_cfg(mode="wait"), ["--p11-module", "m.so"])
    assert ctrl is not None
    assert ctrl._probe() is True


def test_probe_dead_when_both_probes_fail(monkeypatch) -> None:
    import pkcs11_check.core.file_runner as fr

    monkeypatch.setattr(fr, "probe_provider_liveness", lambda *a, **k: False)
    ctrl = _build_recovery_controller(_cfg(mode="wait"), ["--p11-module", "m.so"])
    assert ctrl is not None
    assert ctrl._probe() is False


# --------------------------------------------------------------------------------------
# Re-queue wiring (GH #5): the controller computed requeue_units, QUARANTINE and the
# synthetic crash record, and the runner read none of them. The unit that killed the
# daemon was never re-run, and the finding never reached report.jsonl.
# --------------------------------------------------------------------------------------


def _full_result(target: str, status: str, stderr: str = "") -> FileRunResult:
    return FileRunResult(target=target, status=status, returncode=1, duration_s=0.1, stderr=stderr)


def test_apply_recovery_returns_the_streak_to_requeue() -> None:
    console = _console()
    ctrl = RecoveryController(
        _cfg(consecutive_threshold=3),
        probe=iter([False, True]).__next__,
        recover=lambda: True,
    )
    results = [_result("a", "failed"), _result("b", "failed"), _result("c", "failed")]

    action = _apply_recovery_between_units(ctrl, results, console=console)

    assert action.abort is False
    assert action.requeue == ["a", "b", "c"], "units killed by the dead daemon must re-run"


def test_apply_recovery_surfaces_the_synthetic_crash_record() -> None:
    console = _console()
    ctrl = RecoveryController(
        _cfg(consecutive_threshold=3),
        probe=iter([False, True]).__next__,
        recover=lambda: True,
    )
    results = [_result("a", "failed"), _result("b", "failed"), _result("c", "failed")]

    action = _apply_recovery_between_units(ctrl, results, console=console)

    assert [r["reason"] for r in action.records] == ["crash"]
    assert action.records[0]["trigger_unit"] == "c"


def test_quarantined_unit_is_not_requeued() -> None:
    """A unit that reproducibly kills the daemon must stop being retried."""
    console = _console()
    ctrl = RecoveryController(
        _cfg(consecutive_threshold=1, quarantine_after=1),
        probe=iter([False, True, False, True]).__next__,
        recover=lambda: True,
    )
    _apply_recovery_between_units(ctrl, [_result("a", "crashed")], console=console)

    action = _apply_recovery_between_units(ctrl, [_result("a", "crashed")], console=console)

    assert action.requeue == [], "a quarantined unit must not be re-queued again"
    assert "uarantin" in console.file.getvalue()


def test_hint_rvs_are_scanned_from_the_unit_output() -> None:
    """The configured hint RVs were never read: the runner passed a hardcoded empty set.

    With the scan wired, a single CKR_DEVICE_REMOVED unit triggers the probe immediately
    instead of waiting for the consecutive-failure threshold.
    """
    console = _console()
    probes = iter([False, True])
    ctrl = RecoveryController(
        _cfg(consecutive_threshold=99),  # far above the single failure below
        probe=probes.__next__,
        recover=lambda: True,
    )
    results = [_full_result("a", "failed", stderr="Unexpected CK_RV CKR_DEVICE_REMOVED")]

    action = _apply_recovery_between_units(ctrl, results, console=console)

    assert action.requeue == ["a"], "hint RV did not trigger the liveness probe"


def test_requeue_rewinds_and_drops_the_false_failures() -> None:
    """The results recorded against a dead daemon are not the module's verdict."""
    units = ["a", "b", "c", "d"]
    pending: list[str] = ["d"]
    state = SimpleNamespace(
        results=[_full_result("a", "failed"), _full_result("b", "failed")],
        report_records_by_unit={"a": [{"reason": "crash"}]},
    )

    rewound = _requeue_units_after_recovery(
        ["a", "b"], units=units, index=2, pending_units=pending, state=state
    )

    assert rewound == 0, "must rewind to the earliest requeued unit"
    assert state.results == [], "stale failures from the dead daemon must be dropped"
    assert set(pending) >= {"a", "b"}
    assert state.report_records_by_unit == {}, "stale records must go with the stale results"


def test_requeue_ignores_units_that_never_ran() -> None:
    units = ["a", "b"]
    pending: list[str] = []
    state = SimpleNamespace(results=[], report_records_by_unit={})

    assert (
        _requeue_units_after_recovery(
            ["zzz"], units=units, index=1, pending_units=pending, state=state
        )
        is None
    )


def test_requeue_archives_records_and_process_evidence_before_deleting(
    tmp_path: Path,
) -> None:
    state_file = tmp_path / "state.json"
    cache_dir = state_file.parent / f".{state_file.name}.report-records"
    cache_dir.mkdir()
    from pkcs11_check.core._report_records import _report_record_cache_path

    cache_path = _report_record_cache_path(state_file, "a")
    cache_path.write_text(
        json.dumps({"$report_type": "TestReport", "outcome": "failed"}) + "\n",
        encoding="utf-8",
    )
    state = SimpleNamespace(
        results=[_full_result("a", "failed")],
        report_records_by_unit={},
        process_observations=[{"target": "a", "role": "unit", "termination": {"kind": "signal"}}],
        attempt_history=[],
    )

    _requeue_units_after_recovery(
        ["a"],
        units=["a"],
        index=0,
        pending_units=[],
        state=state,
        state_file=state_file,
        recovery_event={"event_id": 1, "trigger_unit": "a", "reason": "crash"},
    )

    assert state.attempt_history[0]["records"][0]["outcome"] == "failed"
    assert state.attempt_history[0]["process_observations"][0]["termination"]["kind"] == "signal"
    assert not state.results
    assert state.process_observations == []
    assert not cache_path.exists()
    wrappers = [
        json.loads(line)
        for line in state_file.with_name("state.json.recovery.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert wrappers[0]["$report_type"] == "RecoveryAttempt"
    assert wrappers[0]["attempt"]["reason"] == "daemon-recovery-requeue"


def test_requeue_history_is_history_only_for_generic_cascade() -> None:
    state = SimpleNamespace(
        results=[_full_result("a", "failed")],
        report_records_by_unit={},
        attempt_history=[],
        process_observations=[],
    )
    _requeue_units_after_recovery(
        ["a"],
        units=["a"],
        index=0,
        pending_units=[],
        state=state,
        recovery_event={"event_id": 1},
    )

    assert len(state.attempt_history) == 1
    assert state.attempt_history[0]["records"] == []


def test_repeated_requeues_append_attempt_numbers() -> None:
    state = SimpleNamespace(
        results=[_full_result("a", "failed")],
        report_records_by_unit={},
        attempt_history=[],
        process_observations=[],
    )
    kwargs = dict(units=["a"], index=0, pending_units=[], state=state)
    _requeue_units_after_recovery(["a"], recovery_event={"event_id": 1}, **kwargs)
    state.results.append(_full_result("a", "failed"))
    _requeue_units_after_recovery(["a"], recovery_event={"event_id": 2}, **kwargs)

    assert [item["attempt"] for item in state.attempt_history] == [1, 2]


def test_state_round_trip_preserves_attempt_history_and_legacy_state_loads(tmp_path: Path) -> None:
    state_file = tmp_path / "state.json"
    state = SimpleNamespace(
        units=["a"],
        fingerprint="fp",
        results=[],
        report_records_by_unit={},
        process_observations=[],
        process_observations_complete=True,
        attempt_history=[{"target": "a", "attempt": 1}],
        recovery_events=[{"event_id": 1, "trigger_unit": "a"}],
    )
    # FileRunState is intentionally used by save/load; SimpleNamespace keeps this test focused
    # on the serialized compatibility contract.
    from pkcs11_check.core._run_units import FileRunState

    save_run_state(state_file, FileRunState(**vars(state)))
    loaded = load_run_state(state_file)
    assert loaded is not None
    assert loaded.attempt_history == state.attempt_history
    assert loaded.recovery_events == state.recovery_events

    legacy = tmp_path / "legacy.json"
    legacy.write_text(
        json.dumps({"units": ["a"], "fingerprint": "fp", "results": []}), encoding="utf-8"
    )
    loaded_legacy = load_run_state(legacy)
    assert loaded_legacy is not None
    assert loaded_legacy.attempt_history == []
    assert loaded_legacy.recovery_events == []


def test_fresh_run_clears_recovery_attempt_sidecar(tmp_path: Path, monkeypatch) -> None:
    from pkcs11_check.core import file_runner as file_runner_mod

    target = tmp_path / "test_demo.py"
    target.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    state_file = tmp_path / "state.json"
    sidecar = state_file.with_name("state.json.recovery.jsonl")
    sidecar.write_text('{"$report_type":"RecoveryAttempt"}\n', encoding="utf-8")

    def fake_run(cmd, *, env=None, timeout=0):
        del env, timeout
        report_path = Path(cmd[cmd.index("--report-log") + 1])
        report_path.write_text(
            '{"$report_type":"SessionStart"}\n{"$report_type":"SessionFinish","exitstatus":0}\n',
            encoding="utf-8",
        )
        return (0, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    assert (
        file_runner_mod.run_isolated_pytest_units(
            [str(target)],
            ["--p11-module", str(tmp_path / "module.so")],
            timeout=10,
            state_file=state_file,
            policy_file=None,
            report_config=None,
            resume=False,
            stop_on_failure=False,
            console=_console(),
        )
        == 0
    )
    assert not sidecar.exists()


def test_recovery_event_is_one_synthetic_unit_and_one_junit_error(tmp_path: Path) -> None:
    state = FileRunState(
        units=["a"],
        fingerprint="fp",
        results=[FileRunResult("a", "passed", 0, 0.1)],
        recovery_events=[
            {
                "event_id": 1,
                "trigger_unit": "a",
                "reason": "crash",
                "label": "provider became unreachable",
            }
        ],
    )

    payload = _build_isolated_json_payload(
        state,
        per_unit_details={"a": {"counts": {"passed": 1}, "tests": []}},
    )
    recovery_units = [unit for unit in payload["units"] if "daemon-recovery" in unit["target"]]
    assert len(recovery_units) == 1
    assert payload["summary"]["crashed"] == 1
    assert payload["summary"]["crashed"] == sum(
        unit.get("counts", {}).get("crashed", 0) for unit in payload["units"]
    )

    junit_path = tmp_path / "results.xml"
    write_isolated_junit_report(junit_path, state)
    junit = junit_path.read_text(encoding="utf-8")
    assert junit.count('type="daemon-recovery"') == 1
    assert 'errors="1"' in junit


def test_recovery_attempt_wrappers_are_in_final_report_jsonl(tmp_path: Path) -> None:
    state_file = tmp_path / "state.json"
    output = tmp_path / "report.jsonl"
    attempts = [{"target": "a", "attempt": 1, "reason": "daemon-recovery-requeue"}]

    assert _write_report_jsonl_from_record_sources(
        state_file,
        units=["a"],
        inline_records_by_unit={},
        output_path=output,
        attempt_history=attempts,
    )
    records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert records == [
        {
            "$report_type": "RecoveryAttempt",
            "target": "a",
            "attempt": attempts[0],
        }
    ]


def test_terminal_result_is_assessed_and_requeued(monkeypatch, tmp_path: Path) -> None:
    from pkcs11_check.core import file_runner as file_runner_mod

    target = tmp_path / "test_demo.py"
    target.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    state_file = tmp_path / "state.json"
    calls: list[int] = []
    batches: list[list[str]] = []
    controller = RecoveryController(_cfg(), probe=lambda: True, recover=lambda: True)

    def fake_run(cmd, *, env=None, timeout=0):
        del cmd, env, timeout
        calls.append(1)
        return (1 if len(calls) == 1 else 0, "", "")

    def fake_apply(controller_arg, new_results, *, console):
        del console
        assert controller_arg is controller
        batches.append([result.status for result in new_results])
        if len(batches) == 1:
            event = {"trigger_unit": str(target), "reason": "crash"}
            return file_runner_mod._RecoveryAction(
                requeue=[str(target)],
                records=[event],
                requeue_events=[(event, [str(target)])],
            )
        return file_runner_mod._RecoveryAction()

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    monkeypatch.setattr(file_runner_mod, "_build_recovery_controller", lambda *args: controller)
    monkeypatch.setattr(file_runner_mod, "_apply_recovery_between_units", fake_apply)

    exit_code = file_runner_mod.run_isolated_pytest_units(
        [str(target)],
        ["--p11-module", str(tmp_path / "module.so")],
        timeout=10,
        state_file=state_file,
        policy_file=None,
        report_config=None,
        resume=False,
        stop_on_failure=False,
        console=_console(),
    )

    assert exit_code == 1
    assert len(calls) == 2
    assert batches == [["failed"], ["passed"]]


def test_recovery_event_is_saved_before_resume_and_emitted_once(tmp_path: Path) -> None:
    state_file = tmp_path / "state.json"
    state = FileRunState(units=["a"], fingerprint="fp", results=[])
    event = {"trigger_unit": "a", "reason": "crash", "label": "dead"}
    _record_recovery_findings(state, [event])
    save_run_state(state_file, state)

    resumed = load_run_state(state_file)
    assert resumed is not None
    output = tmp_path / "report.jsonl"
    assert _write_report_jsonl_from_record_sources(
        state_file,
        units=resumed.units,
        inline_records_by_unit={},
        output_path=output,
        attempt_history=resumed.attempt_history,
        recovery_events=resumed.recovery_events,
    )
    records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert [record["$report_type"] for record in records] == ["RecoveryEvent"]
    assert records[0]["event_id"] == 1


def test_resume_reconciles_fsynced_attempt_sidecar_after_interruption(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("PKCS11_CHECK_STATE_INLINE_RECORDS", "1")
    state_file = tmp_path / "state.json"
    target = "a"
    original = FileRunState(
        units=[target],
        fingerprint="fp",
        results=[_full_result(target, "failed")],
        report_records_by_unit={
            target: [
                {
                    "$report_type": "TestReport",
                    "nodeid": "a::test_failed",
                    "when": "call",
                    "outcome": "failed",
                }
            ]
        },
        process_observations=[{"target": target, "parent_nodeid": None}],
    )
    save_run_state(state_file, original)
    _requeue_units_after_recovery(
        [target],
        units=[target],
        index=0,
        pending_units=[],
        state=original,
        state_file=state_file,
        recovery_event={"event_id": 1, "trigger_unit": target},
    )
    # Simulate process death after the sidecar fsync and before the post-requeue state save.
    resumed = load_run_state(state_file)
    assert resumed is not None
    assert resumed.results == []
    assert len(resumed.attempt_history) == 1
    assert resumed.process_observations == []
    assert resumed.report_records_by_unit == {}
    assert len(resumed.recovery_events) == 1

    resumed.results.append(FileRunResult(target, "passed", 0, 0.1))
    save_run_state(state_file, resumed)
    retried = load_run_state(state_file)
    assert retried is not None
    assert len(retried.attempt_history) == 1
    assert retried.results[0].status == "passed"
    assert not state_file.with_name("state.json.recovery.jsonl").exists()


def test_malformed_recovery_sidecar_fails_closed(tmp_path: Path) -> None:
    state_file = tmp_path / "state.json"
    save_run_state(state_file, FileRunState(units=["a"], fingerprint="fp", results=[]))
    state_file.with_name("state.json.recovery.jsonl").write_text(
        '{"$report_type":"RecoveryAttempt"\n', encoding="utf-8"
    )

    import pytest

    with pytest.raises(ValueError, match="malformed recovery sidecar"):
        load_run_state(state_file)


def test_resume_cache_seed_does_not_duplicate_recovery_attempt_wrapper(tmp_path: Path) -> None:
    state_file = tmp_path / "state.json"
    source = tmp_path / "prior-report.jsonl"
    attempt = {"target": "a", "attempt": 1, "reason": "daemon-recovery-requeue"}
    source.write_text(
        json.dumps(
            {
                "$report_type": "TestReport",
                "nodeid": "a::test_ok",
                "when": "call",
                "outcome": "passed",
            }
        )
        + "\n"
        + json.dumps({"$report_type": "RecoveryAttempt", "target": "a", "attempt": attempt})
        + "\n",
        encoding="utf-8",
    )
    _seed_missing_report_record_caches_from_jsonl(
        state_file,
        source,
        candidate_targets={"a"},
    )
    output = tmp_path / "rewritten-report.jsonl"
    assert _write_report_jsonl_from_record_sources(
        state_file,
        units=["a"],
        inline_records_by_unit={},
        output_path=output,
        attempt_history=[attempt],
    )
    records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert [record["$report_type"] for record in records].count("RecoveryAttempt") == 1
