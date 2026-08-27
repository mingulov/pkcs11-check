"""Wiring tests for crashing-daemon recovery in the file_runner between-unit hook.

The controller's policy is covered exhaustively in test_recovery.py; these cover the runner-side
glue: building the controller from pytest_args, and feeding completed results to it with a
never-silent banner and an abort signal.
"""

from __future__ import annotations

from io import StringIO
from types import SimpleNamespace

from rich.console import Console

from pkcs11_check.core._run_units import FileRunResult
from pkcs11_check.core.file_runner import (
    _apply_recovery_between_units,
    _build_recovery_controller,
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
