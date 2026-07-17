"""Wiring tests for crashing-daemon recovery in the file_runner between-unit hook.

The controller's policy is covered exhaustively in test_recovery.py; these cover the runner-side
glue: building the controller from pytest_args, and feeding completed results to it with a
never-silent banner and an abort signal.
"""

from __future__ import annotations

from io import StringIO
from types import SimpleNamespace

from rich.console import Console

from pkcs11_check.core.file_runner import (
    _apply_recovery_between_units,
    _build_recovery_controller,
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


def _result(target: str, status: str) -> SimpleNamespace:
    return SimpleNamespace(target=target, status=status)


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
    abort = _apply_recovery_between_units(ctrl, results, console=console)
    out = console.file.getvalue()
    assert abort is False
    assert "DAEMON UNREACHABLE" in out
    assert "recovered" in out.lower()


def test_apply_recovery_aborts_when_unrecoverable() -> None:
    console = _console()
    ctrl = RecoveryController(
        _cfg(max_attempts=2),
        probe=lambda: False,  # never comes back
        recover=lambda: True,
    )
    abort = _apply_recovery_between_units(ctrl, [_result("t", "crashed")], console=console)
    out = console.file.getvalue()
    assert abort is True
    assert "unrecoverable" in out.lower()


def test_apply_recovery_silent_on_healthy_run() -> None:
    console = _console()
    ctrl = RecoveryController(_cfg(), probe=lambda: True, recover=lambda: True)
    results = [_result("a", "passed"), _result("b", "passed"), _result("c", "passed")]
    abort = _apply_recovery_between_units(ctrl, results, console=console)
    assert abort is False
    assert console.file.getvalue() == ""  # never-silent means noisy only on a real event
