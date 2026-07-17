"""Unit tests for the crashing-daemon recovery policy (core/recovery.py).

The policy is injection-testable: probe/recover are callables the tests substitute, so the
full liveness-gated state machine is exercised without a real daemon.
"""

from __future__ import annotations

from pathlib import Path

import pkcs11_check.core.recovery as rec
from pkcs11_check.core.recovery import (
    RecoveryConfig,
    RecoveryController,
    RecoveryOutcome,
    probe_provider_liveness,
    run_recover_cmd,
)


def _cfg(**kw) -> RecoveryConfig:
    base = dict(
        mode="off",
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


class _FakeManifest:
    def __init__(self, status: str) -> None:
        self.status = status


def test_liveness_maps_preflight_status(monkeypatch) -> None:
    """Reachability probe: preflight status 'ok' -> live; crashed/error/timeout -> dead."""
    for status, expected in [
        ("ok", True),
        ("crashed", False),
        ("error", False),
        ("timeout", False),
    ]:
        monkeypatch.setattr(
            rec,
            "run_preflight_subprocess",
            lambda *a, status=status, **kw: _FakeManifest(status),
        )
        got = probe_provider_liveness(
            Path("m.so"), interface="C_GetFunctionList", slot=0, timeout=5
        )
        assert got is expected, f"status={status}"


def test_liveness_dead_when_preflight_raises(monkeypatch) -> None:
    def _boom(*a, **kw):
        raise OSError("no module")

    monkeypatch.setattr(rec, "run_preflight_subprocess", _boom)
    assert (
        probe_provider_liveness(Path("m.so"), interface="C_GetFunctionList", slot=0, timeout=5)
        is False
    )


def test_recover_cmd_is_no_shell(monkeypatch) -> None:
    seen: dict = {}

    class _Completed:
        returncode = 0

    def _fake_run(argv, **kw):
        seen["argv"] = argv
        seen["shell"] = kw.get("shell", False)
        return _Completed()

    monkeypatch.setattr(rec.subprocess, "run", _fake_run)
    assert run_recover_cmd(["systemctl", "restart", "x"], timeout=5) is True
    assert seen["argv"] == ["systemctl", "restart", "x"]
    assert seen["shell"] is False


def test_recover_cmd_false_on_nonzero_and_error(monkeypatch) -> None:
    class _Bad:
        returncode = 1

    monkeypatch.setattr(rec.subprocess, "run", lambda argv, **kw: _Bad())
    assert run_recover_cmd(["false"], timeout=5) is False

    def _timeout(argv, **kw):
        raise rec.subprocess.TimeoutExpired(cmd=argv, timeout=5)

    monkeypatch.setattr(rec.subprocess, "run", _timeout)
    assert run_recover_cmd(["sleep", "99"], timeout=5) is False


def test_feature_off_is_noop() -> None:
    probed: list[int] = []
    ctrl = RecoveryController(
        _cfg(mode="off"),
        probe=lambda: probed.append(1) or False,
        recover=lambda: False,
    )
    for _ in range(10):
        a = ctrl.assess("t.py", "failed", frozenset({"CKR_DEVICE_REMOVED"}))
        assert a.outcome is RecoveryOutcome.CONTINUE
    assert probed == []  # never probes when off


def _seq_probe(values):
    it = iter(values)
    return lambda: next(it)


def test_kryoptic_live_provider_never_recovers() -> None:
    # Consecutive DEVICE_ERROR failures on a LIVE provider (probe True) must never recover:
    # this is what protects kryoptic's normal DEVICE_ERROR/GENERAL_ERROR rejections.
    recovered: list[int] = []
    ctrl = RecoveryController(
        _cfg(mode="wait", consecutive_threshold=3),
        probe=lambda: True,
        recover=lambda: recovered.append(1) or True,
    )
    outs = [
        ctrl.assess("t.py", "failed", frozenset({"CKR_DEVICE_ERROR"})).outcome for _ in range(6)
    ]
    assert all(o is RecoveryOutcome.CONTINUE for o in outs)
    assert recovered == []


def test_counter_reset_on_passing_probe() -> None:
    probes: list[int] = []

    def _probe():
        probes.append(1)
        return True

    ctrl = RecoveryController(
        _cfg(mode="wait", consecutive_threshold=3), probe=_probe, recover=lambda: True
    )
    for _ in range(9):  # 9 failing units, healthy provider
        ctrl.assess("t.py", "failed", frozenset())
    assert len(probes) == 3  # once per fresh 3-streak, NOT once per failure past 3


def test_cascade_requeues_full_streak() -> None:
    ctrl = RecoveryController(
        _cfg(mode="wait", consecutive_threshold=3),
        probe=_seq_probe([False, True]),
        recover=lambda: True,
    )
    ctrl.assess("a", "failed", frozenset())
    ctrl.assess("b", "failed", frozenset())
    a = ctrl.assess("c", "failed", frozenset())
    assert a.outcome is RecoveryOutcome.RECOVERED_RETRY
    assert a.requeue_units == ["a", "b", "c"]


def test_passing_unit_breaks_streak() -> None:
    probes: list[int] = []
    ctrl = RecoveryController(
        _cfg(mode="wait", consecutive_threshold=3),
        probe=lambda: probes.append(1) or True,
        recover=lambda: True,
    )
    ctrl.assess("a", "failed", frozenset())
    ctrl.assess("b", "failed", frozenset())
    ctrl.assess("ok", "passed", frozenset())  # breaks the streak
    ctrl.assess("c", "failed", frozenset())  # streak restarts at 1
    assert probes == []  # never reached the threshold, so never probed


def test_recover_fails_to_max_attempts_aborts() -> None:
    calls: list[int] = []
    ctrl = RecoveryController(
        _cfg(mode="wait", max_attempts=3),
        probe=lambda: False,
        recover=lambda: calls.append(1) or True,
    )
    a = ctrl.assess("t.py", "failed", frozenset({"CKR_DEVICE_REMOVED"}))
    assert a.outcome is RecoveryOutcome.ABORT
    assert len(calls) == 3


def test_repeat_offender_quarantined_on_nth() -> None:
    ctrl = RecoveryController(
        _cfg(mode="wait", quarantine_after=2),
        probe=_seq_probe([False, True, False, True]),
        recover=lambda: True,
    )
    first = ctrl.assess("t.py", "crashed", frozenset())
    second = ctrl.assess("t.py", "crashed", frozenset())
    assert first.outcome is RecoveryOutcome.RECOVERED_RETRY
    assert second.outcome is RecoveryOutcome.QUARANTINE


def test_global_budget_aborts() -> None:
    ctrl = RecoveryController(
        _cfg(mode="wait", max_total=2, quarantine_after=99),
        probe=_seq_probe([False, True] * 100),
        recover=lambda: True,
    )
    outs = [
        ctrl.assess(f"u{i}", "failed", frozenset({"CKR_DEVICE_REMOVED"})).outcome for i in range(5)
    ]
    assert RecoveryOutcome.ABORT in outs


def test_dead_then_recover_retries() -> None:
    ctrl = RecoveryController(
        _cfg(mode="wait", max_attempts=5),
        probe=_seq_probe([False, False, True]),
        recover=lambda: True,
    )
    a = ctrl.assess("t.py", "failed", frozenset({"CKR_DEVICE_REMOVED"}))
    assert a.outcome is RecoveryOutcome.RECOVERED_RETRY


def test_event_finding_emitted_on_confirmed_death() -> None:
    ctrl = RecoveryController(
        _cfg(mode="wait"), probe=_seq_probe([False, True]), recover=lambda: True
    )
    a = ctrl.assess("t.py", "failed", frozenset({"CKR_DEVICE_REMOVED"}))
    assert any(
        r.get("reason") == "crash" and "unreachable" in r.get("label", "") for r in a.records
    )


def test_build_config_tokenizes_cmd_and_implies_cmd_mode() -> None:
    from pkcs11_check.core.recovery import build_recovery_config

    cfg = build_recovery_config(recover_cmd="systemctl restart softhsmd")
    assert cfg.recover_cmd == ["systemctl", "restart", "softhsmd"]
    assert cfg.mode == "cmd"  # --recover-cmd alone implies cmd


def test_build_config_defaults_off() -> None:
    from pkcs11_check.core.recovery import build_recovery_config

    cfg = build_recovery_config()
    assert cfg.mode == "off" and cfg.recover_cmd is None


def test_build_config_wait_mode_needs_no_cmd() -> None:
    from pkcs11_check.core.recovery import build_recovery_config

    cfg = build_recovery_config(mode="wait")
    assert cfg.mode == "wait" and cfg.recover_cmd is None


def test_build_config_cmd_mode_without_command_is_error() -> None:
    import pytest

    from pkcs11_check.core.recovery import build_recovery_config

    with pytest.raises(ValueError):
        build_recovery_config(mode="cmd")


def test_build_config_hint_rvs_parsed() -> None:
    from pkcs11_check.core.recovery import build_recovery_config

    cfg = build_recovery_config(mode="wait", hint_rv="CKR_DEVICE_REMOVED, CKR_DEVICE_ERROR")
    assert cfg.hint_rvs == frozenset({"CKR_DEVICE_REMOVED", "CKR_DEVICE_ERROR"})
