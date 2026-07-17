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
