"""Unit tests for the crashing-daemon recovery policy (core/recovery.py).

The policy is injection-testable: probe/recover are callables the tests substitute, so the
full liveness-gated state machine is exercised without a real daemon.
"""

from __future__ import annotations

from pkcs11_check.core.recovery import (
    RecoveryConfig,
    RecoveryController,
    RecoveryOutcome,
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
