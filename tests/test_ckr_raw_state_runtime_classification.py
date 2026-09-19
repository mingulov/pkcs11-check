"""Runtime classification meta-tests for ckr/test_ckr_raw_state (Phase 4 N2).

Double-Init / cross-operation state probes: a second C_*Init while one is active
may legitimately return CKR_OPERATION_ACTIVE *or* CKR_OK (the module may cancel
the first op and start a new one). Both are accepted passes; any *other* clean
code is a noted deviation. Previously the in-child ``assert rv2 in
(CKR_OPERATION_ACTIVE, CKR_OK)`` turned a third clean code into a false child
crash. Classification now happens in the parent via ``_classify_state_ckr``
(``allow_ok=True``):

- ``CKR_OK`` (module cancelled/restarted) -> ``pass``,
- ``CKR_OPERATION_ACTIVE`` (spec) -> ``pass``,
- any other clean code -> ``xfail`` (noted deviation, not a crash).
"""

from __future__ import annotations

from typing import Any

import pytest
from _pytest.outcomes import XFailed

from pkcs11_check.core.process_observation import drain_process_observations
from pkcs11_check.raw.types_std import (
    CKR_DEVICE_ERROR,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
)
from pkcs11_check.testcases.ckr import test_ckr_raw_state as trs


def _cfg() -> Any:
    return type("Cfg", (), {"module": "x", "pin": None})()


def _patch(monkeypatch: pytest.MonkeyPatch, rv: int) -> None:
    out = f"CKR:0x{int(rv):08x}\nOK"
    monkeypatch.setattr(trs, "_run_probe", lambda *_a, **_k: (0, out, ""))
    monkeypatch.setattr(trs, "_assert_probe_completed", lambda *_a, **_k: None)


def test_state_ok_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, int(CKR_OK))
    trs.TestOperationActive().test_double_encrypt_init(_cfg())


def test_state_operation_active_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, int(CKR_OPERATION_ACTIVE))
    trs.TestOperationActive().test_double_encrypt_init(_cfg())


def test_state_other_code_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, int(CKR_DEVICE_ERROR))
    with pytest.raises(XFailed):
        trs.TestOperationActive().test_double_encrypt_init(_cfg())


def test_cross_operation_passes_and_retains_child_ckr(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-003: survival still passes, but the child CKR is kept durably.

    RED proof: pre-fix the parent receives the ``CKR:0x...`` line and drops
    it -- no observation is recorded on a passing result.
    """
    _patch(monkeypatch, int(CKR_DEVICE_ERROR))
    trs.TestOperationActive().test_encrypt_then_sign_init(_cfg())  # must not raise
    retained = [o for o in drain_process_observations() if o.get("role") == "probe-ckr"]
    assert len(retained) == 1
    assert retained[0]["ckr"] == f"0x{int(CKR_DEVICE_ERROR):08x}"
    assert retained[0]["probe"] == "encrypt_then_sign_init"


def test_cross_operation_first_init_failed_records_no_ckr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No state-conflict outcome exists when the first init failed: pass, retain nothing."""
    monkeypatch.setattr(
        trs, "_run_probe", lambda *_a, **_k: (0, "CKR:0x00000007:first_init_failed\nOK", "")
    )
    monkeypatch.setattr(trs, "_assert_probe_completed", lambda *_a, **_k: None)
    trs.TestOperationActive().test_encrypt_then_sign_init(_cfg())
    assert drain_process_observations() == []
