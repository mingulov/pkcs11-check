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
