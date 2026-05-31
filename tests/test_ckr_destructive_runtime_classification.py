"""Runtime classification meta-tests for ckr/test_ckr_destructive (Phase 4 N2).

These destructive C_InitToken/C_SetPIN/C_InitPIN error-condition probes run in a
subprocess child script against a temporary SoftHSM2 token. Previously the spec
CKR was asserted *inside* the child script, so a non-spec clean reject crashed
the child (rc != 0) and was mislabeled as a "Crash" by the parent. The negative
classification now happens in the parent via ``_classify_destructive_ckr`` over
the printed ``CKR:0x...`` line, giving a 3-way result:

- ``CKR_OK`` (the forbidden/invalid op was accepted) -> ``fail``,
- the spec CKR -> ``pass``,
- any other clean reject code -> ``xfail``.
"""

from __future__ import annotations

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKR_FUNCTION_FAILED,
    CKR_OK,
    CKR_PIN_INCORRECT,
)
from pkcs11_check.testcases.ckr import test_ckr_destructive as tcd


def test_destructive_accepted_fails() -> None:
    out = f"CKR:0x{int(CKR_OK):08x}\nOK"
    with pytest.raises(Failed) as ei:
        tcd._classify_destructive_ckr(out, (CKR_PIN_INCORRECT,), label="x")
    assert not isinstance(ei.value, XFailed)


def test_destructive_spec_passes() -> None:
    out = f"CKR:0x{int(CKR_PIN_INCORRECT):08x}\nOK"
    tcd._classify_destructive_ckr(out, (CKR_PIN_INCORRECT,), label="x")


def test_destructive_other_reject_xfails() -> None:
    out = f"CKR:0x{int(CKR_FUNCTION_FAILED):08x}\nOK"
    with pytest.raises(pytest.xfail.Exception):
        tcd._classify_destructive_ckr(out, (CKR_PIN_INCORRECT,), label="x")
