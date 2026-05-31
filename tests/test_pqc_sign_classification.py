"""Classification meta-tests for test_pqc_sign ML-DSA sign leg (Phase 5 P1b).

The ML-DSA produce-leg guards previously ``pytest.xfail``-ed on *any*
AssertionError, hiding a non-CKR failure. They now xfail only on a known clean
reject CKR; a non-CKR error propagates.
"""

from __future__ import annotations

from typing import Any

import pytest
from _pytest.outcomes import XFailed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED
from pkcs11_check.testcases import test_pqc_sign as tps


class _RawSession:
    raw = object()
    sh = 1
    slot_id = 0

    @staticmethod
    def has_mechanism(_n: str) -> bool:
        return True


def _patch(monkeypatch: pytest.MonkeyPatch, *, sign_exc: BaseException) -> None:
    monkeypatch.setattr(tps, "_generate_ml_dsa_keypair", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(tps, "destroy_quietly", lambda *_a, **_k: None)

    def _raise(*_a: Any, **_k: Any) -> bytes:
        raise sign_exc

    monkeypatch.setattr(tps, "sign_single", _raise)


def test_ml_dsa_sign_clean_ckr_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    exc = CkrAssertionError("CKR_FUNCTION_NOT_SUPPORTED", int(CKR_FUNCTION_NOT_SUPPORTED))
    _patch(monkeypatch, sign_exc=exc)
    with pytest.raises(XFailed):
        tps.TestMLDSASignVerify().test_sign_and_verify(_RawSession())


def test_ml_dsa_sign_non_ckr_error_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, sign_exc=AssertionError("python decoder bug, no CKR"))
    with pytest.raises(AssertionError, match="decoder bug") as ei:
        tps.TestMLDSASignVerify().test_sign_and_verify(_RawSession())
    assert not isinstance(ei.value, XFailed)
