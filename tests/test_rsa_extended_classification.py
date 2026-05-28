"""Classification meta-tests for test_rsa_extended first-leg xfail (Phase 5 P1b).

The produce-leg guards used to ``pytest.xfail`` on *any* AssertionError, which
would hide a non-CKR Python failure. They now xfail only on a known clean
reject CKR; a non-CKR error propagates.
"""

from __future__ import annotations

from typing import Any

import pytest
from _pytest.outcomes import XFailed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED
from pkcs11_check.testcases import test_rsa_extended as tre


class _RawSession:
    raw = object()
    sh = 1
    slot_id = 0

    @staticmethod
    def has_mechanism(_n: str) -> bool:
        return True


def _patch(monkeypatch: pytest.MonkeyPatch, *, sign_exc: BaseException) -> None:
    monkeypatch.setattr(tre, "_rsa_keypair", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(tre, "destroy_quietly", lambda *_a, **_k: None)

    def _raise(*_a: Any, **_k: Any) -> bytes:
        raise sign_exc

    monkeypatch.setattr(tre, "sign_single", _raise)


def test_first_leg_clean_ckr_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    exc = CkrAssertionError("CKR_FUNCTION_NOT_SUPPORTED", int(CKR_FUNCTION_NOT_SUPPORTED))
    _patch(monkeypatch, sign_exc=exc)
    with pytest.raises(XFailed):
        tre.TestRSAX931().test_sign_verify_sha256(_RawSession())


def test_first_leg_non_ckr_error_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, sign_exc=AssertionError("decoder bug not a CKR"))
    with pytest.raises(AssertionError, match="decoder bug") as ei:
        tre.TestRSAX931().test_sign_verify_sha256(_RawSession())
    assert not isinstance(ei.value, XFailed)
