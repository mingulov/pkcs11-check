"""Regression tests for shared invalid-signature result classification."""

from __future__ import annotations

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases import test_sign
from pkcs11_check.testcases._signature_policy import signature_rejected_or_xfail


@pytest.mark.parametrize(
    ("rv", "name"),
    [
        (CKR_ARGUMENTS_BAD, "CKR_ARGUMENTS_BAD"),
        (CKR_KEY_TYPE_INCONSISTENT, "CKR_KEY_TYPE_INCONSISTENT"),
        (CKR_MECHANISM_INVALID, "CKR_MECHANISM_INVALID"),
        (CKR_MECHANISM_PARAM_INVALID, "CKR_MECHANISM_PARAM_INVALID"),
    ],
)
def test_invalid_signature_non_clean_explicit_ckrs_are_xfail(rv: int, name: str) -> None:
    exc = CkrAssertionError(f"Unexpected CK_RV {name}", int(rv))

    with pytest.raises(pytest.xfail.Exception, match=name):
        signature_rejected_or_xfail(exc, "tc-invalid")


def test_basic_rsa_wrong_data_uses_signature_reject_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = type("RawSession", (), {"raw": object(), "sh": 1})()

    monkeypatch.setattr(test_sign, "gen_rsa_keypair", lambda *_args: (10, 11))
    monkeypatch.setattr(test_sign, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(test_sign, "sign_single", lambda *_args, **_kwargs: b"\x01" * 256)

    def _verify_rejects_with_non_clean_ckr(*_args: object, **_kwargs: object) -> bool:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    monkeypatch.setattr(test_sign, "verify_single", _verify_rejects_with_non_clean_ckr)

    with pytest.raises(pytest.xfail.Exception, match="CKR_DEVICE_ERROR"):
        test_sign.TestRSASignature().test_rsa_sign_wrong_data_fails_verify(rs)
