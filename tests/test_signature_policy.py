"""Regression tests for shared invalid-signature result classification."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases import test_metamorphic, test_sign
from pkcs11_check.testcases._signature_policy import signature_rejected_or_xfail


@pytest.mark.parametrize(
    ("rv", "name"),
    [
        (CKR_ARGUMENTS_BAD, "CKR_ARGUMENTS_BAD"),
        (CKR_FUNCTION_NOT_SUPPORTED, "CKR_FUNCTION_NOT_SUPPORTED"),
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
    rs = type(
        "RawSession",
        (),
        {
            "raw": object(),
            "sh": 1,
            "has_mechanism": lambda _self, name: (
                name in {"RSA_PKCS_KEY_PAIR_GEN", "SHA256_RSA_PKCS"}
            ),
        },
    )()

    monkeypatch.setattr(test_sign, "gen_rsa_keypair_or_xfail", lambda *_args: (10, 11))
    monkeypatch.setattr(test_sign, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(test_sign, "sign_single", lambda *_args, **_kwargs: b"\x01" * 256)

    def _verify_rejects_with_non_clean_ckr(*_args: object, **_kwargs: object) -> bool:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    monkeypatch.setattr(test_sign, "verify_single", _verify_rejects_with_non_clean_ckr)

    with pytest.raises(pytest.xfail.Exception, match="CKR_DEVICE_ERROR"):
        test_sign.TestRSASignature().test_rsa_sign_wrong_data_fails_verify(rs)


def _patch_metamorphic_rsa_setup(
    monkeypatch: pytest.MonkeyPatch,
    verify_impl: object,
) -> SimpleNamespace:
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "SHA256_RSA_PKCS",
    )
    monkeypatch.setattr(test_metamorphic, "gen_rsa_keypair_or_xfail", lambda *_args: (10, 11))
    monkeypatch.setattr(test_metamorphic, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(test_metamorphic, "sign_single", lambda *_args, **_kwargs: b"\x01" * 256)
    monkeypatch.setattr(test_metamorphic, "verify_single", verify_impl)
    return rs


def test_metamorphic_wrong_data_acceptance_is_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _patch_metamorphic_rsa_setup(
        monkeypatch,
        lambda *_args, **_kwargs: True,
    )

    with pytest.raises(AssertionError):
        test_metamorphic.TestRoundTripInvariants().test_rsa_wrong_data_verify_fails(rs)


def test_metamorphic_wrong_data_non_clean_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _verify_rejects_with_non_clean_ckr(*_args: object, **_kwargs: object) -> bool:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    rs = _patch_metamorphic_rsa_setup(monkeypatch, _verify_rejects_with_non_clean_ckr)

    with pytest.raises(pytest.xfail.Exception, match="CKR_DEVICE_ERROR"):
        test_metamorphic.TestRoundTripInvariants().test_rsa_wrong_data_verify_fails(rs)
