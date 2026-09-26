"""Regression tests for setup rejects in mechanism-negative tests."""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR, CKR_FUNCTION_NOT_SUPPORTED
from pkcs11_check.testcases import test_mech_negative


class _AesRejectRaw:
    def C_GenerateKey(self, *_args: object) -> int:  # noqa: N802
        return int(CKR_FUNCTION_NOT_SUPPORTED)


class _RsaRejectRaw:
    def C_GenerateKeyPair(self, *_args: object) -> int:  # noqa: N802
        return int(CKR_DEVICE_ERROR)


def test_negative_aes_setup_runtime_reject_is_xfail() -> None:
    rs = SimpleNamespace(
        raw=_AesRejectRaw(),
        sh=1,
        has_mechanism=lambda name: name in {"RSA_PKCS", "AES_KEY_GEN"},
    )

    with pytest.raises(
        pytest.xfail.Exception,
        match="AES_KEY_GEN advertised but 256-bit key generation",
    ):
        test_mech_negative.TestWrongKeyType().test_rsa_pkcs_with_aes_key_rejected(
            cast(RawSession, rs)
        )


def test_eddsa_malformed_canonical_reject_passes() -> None:
    """Exact canonical PASS for EdDSA malformed structures is MECHANISM_PARAM_INVALID."""
    from pkcs11_check.raw.types_std import CKR_MECHANISM_PARAM_INVALID
    from pkcs11_check.testcases.conftest import classify_negative_rv

    classify_negative_rv(
        int(CKR_MECHANISM_PARAM_INVALID),
        test_mech_negative._EDDSA_MALFORMED_PARAM_RVS,
        label="CKM_EDDSA malformed structure",
    )


def test_eddsa_malformed_arguments_bad_is_adverse_xfail() -> None:
    from pkcs11_check.raw.types_std import CKR_ARGUMENTS_BAD
    from pkcs11_check.testcases.conftest import classify_negative_rv

    with pytest.raises(pytest.xfail.Exception):
        classify_negative_rv(
            int(CKR_ARGUMENTS_BAD),
            test_mech_negative._EDDSA_MALFORMED_PARAM_RVS,
            label="CKM_EDDSA malformed structure",
        )


def test_eddsa_malformed_other_defined_reject_is_adverse_xfail() -> None:
    from pkcs11_check.raw.types_std import CKR_FUNCTION_FAILED
    from pkcs11_check.testcases.conftest import classify_negative_rv

    with pytest.raises(pytest.xfail.Exception):
        classify_negative_rv(
            int(CKR_FUNCTION_FAILED),
            test_mech_negative._EDDSA_MALFORMED_PARAM_RVS,
            label="CKM_EDDSA malformed structure",
        )


def test_eddsa_malformed_accepted_ok_fails() -> None:
    from _pytest.outcomes import Failed

    from pkcs11_check.raw.types_std import CKR_OK
    from pkcs11_check.testcases.conftest import classify_negative_rv

    with pytest.raises(Failed):
        classify_negative_rv(
            int(CKR_OK),
            test_mech_negative._EDDSA_MALFORMED_PARAM_RVS,
            label="CKM_EDDSA malformed structure",
        )


def test_eddsa_malformed_undefined_ckr_fails() -> None:
    from _pytest.outcomes import Failed

    from pkcs11_check.testcases.conftest import classify_negative_rv

    with pytest.raises(Failed, match="undefined CK_RV"):
        classify_negative_rv(
            0x7FFFFFFF,
            test_mech_negative._EDDSA_MALFORMED_PARAM_RVS,
            label="CKM_EDDSA malformed structure",
        )


def test_eddsa_malformed_policy_does_not_narrow_shared_policy() -> None:
    """The EdDSA-only canonical set must not narrow the shared malformed policy."""
    from pkcs11_check.raw.types_std import CKR_ARGUMENTS_BAD, CKR_MECHANISM_PARAM_INVALID

    assert test_mech_negative._EDDSA_MALFORMED_PARAM_RVS == (CKR_MECHANISM_PARAM_INVALID,)
    assert set(test_mech_negative._MALFORMED_REQUIRED_PARAM_RVS) == {
        CKR_MECHANISM_PARAM_INVALID,
        CKR_ARGUMENTS_BAD,
    }


def test_negative_rsa_setup_runtime_reject_is_xfail() -> None:
    rs = SimpleNamespace(
        raw=_RsaRejectRaw(),
        sh=1,
        has_mechanism=lambda name: name in {"AES_ECB", "RSA_PKCS_KEY_PAIR_GEN"},
    )

    with pytest.raises(
        pytest.xfail.Exception,
        match="advertised RSA keypair generation rejected setup",
    ):
        test_mech_negative.TestWrongKeyType().test_aes_ecb_with_rsa_key_rejected(
            cast(RawSession, rs)
        )
