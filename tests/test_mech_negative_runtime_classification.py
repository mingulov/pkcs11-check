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


def test_negative_rsa_setup_runtime_reject_is_xfail() -> None:
    rs = SimpleNamespace(
        raw=_RsaRejectRaw(),
        sh=1,
        has_mechanism=lambda name: name in {"AES_ECB", "RSA_PKCS_KEY_PAIR_GEN"},
    )

    with pytest.raises(
        pytest.xfail.Exception,
        match="RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational",
    ):
        test_mech_negative.TestWrongKeyType().test_aes_ecb_with_rsa_key_rejected(
            cast(RawSession, rs)
        )
