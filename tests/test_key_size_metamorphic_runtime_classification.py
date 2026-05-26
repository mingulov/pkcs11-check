"""Regression tests for key-size and metamorphic setup classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
)
from pkcs11_check.testcases import test_key_sizes, test_metamorphic


def _session(*mechanisms: str) -> SimpleNamespace:
    advertised = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in advertised,
    )


def test_key_size_aes_keygen_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _keygen_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
            int(CKR_FUNCTION_NOT_SUPPORTED),
        )

    import pkcs11_check.raw.recipes as recipes

    monkeypatch.setattr(recipes, "gen_aes_key", _keygen_reject)
    monkeypatch.setattr(test_key_sizes, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_key_sizes.TestAESKeySizes().test_aes_generate(
            _session("AES_KEY_GEN"),
            128,
        )


def test_key_size_rsa_keypair_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _keypair_reject(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID",
            int(CKR_ATTRIBUTE_VALUE_INVALID),
        )

    import pkcs11_check.raw.recipes as recipes

    monkeypatch.setattr(recipes, "gen_rsa_keypair", _keypair_reject)
    monkeypatch.setattr(test_key_sizes, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="RSA_PKCS_KEY_PAIR_GEN advertised"):
        test_key_sizes.TestRSAKeySizes().test_rsa_generate(
            _session("RSA_PKCS_KEY_PAIR_GEN"),
            2048,
        )


def test_key_size_rsa_sign_missing_mechanism_is_counted_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_key_sizes,
        "gen_rsa_keypair_or_xfail",
        lambda *_args, **_kwargs: pytest.fail("RSA keygen should not be called"),
    )

    with pytest.raises(pytest.skip.Exception, match="SHA256_RSA_PKCS not supported"):
        test_key_sizes.TestRSAKeySizes().test_rsa_sign_verify(
            _session("RSA_PKCS_KEY_PAIR_GEN"),
            2048,
        )


def test_key_size_rsa_sign_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _sign_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_INVALID",
            int(CKR_MECHANISM_INVALID),
        )

    monkeypatch.setattr(
        test_key_sizes, "gen_rsa_keypair_or_xfail", lambda *_args, **_kwargs: (1, 2)
    )
    monkeypatch.setattr(test_key_sizes, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(test_key_sizes, "sign_single", _sign_reject)

    with pytest.raises(pytest.xfail.Exception, match="SHA256_RSA_PKCS sign rejected"):
        test_key_sizes.TestRSAKeySizes().test_rsa_sign_verify(
            _session("RSA_PKCS_KEY_PAIR_GEN", "SHA256_RSA_PKCS"),
            2048,
        )


def test_metamorphic_aes_setup_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    def _keygen_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
            int(CKR_FUNCTION_NOT_SUPPORTED),
        )

    import pkcs11_check.raw.recipes as recipes

    monkeypatch.setattr(recipes, "gen_aes_key", _keygen_reject)
    monkeypatch.setattr(test_metamorphic, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_metamorphic.TestRoundTripInvariants().test_aes_ecb_roundtrip(
            _session("AES_KEY_GEN"),
            128,
        )
