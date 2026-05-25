"""Regression tests for setup capability/runtime guards in provider buckets."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw import recipes as raw_recipes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
)
from pkcs11_check.testcases import (
    test_aes_modes,
    test_generic_secret,
    test_key_usage_policy,
    test_object_size,
    test_rsa_oaep,
    test_sensitivity,
    test_sign_recover,
    test_stateful,
)
from pkcs11_check.testcases.security import test_nonce_quality


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in names,
    )


def _raise_function_not_supported(*_args: Any, **_kwargs: Any) -> int:
    raise CkrAssertionError(
        "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
        int(CKR_FUNCTION_NOT_SUPPORTED),
    )


def _raise_attribute_value_invalid(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
    raise CkrAssertionError(
        "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID",
        int(CKR_ATTRIBUTE_VALUE_INVALID),
    )


def test_aes_modes_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_CTR", "AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_aes_modes.TestAESCTR().test_aes_ctr_roundtrip(rs)


def test_key_usage_policy_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_key_usage_policy.TestAESKeyUsagePolicy().test_decrypt_only_key_cannot_encrypt(rs)


def test_sensitivity_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_sensitivity.TestSensitiveFlag().test_sensitive_flag_is_true_when_requested(rs)


def test_stateful_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_stateful.test_object_count_consistency(rs)


def test_stateful_uses_operational_aes128_keygen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter([1, 2, 3])
    find_results = iter([[1], [2], [3], [], [1], [3]])

    def _gen_aes128_key(*_args: Any, bits: int = 256, **_kwargs: Any) -> int:
        if bits != 128:
            raise CkrAssertionError(
                "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
                int(CKR_FUNCTION_NOT_SUPPORTED),
            )
        return next(handles)

    monkeypatch.setattr(test_stateful, "require_operational_aes_keygen", lambda _rs: None)
    monkeypatch.setattr(test_stateful, "gen_aes_key", _gen_aes128_key)
    monkeypatch.setattr(
        test_stateful,
        "find_objects",
        lambda *_args, **_kwargs: next(find_results),
    )
    monkeypatch.setattr(test_stateful, "destroy_quietly", lambda *_args, **_kwargs: None)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    test_stateful.test_object_count_consistency(rs)


def test_stateful_direct_keygen_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_stateful, "require_operational_aes_keygen", lambda _rs: None)
    monkeypatch.setattr(test_stateful, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="stateful AES key generation"):
        test_stateful.test_object_count_consistency(rs)


def test_object_size_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_object_size.TestObjectSize().test_aes_key_has_size(rs)


def test_rsa_oaep_xfail_when_advertised_rsa_keypair_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_rsa_keypair", _raise_attribute_value_invalid)
    rs = _session_with_mechanisms("RSA_PKCS_KEY_PAIR_GEN", "RSA_PKCS_OAEP")

    with pytest.raises(pytest.xfail.Exception, match="RSA_PKCS_KEY_PAIR_GEN advertised"):
        test_rsa_oaep.TestRSAOAEPRoundtrip().test_oaep_encrypt_decrypt(rs)


def test_nonce_quality_xfail_when_advertised_ec_keypair_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_ec_keypair", _raise_attribute_value_invalid)
    rs = _session_with_mechanisms("ECDSA", "EC_KEY_PAIR_GEN")

    with pytest.raises(pytest.xfail.Exception, match="EC_KEY_PAIR_GEN advertised"):
        test_nonce_quality.TestECDSANonceReuse().test_nonce_reuse_p256(rs)


def test_generic_secret_hmac_runtime_general_error_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _sign_general_error(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(test_generic_secret, "create_object", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_generic_secret, "sign_single", _sign_general_error)
    monkeypatch.setattr(test_generic_secret, "destroy_quietly", lambda *_args: None)
    rs = _session_with_mechanisms("SHA256_HMAC")

    with pytest.raises(pytest.xfail.Exception, match="SHA256_HMAC advertised"):
        test_generic_secret.TestGenericSecretHMAC().test_hmac_with_imported_generic_secret(rs)


def test_sign_recover_subprocess_keygen_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_sign_recover, "_has_rsa_x509", lambda _module: True)
    monkeypatch.setattr(
        test_sign_recover,
        "_run_script",
        lambda *_args, **_kwargs: (1, "FATAL:GenerateKeyPair:0x00000013", ""),
    )
    config = SimpleNamespace(module="/tmp/mock-pkcs11.so", slot=0, pin=None)

    with pytest.raises(pytest.xfail.Exception, match="keypair setup rejected"):
        test_sign_recover.TestSignRecover().test_sign_recover_produces_output(config, object())
