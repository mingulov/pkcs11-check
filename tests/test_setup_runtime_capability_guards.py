"""Regression tests for setup capability/runtime guards in provider buckets."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw import recipes as raw_recipes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKF_DECRYPT,
    CKF_ENCRYPT,
    CKK_AES,
    CKM_AES_CBC,
    CKM_AES_CBC_PAD,
    CKM_AES_KEY_WRAP_KWP,
    CKM_RC2_CBC,
    CKM_RSA_PKCS_OAEP,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_SESSION_COUNT,
)
from pkcs11_check.testcases import (
    _rsa_export,
    test_access,
    test_access_levels,
    test_aead,
    test_aes_modes,
    test_attribute_defaults,
    test_attribute_enforcement,
    test_authenticated_wrap,
    test_buffers,
    test_concurrent_sessions,
    test_crossverify,
    test_crossverify_extended,
    test_data_objects,
    test_duplicate_labels,
    test_encrypt,
    test_fuzz,
    test_generic_secret,
    test_interface,
    test_interop,
    test_kdf,
    test_key_usage_policy,
    test_large_objects,
    test_mech_attribute,
    test_mech_flags,
    test_mech_keygen,
    test_mech_lifecycle,
    test_mech_sign_recover,
    test_mech_state,
    test_mech_wrap,
    test_mechanism_fuzz,
    test_object_search_patterns,
    test_object_size,
    test_object_visibility,
    test_operation_termination,
    test_ro_session,
    test_ro_session_restrictions,
    test_rsa_oaep,
    test_search,
    test_sensitivity,
    test_session_edge_cases,
    test_session_exhaustion,
    test_session_info,
    test_session_state_machine,
    test_set_attribute,
    test_sign_recover,
    test_stateful,
    test_surface_audit,
    test_v30_session,
)
from pkcs11_check.testcases.ckr import (
    test_ckr_codes,
    test_ckr_decrypt,
    test_ckr_derive,
    test_ckr_encrypt,
    test_ckr_object,
    test_ckr_priority,
    test_ckr_raw_state,
    test_ckr_session,
    test_ckr_sign,
    test_ckr_spec_compliance,
    test_ckr_verify,
    test_ckr_wrap,
)
from pkcs11_check.testcases.mechanism_registry import ParamRecipe
from pkcs11_check.testcases.security import (
    test_api_security,
    test_nonce_quality,
    test_padding_oracle,
    test_parameter_validation,
    test_tookan,
)


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


def _raise_general_error(*_args: Any, **_kwargs: Any) -> bytes:
    raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))


def test_aes_modes_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_CTR", "AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_aes_modes.TestAESCTR().test_aes_ctr_roundtrip(rs)


def test_aes_modes_use_operational_aes128_setup_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _gen_aes128_key(*_args: Any, bits: int = 256, **_kwargs: Any) -> int:
        if len(_args) >= 3:
            bits = int(_args[2])
        if bits != 128:
            raise CkrAssertionError(
                "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
                int(CKR_FUNCTION_NOT_SUPPORTED),
            )
        return 1

    monkeypatch.setattr(test_aes_modes, "require_operational_aes_keygen", lambda _rs: None)
    monkeypatch.setattr(test_aes_modes, "_raw_gen_aes_key", _gen_aes128_key)
    monkeypatch.setattr(
        test_aes_modes,
        "encrypt_single",
        lambda *args, **_kwargs: b"x" * len(args[4]),
    )
    monkeypatch.setattr(
        test_aes_modes,
        "decrypt_single",
        lambda *_args, **_kwargs: b"AES-CTR test data, any length ok",
    )
    monkeypatch.setattr(test_aes_modes, "destroy_quietly", lambda *_args, **_kwargs: None)
    rs = _session_with_mechanisms("AES_CTR", "AES_KEY_GEN")

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
    monkeypatch.setattr(raw_recipes, "sign_single", _raise_general_error)
    monkeypatch.setattr(test_generic_secret, "create_object", lambda *_args, **_kwargs: 1)
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


def test_sign_recover_probe_returns_false_for_empty_token_slots() -> None:
    module = SimpleNamespace(get_slots=lambda token_present=True: [])

    assert test_sign_recover._has_rsa_x509(module) is False


def test_sign_recover_probe_propagates_slot_enumeration_error() -> None:
    def _raise_get_slots(*_args: Any, **_kwargs: Any) -> list[Any]:
        raise RuntimeError("slot enumeration failed")

    module = SimpleNamespace(get_slots=_raise_get_slots)

    with pytest.raises(RuntimeError, match="slot enumeration failed"):
        test_sign_recover._has_rsa_x509(module)


def test_sign_recover_probe_propagates_mechanism_enumeration_error() -> None:
    slot = SimpleNamespace(
        get_mechanisms=lambda: (_ for _ in ()).throw(RuntimeError("mechanism probe failed"))
    )
    module = SimpleNamespace(get_slots=lambda token_present=True: [slot])

    with pytest.raises(RuntimeError, match="mechanism probe failed"):
        test_sign_recover._has_rsa_x509(module)


def test_authenticated_wrap_v240_probe_xfails_when_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    monkeypatch.setattr(test_authenticated_wrap, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_authenticated_wrap.TestAuthenticatedWrap().test_authenticated_wrap_requires_v32(
            rs,
            "2.40",
        )


def test_authenticated_wrap_generated_iv_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("AES_GCM")
    monkeypatch.setattr(test_authenticated_wrap, "gen_aes_key", lambda *_args, **_kwargs: 10)
    monkeypatch.setattr(
        test_authenticated_wrap,
        "read_attributes",
        lambda *_args, **_kwargs: {test_authenticated_wrap.CKA_VALUE: b"\x5a" * 16},
    )
    monkeypatch.setattr(test_authenticated_wrap, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(
        test_authenticated_wrap.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    def _wrap_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
            int(CKR_FUNCTION_NOT_SUPPORTED),
        )

    monkeypatch.setattr(test_authenticated_wrap, "wrap_key_authenticated", _wrap_reject)

    with pytest.raises(pytest.xfail.Exception, match="authenticated generated-IV wrap rejected"):
        test_authenticated_wrap.TestAuthenticatedWrap().test_aes_gcm_authenticated_wrap_generated_iv_and_tag(
            rs, "3.2"
        )


def test_authenticated_wrap_roundtrip_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("AES_GCM")
    monkeypatch.setattr(test_authenticated_wrap, "gen_aes_key", lambda *_args, **_kwargs: 10)
    monkeypatch.setattr(test_authenticated_wrap, "generate_random", lambda *_args: b"\x01" * 12)
    monkeypatch.setattr(
        test_authenticated_wrap,
        "read_attributes",
        lambda *_args, **_kwargs: {test_authenticated_wrap.CKA_VALUE: b"\x5a" * 16},
    )
    monkeypatch.setattr(test_authenticated_wrap, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(
        test_authenticated_wrap.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )
    monkeypatch.setattr(
        test_authenticated_wrap,
        "wrap_key_authenticated",
        _raise_function_not_supported,
    )

    with pytest.raises(pytest.xfail.Exception, match="AES-GCM authenticated wrap rejected"):
        test_authenticated_wrap.TestAuthenticatedWrap().test_aes_gcm_wrap_unwrap(rs, "3.2")


def test_authenticated_wrap_aes_kw_baseline_wrap_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("AES_KEY_WRAP")
    p11_config = SimpleNamespace(module="/tmp/mock-pkcs11.so")
    monkeypatch.setattr(test_authenticated_wrap, "gen_aes_key", lambda *_args, **_kwargs: 10)
    monkeypatch.setattr(
        test_authenticated_wrap,
        "read_attributes",
        lambda *_args, **_kwargs: {test_authenticated_wrap.CKA_VALUE: b"\x5a" * 16},
    )
    monkeypatch.setattr(test_authenticated_wrap, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(
        test_authenticated_wrap.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    def _wrap_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(test_authenticated_wrap, "wrap_key", _wrap_reject)

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_WRAP advertised"):
        test_authenticated_wrap.TestWrapIntegrity().test_aes_key_wrap_bit_flip_detected(
            rs, p11_config
        )


def test_authenticated_wrap_gcm_bitflip_baseline_wrap_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("AES_GCM")
    p11_config = SimpleNamespace(module="/tmp/mock-pkcs11.so")
    monkeypatch.setattr(test_authenticated_wrap, "gen_aes_key", lambda *_args, **_kwargs: 10)
    monkeypatch.setattr(test_authenticated_wrap, "generate_random", lambda *_args: b"\x01" * 12)
    monkeypatch.setattr(
        test_authenticated_wrap,
        "read_attributes",
        lambda *_args, **_kwargs: {test_authenticated_wrap.CKA_VALUE: b"\x5a" * 16},
    )
    monkeypatch.setattr(test_authenticated_wrap, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(
        test_authenticated_wrap.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )
    monkeypatch.setattr(
        test_authenticated_wrap,
        "wrap_key_authenticated",
        _raise_function_not_supported,
    )

    with pytest.raises(pytest.xfail.Exception, match="AES-GCM authenticated wrap rejected"):
        test_authenticated_wrap.TestWrapIntegrity().test_aes_gcm_wrap_bit_flip_detected(
            rs, "3.2", p11_config
        )


def test_authenticated_wrap_gcm_bitflip_unknown_unwrap_error_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("AES_GCM")
    p11_config = SimpleNamespace(module="/tmp/mock-pkcs11.so")
    monkeypatch.setattr(test_authenticated_wrap, "gen_aes_key", lambda *_args, **_kwargs: 10)
    monkeypatch.setattr(test_authenticated_wrap, "generate_random", lambda *_args: b"\x01" * 12)
    monkeypatch.setattr(
        test_authenticated_wrap,
        "read_attributes",
        lambda *_args, **_kwargs: {test_authenticated_wrap.CKA_VALUE: b"\x5a" * 16},
    )
    monkeypatch.setattr(test_authenticated_wrap, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(
        test_authenticated_wrap,
        "wrap_key_authenticated",
        lambda *_args, **_kwargs: b"\x22" * 16,
    )
    monkeypatch.setattr(
        test_authenticated_wrap,
        "unwrap_key_authenticated",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("ctypes packing bug")),
    )

    with pytest.raises(AssertionError, match="ctypes packing bug"):
        test_authenticated_wrap.TestWrapIntegrity().test_aes_gcm_wrap_bit_flip_detected(
            rs, "3.2", p11_config
        )


def test_authenticated_wrap_tampered_tag_unknown_unwrap_error_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("AES_GCM")
    p11_config = SimpleNamespace(module="/tmp/mock-pkcs11.so")
    monkeypatch.setattr(test_authenticated_wrap, "gen_aes_key", lambda *_args, **_kwargs: 10)
    monkeypatch.setattr(test_authenticated_wrap, "generate_random", lambda *_args: b"\x01" * 12)
    monkeypatch.setattr(
        test_authenticated_wrap,
        "read_attributes",
        lambda *_args, **_kwargs: {test_authenticated_wrap.CKA_VALUE: b"\x5a" * 16},
    )
    monkeypatch.setattr(test_authenticated_wrap, "destroy_quietly", lambda *_args: None)

    def _wrap_success(*_args: Any, **kwargs: Any) -> bytes:
        mech_param = kwargs["mech_param"]
        tag_storage, _ = mech_param.buffer_storage("tag")
        tag_storage[0] = 1
        return b"\x22" * 16

    monkeypatch.setattr(test_authenticated_wrap, "wrap_key_authenticated", _wrap_success)
    monkeypatch.setattr(
        test_authenticated_wrap,
        "unwrap_key_authenticated",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("ctypes packing bug")),
    )

    with pytest.raises(AssertionError, match="ctypes packing bug"):
        test_authenticated_wrap.TestAuthenticatedWrap().test_tampered_tag_rejected(
            rs, "3.2", p11_config
        )


def test_authenticated_wrap_ecdh_roundtrip_ec_keygen_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("ECDH_AES_KEY_WRAP", "EC_KEY_PAIR_GEN")
    p11_config = SimpleNamespace(module="/tmp/mock-pkcs11.so")
    monkeypatch.setattr(raw_recipes, "gen_ec_keypair", _raise_attribute_value_invalid)
    monkeypatch.setattr(
        test_authenticated_wrap.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    with pytest.raises(pytest.xfail.Exception, match="EC_KEY_PAIR_GEN advertised"):
        test_authenticated_wrap.TestEcdhAesKeyWrap().test_ecdh_aes_kw_roundtrip(
            rs,
            p11_config,
            test_authenticated_wrap._ECDH_AES_KW_CASES[0],
        )


def test_authenticated_wrap_ecdh_integrity_ec_keygen_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("ECDH_AES_KEY_WRAP", "EC_KEY_PAIR_GEN")
    p11_config = SimpleNamespace(module="/tmp/mock-pkcs11.so")
    monkeypatch.setattr(raw_recipes, "gen_ec_keypair", _raise_attribute_value_invalid)
    monkeypatch.setattr(
        test_authenticated_wrap.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    with pytest.raises(pytest.xfail.Exception, match="EC_KEY_PAIR_GEN advertised"):
        test_authenticated_wrap.TestEcdhAesKeyWrap().test_ecdh_aes_kw_bit_flip_integrity(
            rs,
            p11_config,
            test_authenticated_wrap._ECDH_AES_KW_CASES[0],
        )


def test_buffer_encrypt_xfails_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    monkeypatch.setattr(test_buffers, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_ECB", "AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_buffers.TestEncryptBufferSizes().test_single_block(rs)


def test_buffer_encrypt_uses_operational_aes128_setup_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []

    def _gen_aes_key(*_args: Any, bits: int = 256, **_kwargs: Any) -> int:
        if len(_args) >= 3:
            bits = int(_args[2])
        calls.append(bits)
        if bits != 128:
            raise CkrAssertionError(
                "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
                int(CKR_FUNCTION_NOT_SUPPORTED),
            )
        return 1

    monkeypatch.setattr(test_buffers, "require_operational_aes_keygen", lambda _rs: None)
    monkeypatch.setattr(test_buffers, "gen_aes_key", _gen_aes_key)
    monkeypatch.setattr(
        test_buffers, "encrypt_single", lambda *args, **_kwargs: b"x" * len(args[4])
    )
    monkeypatch.setattr(test_buffers, "decrypt_single", lambda *_args, **_kwargs: b"X" * 16)
    monkeypatch.setattr(test_buffers, "destroy_quietly", lambda *_args, **_kwargs: None)
    rs = _session_with_mechanisms("AES_ECB", "AES_KEY_GEN")

    test_buffers.TestEncryptBufferSizes().test_single_block(rs)

    assert calls == [128]


def test_buffer_digest_skips_without_sha256(monkeypatch: pytest.MonkeyPatch) -> None:
    rs = _session_with_mechanisms()

    def _unexpected_digest(*_args: Any, **_kwargs: Any) -> bytes:
        raise AssertionError("digest should not run without SHA256")

    monkeypatch.setattr(test_buffers, "digest_single", _unexpected_digest)

    with pytest.raises(pytest.skip.Exception, match="CKM_SHA256 not supported"):
        test_buffers.TestDigestBufferSizes().test_empty_input(rs)


def test_buffer_sign_skips_without_sha256_rsa_pkcs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("RSA_PKCS_KEY_PAIR_GEN")

    def _unexpected_keypair(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        raise AssertionError("RSA setup should not run without SHA256_RSA_PKCS")

    monkeypatch.setattr(test_buffers, "gen_rsa_keypair_or_xfail", _unexpected_keypair)

    with pytest.raises(pytest.skip.Exception, match="CKM_SHA256_RSA_PKCS not supported"):
        test_buffers.TestSignBufferSizes().test_sign_empty(rs)


def test_mechanism_fuzz_xfails_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    monkeypatch.setattr(
        test_mechanism_fuzz,
        "gen_aes_key",
        _raise_function_not_supported,
        raising=False,
    )
    rs = _session_with_mechanisms("AES_KEY_GEN", "AES_CBC")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_mechanism_fuzz.TestAESParameterFuzz().test_aes_cbc_bad_iv(rs, b"\x00" * 8)


def test_ckr_encrypt_xfails_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    monkeypatch.setattr(
        test_ckr_encrypt,
        "gen_aes_key",
        _raise_function_not_supported,
        raising=False,
    )
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_ckr_encrypt.TestEncryptDataErrors().test_ecb_non_aligned(rs, False, 15)


def test_ckr_decrypt_xfails_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    monkeypatch.setattr(
        test_ckr_decrypt,
        "gen_aes_key",
        _raise_function_not_supported,
        raising=False,
    )
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_ckr_decrypt.TestDecryptDataErrors().test_ecb_ciphertext_not_aligned(
            rs,
            False,
            15,
        )


class _OAEPParamRequiredRaw:
    def __init__(self) -> None:
        self.decrypt_init_param_len = 0
        self.decrypt_called = False

    def C_DecryptInit(self, _sh: int, mech_ptr: Any, _key: int) -> int:  # noqa: N802
        mech = mech_ptr._obj
        assert int(mech.mechanism) == int(CKM_RSA_PKCS_OAEP)
        self.decrypt_init_param_len = int(mech.ulParameterLen)
        if mech.pParameter is None or self.decrypt_init_param_len == 0:
            return int(CKR_MECHANISM_PARAM_INVALID)
        return int(CKR_OK)

    def C_Decrypt(self, *_args: Any) -> int:  # noqa: N802
        self.decrypt_called = True
        return int(CKR_ENCRYPTED_DATA_INVALID)


def test_ckr_rsa_oaep_garbage_uses_oaep_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _OAEPParamRequiredRaw()
    monkeypatch.setattr(test_ckr_decrypt, "gen_rsa_keypair_or_xfail", lambda *_args: (1, 2))
    monkeypatch.setattr(test_ckr_decrypt, "destroy_quietly", lambda *_args: None)
    rs = SimpleNamespace(
        raw=raw,
        sh=1,
        has_mechanism=lambda name: name == "RSA_PKCS_OAEP",
    )

    try:
        test_ckr_decrypt.TestDecryptDataErrors().test_rsa_oaep_garbage(rs, False)
    except pytest.skip.Exception as exc:
        pytest.fail(f"RSA-OAEP garbage test skipped instead of exercising C_Decrypt: {exc}")

    assert raw.decrypt_init_param_len > 0
    assert raw.decrypt_called is True


def test_padding_oracle_xfails_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    monkeypatch.setattr(
        test_padding_oracle,
        "gen_aes_key",
        _raise_function_not_supported,
        raising=False,
    )
    monkeypatch.setattr(test_padding_oracle, "require_operational_aes_keygen", lambda _rs: None)
    rs = _session_with_mechanisms("AES_CBC_PAD", "AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_padding_oracle.TestAESPaddingOracle().test_cbc_pad_all_last_block_positions(rs)


def test_padding_oracle_uses_operational_aes128_setup_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    handles = iter(range(1, 25))

    def _gen_aes_key(*_args: Any, bits: int = 256, **_kwargs: Any) -> int:
        if len(_args) >= 3:
            bits = int(_args[2])
        calls.append(bits)
        if bits != 128:
            raise CkrAssertionError(
                "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
                int(CKR_FUNCTION_NOT_SUPPORTED),
            )
        return next(handles)

    def _decrypt_invalid_padding(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID",
            int(CKR_ENCRYPTED_DATA_INVALID),
        )

    monkeypatch.setattr(raw_recipes, "gen_aes_key", _gen_aes_key)
    monkeypatch.setattr(test_padding_oracle, "gen_aes_key", _gen_aes_key, raising=False)
    monkeypatch.setattr(test_padding_oracle, "require_operational_aes_keygen", lambda _rs: None)
    monkeypatch.setattr(test_padding_oracle, "generate_random", lambda *_args: b"\x00" * 16)
    monkeypatch.setattr(test_padding_oracle, "encrypt_single", lambda *_args, **_kwargs: b"x" * 48)
    monkeypatch.setattr(test_padding_oracle, "decrypt_single", _decrypt_invalid_padding)
    monkeypatch.setattr(test_padding_oracle, "destroy_quietly", lambda *_args, **_kwargs: None)
    rs = _session_with_mechanisms("AES_CBC_PAD", "AES_KEY_GEN")

    test_padding_oracle.TestAESPaddingOracle().test_cbc_pad_all_last_block_positions(rs)

    assert calls == [128] * 20


def test_access_levels_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    monkeypatch.setattr(test_access_levels, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_access_levels.TestUserSessionCapabilities().test_user_can_create_and_destroy_objects(
            rs
        )


def test_access_levels_use_operational_aes128_setup_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []

    def _gen_aes_key(*_args: Any, bits: int = 256, **_kwargs: Any) -> int:
        if len(_args) >= 3:
            bits = int(_args[2])
        calls.append(bits)
        if bits != 128:
            raise CkrAssertionError(
                "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
                int(CKR_FUNCTION_NOT_SUPPORTED),
            )
        return 1

    monkeypatch.setattr(test_access_levels, "require_operational_aes_keygen", lambda _rs: None)
    monkeypatch.setattr(test_access_levels, "gen_aes_key", _gen_aes_key)
    monkeypatch.setattr(test_access_levels, "destroy_quietly", lambda *_args, **_kwargs: None)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    test_access_levels.TestUserSessionCapabilities().test_user_can_create_and_destroy_objects(rs)

    assert calls == [128]


def test_access_levels_data_object_setup_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_access_levels, "create_object", _raise_attribute_value_invalid)
    rs = _session_with_mechanisms()

    with pytest.raises(pytest.xfail.Exception, match="data object setup rejected"):
        test_access_levels._create_access_data_object(rs, 1, {})


def test_access_levels_public_session_capacity_reject_is_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _open_session_limit(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_SESSION_COUNT",
            int(CKR_SESSION_COUNT),
        )

    monkeypatch.setattr(test_access_levels, "raw_open_session", _open_session_limit)
    rs = SimpleNamespace(raw=object(), slot_id=1)

    with pytest.raises(pytest.skip.Exception, match="additional session"):
        test_access_levels.TestPublicSessionVisibility().test_public_session_can_digest(
            rs,
            SimpleNamespace(),
        )


def test_legacy_access_extra_session_capacity_reject_is_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _open_session_limit(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_SESSION_COUNT",
            int(CKR_SESSION_COUNT),
        )

    open_attr = (
        "_raw_open_session" if hasattr(test_access, "_raw_open_session") else "raw_open_session"
    )
    monkeypatch.setattr(test_access, open_attr, _open_session_limit)
    rs = SimpleNamespace(raw=object(), slot_id=1)

    with pytest.raises(pytest.skip.Exception, match="additional session"):
        test_access.TestSessionTypes().test_ro_session_can_read(
            rs,
            SimpleNamespace(pin=None),
        )


def test_legacy_access_missing_aes_keygen_is_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _unexpected_keygen(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("AES keygen should have been capability-guarded")

    monkeypatch.setattr(raw_recipes, "gen_aes_key", _unexpected_keygen)
    rs = _session_with_mechanisms()

    with pytest.raises(pytest.skip.Exception, match="AES_KEY_GEN not supported"):
        test_access.TestSessionTypes().test_rw_session_can_generate_key(rs)


def test_ckr_session_invalid_slot_capacity_reject_is_skip() -> None:
    class Raw:
        pass

    raw = Raw()
    setattr(raw, "C_OpenSession", lambda *_args, **_kwargs: int(CKR_SESSION_COUNT))
    rs = SimpleNamespace(raw=raw)

    with pytest.raises(pytest.skip.Exception, match="additional session"):
        test_ckr_session.TestOpenSessionErrors().test_invalid_slot_id(rs)


def test_ckr_session_wrong_pin_capacity_reject_is_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _open_session_limit(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_SESSION_COUNT",
            int(CKR_SESSION_COUNT),
        )

    open_attr = (
        "_raw_open_session" if hasattr(test_ckr_session, "_raw_open_session") else "open_session"
    )
    monkeypatch.setattr(test_ckr_session, open_attr, _open_session_limit)
    rs = SimpleNamespace(raw=object(), slot_id=1)

    with pytest.raises(pytest.skip.Exception, match="additional session"):
        test_ckr_session.TestLoginErrors().test_wrong_pin(rs)


def test_ckr_session_logout_capacity_reject_is_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _open_session_limit(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_SESSION_COUNT",
            int(CKR_SESSION_COUNT),
        )

    open_attr = (
        "_raw_open_session" if hasattr(test_ckr_session, "_raw_open_session") else "open_session"
    )
    monkeypatch.setattr(test_ckr_session, open_attr, _open_session_limit)
    rs = SimpleNamespace(raw=object(), slot_id=1)

    with pytest.raises(pytest.skip.Exception, match="additional session"):
        test_ckr_session.TestLogoutErrors().test_logout_when_not_logged_in(rs)


def test_legacy_ro_session_extra_session_capacity_reject_is_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _open_session_limit(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_SESSION_COUNT",
            int(CKR_SESSION_COUNT),
        )

    open_attr = (
        "_raw_open_session" if hasattr(test_ro_session, "_raw_open_session") else "raw_open_session"
    )
    monkeypatch.setattr(test_ro_session, open_attr, _open_session_limit)
    rs = SimpleNamespace(raw=object(), slot_id=1)

    with pytest.raises(pytest.skip.Exception, match="additional session"):
        test_ro_session.TestROSessionOperations().test_digest_in_ro_session(
            rs,
            SimpleNamespace(pin=None),
        )


def test_session_info_extra_session_capacity_reject_is_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _open_session_limit(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_SESSION_COUNT",
            int(CKR_SESSION_COUNT),
        )

    open_attr = (
        "_raw_open_session"
        if hasattr(test_session_info, "_raw_open_session")
        else "raw_open_session"
    )
    monkeypatch.setattr(test_session_info, open_attr, _open_session_limit)
    rs = SimpleNamespace(raw=object(), slot_id=1)

    with pytest.raises(pytest.skip.Exception, match="additional session"):
        test_session_info.TestSessionInfo().test_rw_session_is_rw(
            rs,
            SimpleNamespace(pin=None),
        )


def test_operation_termination_multipart_encrypt_not_initialized_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _encrypt_multipart_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_OPERATION_NOT_INITIALIZED",
            int(CKR_OPERATION_NOT_INITIALIZED),
        )

    entry = SimpleNamespace(
        mech_id=int(CKM_AES_CBC),
        mech_name="AES_CBC",
        config=SimpleNamespace(key_type=int(CKK_AES)),
    )
    rs = SimpleNamespace(raw=object(), sh=1)

    monkeypatch.setattr(
        test_operation_termination,
        "generate_key_for_encrypt",
        lambda *_args: (1, None),
    )
    monkeypatch.setattr(test_operation_termination, "make_mech_param_or_skip", lambda _entry: None)
    monkeypatch.setattr(test_operation_termination, "get_test_plaintext_bytes", lambda: b"0" * 32)
    monkeypatch.setattr(test_operation_termination, "encrypt_multipart", _encrypt_multipart_reject)
    monkeypatch.setattr(test_operation_termination, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="multipart encrypt not operational"):
        test_operation_termination.test_c_encrypt_terminates_after_multipart(rs, entry)


def test_legacy_access_aes_setup_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(
        pytest.xfail.Exception, match="AES_KEY_GEN advertised but.*is not operational"
    ):
        test_access.TestSessionTypes().test_rw_session_can_generate_key(rs)


def test_legacy_access_rsa_setup_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keypair_attr = (
        "_raw_gen_rsa_keypair"
        if hasattr(test_access, "_raw_gen_rsa_keypair")
        else "gen_rsa_keypair"
    )
    monkeypatch.setattr(test_access, keypair_attr, _raise_attribute_value_invalid)
    rs = _session_with_mechanisms("RSA_PKCS_KEY_PAIR_GEN")

    with pytest.raises(pytest.xfail.Exception, match="access RSA keypair setup"):
        test_access.TestLoginStates().test_user_session_can_see_private(rs)


def test_api_security_missing_aes_keygen_is_skip_not_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _unexpected_keygen(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("AES keygen should have been capability-guarded")

    keygen_attr = (
        "_raw_gen_aes_key" if hasattr(test_api_security, "_raw_gen_aes_key") else "gen_aes_key"
    )
    monkeypatch.setattr(test_api_security, keygen_attr, _unexpected_keygen)
    rs = _session_with_mechanisms("AES_ECB")

    with pytest.raises(pytest.skip.Exception, match="AES_KEY_GEN not supported"):
        test_api_security.TestWrapDecryptOracle().test_wrap_decrypt_combination_prevented(rs)


def test_api_security_aes_setup_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_api_security,
        "require_operational_aes_keygen",
        lambda _rs: None,
        raising=False,
    )
    keygen_attr = (
        "_raw_gen_aes_key" if hasattr(test_api_security, "_raw_gen_aes_key") else "gen_aes_key"
    )
    monkeypatch.setattr(test_api_security, keygen_attr, _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="API security AES setup"):
        test_api_security.TestSensitiveExtraction().test_sensitive_key_value_not_readable(rs)


def test_api_security_rsa_setup_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keypair_attr = (
        "_raw_gen_rsa_keypair"
        if hasattr(test_api_security, "_raw_gen_rsa_keypair")
        else "gen_rsa_keypair"
    )
    monkeypatch.setattr(test_api_security, keypair_attr, _raise_attribute_value_invalid)
    rs = _session_with_mechanisms("RSA_PKCS_KEY_PAIR_GEN")

    with pytest.raises(pytest.xfail.Exception, match="API security RSA setup"):
        test_api_security.TestSensitiveExtraction().test_private_key_not_extractable(rs)


def test_api_security_extra_session_capacity_reject_is_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _open_session_limit(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_SESSION_COUNT",
            int(CKR_SESSION_COUNT),
        )

    open_attr = (
        "_raw_open_session"
        if hasattr(test_api_security, "_raw_open_session")
        else "raw_open_session"
    )
    monkeypatch.setattr(test_api_security, open_attr, _open_session_limit)
    rs = SimpleNamespace(raw=object(), slot_id=1)

    with pytest.raises(pytest.skip.Exception, match="additional session"):
        test_api_security.TestAccessControl().test_no_login_private_objects_invisible(rs)


def test_api_security_wrap_runtime_reject_is_xfail_not_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter([1, 2])

    def _next_key(*_args: Any, **_kwargs: Any) -> int:
        return next(handles)

    def _reject_wrap(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_INVALID",
            int(CKR_MECHANISM_INVALID),
        )

    monkeypatch.setattr(test_api_security, "require_operational_aes_keygen", lambda _rs: None)
    monkeypatch.setattr(test_api_security, "_raw_gen_aes_key", _next_key)
    monkeypatch.setattr(test_api_security, "wrap_key", _reject_wrap)
    monkeypatch.setattr(test_api_security, "destroy_quietly", lambda *_args: None)
    rs = _session_with_mechanisms("AES_ECB", "AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="API security wrap-decrypt operation"):
        test_api_security.TestWrapDecryptOracle().test_wrap_decrypt_combination_prevented(rs)


def test_data_objects_extra_session_capacity_reject_is_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _open_session_limit(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_SESSION_COUNT",
            int(CKR_SESSION_COUNT),
        )

    open_attr = (
        "_raw_open_session"
        if hasattr(test_data_objects, "_raw_open_session")
        else "raw_open_session"
    )
    monkeypatch.setattr(test_data_objects, open_attr, _open_session_limit)
    monkeypatch.setattr(test_data_objects, "skip_if_token_write_protected", lambda *_args: None)
    rs = SimpleNamespace(raw=object(), slot_id=1)

    with pytest.raises(pytest.skip.Exception, match="additional session"):
        test_data_objects.TestDataObjectToken().test_token_data_object_survives_session(
            rs,
            SimpleNamespace(pin=None),
        )


def test_fuzz_aes_missing_mechanism_skips_before_keygen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _unexpected_keygen(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("AES fuzz setup should have been capability-guarded")

    monkeypatch.setattr(test_fuzz, "gen_aes_key", _unexpected_keygen)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.skip.Exception, match="AES_ECB not supported"):
        test_fuzz.TestAESFuzz().test_ecb_roundtrip(rs)


def test_fuzz_digest_missing_mechanism_skips_before_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _unexpected_digest(*_args: Any, **_kwargs: Any) -> bytes:
        raise AssertionError("digest fuzz operation should have been capability-guarded")

    monkeypatch.setattr(test_fuzz, "digest_single", _unexpected_digest)
    rs = _session_with_mechanisms()

    with pytest.raises(pytest.skip.Exception, match="SHA256 not supported"):
        test_fuzz.TestDigestFuzz().test_sha256_cross_verify(rs)


def test_fuzz_rsa_missing_sign_mechanism_skips_before_keypair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _unexpected_keypair(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        raise AssertionError("RSA fuzz keypair should have been capability-guarded")

    monkeypatch.setattr(test_fuzz, "gen_rsa_keypair", _unexpected_keypair)
    rs = _session_with_mechanisms("RSA_PKCS_KEY_PAIR_GEN")

    with pytest.raises(pytest.skip.Exception, match="SHA256_RSA_PKCS not supported"):
        test_fuzz.TestRSAFuzz().test_sign_verify_roundtrip(rs)


def test_fuzz_hmac_missing_mechanism_skips_before_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _unexpected_import(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("HMAC fuzz key import should have been capability-guarded")

    monkeypatch.setattr(test_fuzz, "import_secret_key", _unexpected_import)
    rs = _session_with_mechanisms()

    with pytest.raises(pytest.skip.Exception, match="SHA256_HMAC not supported"):
        test_fuzz.TestHMACFuzz().test_hmac_deterministic(rs)


def test_fuzz_advertised_digest_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _rejected_digest(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_INVALID",
            int(CKR_MECHANISM_INVALID),
        )

    monkeypatch.setattr(test_fuzz, "digest_single", _rejected_digest)
    rs = _session_with_mechanisms("SHA256")

    with pytest.raises(pytest.xfail.Exception, match="fuzz digest"):
        test_fuzz.TestDigestFuzz().test_sha256_deterministic(rs)


def test_session_state_machine_extra_session_capacity_reject_is_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _open_session_limit(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_SESSION_COUNT",
            int(CKR_SESSION_COUNT),
        )

    open_attr = (
        "_raw_open_session"
        if hasattr(test_session_state_machine, "_raw_open_session")
        else "raw_open_session"
    )
    monkeypatch.setattr(test_session_state_machine, open_attr, _open_session_limit)
    rs = SimpleNamespace(raw=object(), slot_id=1)

    with pytest.raises(pytest.skip.Exception, match="additional session"):
        test_session_state_machine.TestSessionFlags().test_rw_session_flag(
            rs,
            SimpleNamespace(),
        )


def test_session_state_machine_aes_setup_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Pin:
        def get_secret_value(self) -> str:
            return "1234"

    open_attr = (
        "_raw_open_session"
        if hasattr(test_session_state_machine, "_raw_open_session")
        else "raw_open_session"
    )
    monkeypatch.setattr(test_session_state_machine, open_attr, lambda *_a: 2)
    monkeypatch.setattr(test_session_state_machine, "_login_user_raw", lambda *_a: None)
    monkeypatch.setattr(test_session_state_machine, "_logout_safe", lambda *_a: None)
    monkeypatch.setattr(test_session_state_machine, "close_session_quietly", lambda *_a: None)
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")
    rs.slot_id = 1

    with pytest.raises(
        pytest.xfail.Exception, match="AES_KEY_GEN advertised but.*is not operational"
    ):
        test_session_state_machine.TestLoginStateTransitions().test_login_user_enables_private_access(
            rs,
            SimpleNamespace(pin=_Pin()),
        )


def test_session_state_machine_data_object_setup_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Pin:
        def get_secret_value(self) -> str:
            return "1234"

    raw = SimpleNamespace(C_Logout=lambda *_args: int(CKR_OK))
    rs = SimpleNamespace(raw=raw, sh=1, slot_id=1, has_mechanism=lambda _name: True)
    open_attr = (
        "_raw_open_session"
        if hasattr(test_session_state_machine, "_raw_open_session")
        else "raw_open_session"
    )
    monkeypatch.setattr(test_session_state_machine, open_attr, lambda *_a: 2)
    monkeypatch.setattr(test_session_state_machine, "_login_user_raw", lambda *_a: None)
    monkeypatch.setattr(test_session_state_machine, "_logout_safe", lambda *_a: None)
    monkeypatch.setattr(test_session_state_machine, "close_session_quietly", lambda *_a: None)
    create_attr = (
        "_raw_create_object"
        if hasattr(test_session_state_machine, "_raw_create_object")
        else "create_object"
    )
    monkeypatch.setattr(test_session_state_machine, create_attr, _raise_attribute_value_invalid)

    with pytest.raises(pytest.xfail.Exception, match="data object setup rejected"):
        test_session_state_machine.TestLogoutEffects().test_public_object_remains_after_logout(
            rs,
            SimpleNamespace(pin=_Pin()),
        )


def test_ro_session_extra_session_capacity_reject_is_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _open_session_limit(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_SESSION_COUNT",
            int(CKR_SESSION_COUNT),
        )

    open_attr = (
        "_raw_open_session"
        if hasattr(test_ro_session_restrictions, "_raw_open_session")
        else "raw_open_session"
    )
    monkeypatch.setattr(test_ro_session_restrictions, open_attr, _open_session_limit)
    rs = SimpleNamespace(raw=object(), slot_id=1)

    with pytest.raises(pytest.skip.Exception, match="additional RO session"):
        test_ro_session_restrictions.TestROCryptoOperations().test_digest_in_ro_session(
            rs,
            SimpleNamespace(pin=None),
        )


def test_ro_session_setup_aes_keygen_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_ro_session_restrictions,
        "require_operational_aes_keygen",
        lambda _rs: None,
        raising=False,
    )
    keygen_attr = (
        "_raw_gen_aes_key"
        if hasattr(test_ro_session_restrictions, "_raw_gen_aes_key")
        else "gen_aes_key"
    )
    monkeypatch.setattr(test_ro_session_restrictions, keygen_attr, _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")
    rs.slot_id = 1
    monkeypatch.setattr(
        test_ro_session_restrictions,
        "skip_if_token_write_protected",
        lambda *_args: None,
    )

    with pytest.raises(pytest.xfail.Exception, match="RO-session token-object setup"):
        test_ro_session_restrictions.TestROTokenObjectMutation().test_destroy_token_object_in_ro_fails(
            rs,
        )


def test_ro_session_negative_aes_operation_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Pin:
        def get_secret_value(self) -> str:
            return "1234"

    class _FakeRaw:
        def C_Login(self, *_args: Any) -> int:  # noqa: N802 - PKCS#11 name.
            return int(CKR_OK)

        def C_GenerateKey(self, *_args: Any) -> int:  # noqa: N802 - PKCS#11 name.
            return int(CKR_FUNCTION_NOT_SUPPORTED)

    open_attr = (
        "_raw_open_session"
        if hasattr(test_ro_session_restrictions, "_raw_open_session")
        else "raw_open_session"
    )
    monkeypatch.setattr(test_ro_session_restrictions, open_attr, lambda *_a: 2)
    monkeypatch.setattr(test_ro_session_restrictions, "close_session_quietly", lambda *_a: None)
    rs = SimpleNamespace(
        raw=_FakeRaw(),
        slot_id=1,
        has_mechanism=lambda name: name == "AES_KEY_GEN",
    )

    with pytest.raises(pytest.xfail.Exception, match="RO restriction AES key generation"):
        test_ro_session_restrictions.TestROTokenObjectCreation().test_generate_key_token_true_in_ro_fails(
            rs,
            SimpleNamespace(pin=_Pin()),
        )


def test_object_visibility_extra_session_capacity_reject_is_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _open_session_limit(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_SESSION_COUNT",
            int(CKR_SESSION_COUNT),
        )

    open_attr = (
        "_raw_open_session"
        if hasattr(test_object_visibility, "_raw_open_session")
        else "raw_open_session"
    )
    monkeypatch.setattr(test_object_visibility, open_attr, _open_session_limit)

    with pytest.raises(pytest.skip.Exception, match="object-visibility session"):
        test_object_visibility._open_rw_session(object(), 1, None)


def test_object_visibility_aes_setup_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    monkeypatch.setattr(test_object_visibility, "destroy_quietly", lambda *_args: None)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(
        pytest.xfail.Exception, match="AES_KEY_GEN advertised but.*is not operational"
    ):
        test_object_visibility.TestSessionObjectLifecycle().test_session_object_exists_while_session_open(
            rs
        )


def test_object_visibility_data_object_setup_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_attr = (
        "_raw_create_object"
        if hasattr(test_object_visibility, "_raw_create_object")
        else "create_object"
    )
    monkeypatch.setattr(test_object_visibility, create_attr, _raise_attribute_value_invalid)
    rs = _session_with_mechanisms()

    with pytest.raises(pytest.xfail.Exception, match="data object setup rejected"):
        test_object_visibility.TestTokenPrivateInteraction().test_public_session_obj_visible_same_session(
            rs
        )


def test_search_aes_setup_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    if hasattr(test_search, "gen_aes_key"):
        monkeypatch.setattr(test_search, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="object search"):
        test_search.TestObjectSearch().test_find_by_label(rs)


def test_search_rsa_setup_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(raw_recipes, "gen_rsa_keypair", _raise_function_not_supported)
    if hasattr(test_search, "gen_rsa_keypair"):
        monkeypatch.setattr(test_search, "gen_rsa_keypair", _raise_function_not_supported)
    rs = _session_with_mechanisms("RSA_PKCS_KEY_PAIR_GEN")

    with pytest.raises(pytest.xfail.Exception, match="keypair generation"):
        test_search.TestKeyPairSearch().test_find_public_key(rs)


def test_object_search_patterns_aes_setup_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    if hasattr(test_object_search_patterns, "gen_aes_key"):
        monkeypatch.setattr(
            test_object_search_patterns,
            "gen_aes_key",
            _raise_function_not_supported,
        )
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="object search"):
        test_object_search_patterns.TestSearchByID().test_find_key_by_id(rs)


def test_object_search_patterns_rsa_setup_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_rsa_keypair", _raise_function_not_supported)
    if hasattr(test_object_search_patterns, "gen_rsa_keypair"):
        monkeypatch.setattr(
            test_object_search_patterns,
            "gen_rsa_keypair",
            _raise_function_not_supported,
        )
    rs = _session_with_mechanisms("RSA_PKCS_KEY_PAIR_GEN")

    with pytest.raises(pytest.xfail.Exception, match="keypair generation"):
        test_object_search_patterns.TestKeypairIDLinkage().test_rsa_keypair_same_id(rs)


def test_set_attribute_aes_setup_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    if hasattr(test_set_attribute, "gen_aes_key"):
        monkeypatch.setattr(test_set_attribute, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="set-attribute"):
        test_set_attribute.TestSetAttributePositive().test_change_label(rs)


def test_set_attribute_rsa_setup_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_rsa_keypair", _raise_function_not_supported)
    if hasattr(test_set_attribute, "gen_rsa_keypair"):
        monkeypatch.setattr(test_set_attribute, "gen_rsa_keypair", _raise_function_not_supported)
    rs = _session_with_mechanisms("RSA_PKCS_KEY_PAIR_GEN")

    with pytest.raises(pytest.xfail.Exception, match="keypair generation"):
        test_set_attribute.TestSetAttributePositive().test_change_label_on_keypair(rs)


def test_access_levels_user_setattr_trusted_reject_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _set_attributes(*_args: Any, **_kwargs: Any) -> None:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ATTRIBUTE_TYPE_INVALID",
            int(CKR_ATTRIBUTE_TYPE_INVALID),
        )

    monkeypatch.setattr(test_access_levels, "require_operational_aes_keygen", lambda _rs: None)
    monkeypatch.setattr(test_access_levels, "gen_aes_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(
        test_access_levels,
        "read_attributes",
        lambda *_args, **_kwargs: {test_access_levels.CKA_TRUSTED: False},
    )
    monkeypatch.setattr(test_access_levels, "set_attributes", _set_attributes)
    monkeypatch.setattr(test_access_levels, "destroy_quietly", lambda *_args, **_kwargs: None)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    test_access_levels.TestTrustedAttribute().test_user_cannot_setattr_trusted(rs)


def test_access_levels_user_setattr_trusted_setup_bug_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _broken_setup(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("ctypes packing bug before trusted setattr")

    monkeypatch.setattr(test_access_levels, "_gen_access_aes_key", _broken_setup)
    monkeypatch.setattr(
        test_access_levels.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(AssertionError, match="ctypes packing bug"):
        test_access_levels.TestTrustedAttribute().test_user_cannot_setattr_trusted(rs)


def test_access_levels_wrap_with_trusted_uses_cbc_pad_iv_when_key_wrap_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeMech:
        def byref(self) -> str:
            return "mech"

    class _Raw:
        def C_WrapKey(  # noqa: N802 - mirrors the PKCS#11 function name.
            self,
            _sh: int,
            _mech: str,
            _wrapper: int,
            _target: int,
            _out: object,
            _out_len: object,
        ) -> int:
            return int(CKR_ACTION_PROHIBITED)

    mech_calls: list[tuple[int, bytes]] = []
    handles = iter([10, 20])

    def _mech_bytes(mechanism: int, parameter: bytes) -> _FakeMech:
        mech_calls.append((int(mechanism), parameter))
        return _FakeMech()

    def _mech_simple(_mechanism: int) -> _FakeMech:
        pytest.fail("AES_CBC_PAD fallback must use an IV parameter")

    monkeypatch.setattr(test_access_levels, "require_operational_aes_keygen", lambda _rs: None)
    monkeypatch.setattr(test_access_levels, "gen_aes_key", lambda *_args, **_kwargs: next(handles))
    monkeypatch.setattr(
        test_access_levels,
        "read_attributes",
        lambda *_args, **_kwargs: {test_access_levels.CKA_WRAP_WITH_TRUSTED: True},
    )
    monkeypatch.setattr(test_access_levels, "mech_bytes", _mech_bytes)
    monkeypatch.setattr(test_access_levels, "mech_simple", _mech_simple)
    monkeypatch.setattr(test_access_levels, "destroy_quietly", lambda *_args, **_kwargs: None)
    rs = SimpleNamespace(
        raw=_Raw(),
        sh=1,
        has_mechanism=lambda name: name in {"AES_KEY_GEN", "AES_CBC_PAD"},
    )

    test_access_levels.TestTrustedAttribute().test_wrap_with_trusted_rejects_untrusted(rs)

    assert mech_calls == [(int(CKM_AES_CBC_PAD), b"\x00" * 16)]


def test_access_levels_always_auth_keygen_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _keygen_general_error(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    rs = _session_with_mechanisms("RSA_PKCS_KEY_PAIR_GEN", "SHA256_RSA_PKCS")
    monkeypatch.setattr(raw_recipes, "gen_rsa_keypair", _keygen_general_error)
    monkeypatch.setattr(test_access_levels, "gen_rsa_keypair", _keygen_general_error)
    monkeypatch.setattr(
        test_access_levels.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    with pytest.raises(pytest.xfail.Exception, match="CKA_ALWAYS_AUTHENTICATE"):
        test_access_levels.TestAlwaysAuthenticate().test_always_authenticate_key_requires_reauth(rs)


def test_access_levels_always_auth_context_keygen_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _keygen_general_error(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    rs = _session_with_mechanisms("RSA_PKCS_KEY_PAIR_GEN", "SHA256_RSA_PKCS")
    p11_config = SimpleNamespace(pin="1234")
    monkeypatch.setattr(raw_recipes, "gen_rsa_keypair", _keygen_general_error)
    monkeypatch.setattr(test_access_levels, "gen_rsa_keypair", _keygen_general_error)
    monkeypatch.setattr(
        test_access_levels.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    with pytest.raises(pytest.xfail.Exception, match="CKA_ALWAYS_AUTHENTICATE"):
        test_access_levels.TestAlwaysAuthenticate().test_always_authenticate_with_context_login(
            rs, p11_config
        )


def test_mech_lifecycle_digest_aes_keygen_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("SHA256", "AES_ECB", "AES_KEY_GEN")
    monkeypatch.setattr(test_mech_lifecycle, "digest_single", lambda *_args: b"\x00" * 32)
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_mech_lifecycle.TestDigestThenEncrypt().test_sha256_digest_then_aes_ecb_encrypt(rs)


def test_mech_lifecycle_batch_aes_keygen_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("AES_ECB", "AES_KEY_GEN")
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_mech_lifecycle.TestBatchAESKeys().test_batch_keygen_encrypt_destroy(rs)


def test_mech_lifecycle_rsa_oaep_keygen_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("RSA_PKCS_KEY_PAIR_GEN", "RSA_PKCS_OAEP", "AES_ECB")
    monkeypatch.setattr(raw_recipes, "gen_rsa_keypair", _raise_attribute_value_invalid)

    with pytest.raises(pytest.xfail.Exception, match="RSA_PKCS_KEY_PAIR_GEN advertised"):
        test_mech_lifecycle.TestRSAOAEPWrapLifecycle().test_rsa_oaep_wrap_aes_roundtrip(rs)


def test_mech_lifecycle_ecdh_keygen_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("EC_KEY_PAIR_GEN", "ECDH1_DERIVE", "AES_CBC")
    monkeypatch.setattr(raw_recipes, "gen_ec_keypair", _raise_attribute_value_invalid)

    with pytest.raises(pytest.xfail.Exception, match="EC_KEY_PAIR_GEN advertised"):
        test_mech_lifecycle.TestECDHDerivedKeyUse().test_ecdh_derive_and_use(rs)


def test_mechanism_attribute_read_value_invalid_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _read_attributes(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID",
            int(CKR_ATTRIBUTE_VALUE_INVALID),
        )

    monkeypatch.setattr(test_mech_attribute, "read_attributes", _read_attributes)
    rs = _session_with_mechanisms()

    with pytest.raises(pytest.xfail.Exception, match="non-clean CKR"):
        test_mech_attribute._read_attr_safe(rs, 1, 2, "CKA_KEY_TYPE")


def test_mech_keygen_local_read_value_invalid_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = SimpleNamespace(
        mech_name="HKDF_KEY_GEN",
        config=SimpleNamespace(is_param_gen=False, is_keypair=False),
    )
    rs = SimpleNamespace(raw=object(), sh=1)

    monkeypatch.setattr(test_mech_keygen, "gen_symmetric_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_mech_keygen, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        test_mech_keygen,
        "read_attributes",
        _raise_attribute_value_invalid,
    )

    with pytest.raises(pytest.xfail.Exception, match="CKA_LOCAL read rejected"):
        test_mech_keygen.TestMechKeygen().test_local_flag(rs, entry)


def test_mech_keygen_local_false_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = SimpleNamespace(
        mech_name="AES_KEY_GEN",
        config=SimpleNamespace(is_param_gen=False, is_keypair=False),
    )
    rs = SimpleNamespace(raw=object(), sh=1)

    monkeypatch.setattr(test_mech_keygen, "gen_symmetric_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_mech_keygen, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        test_mech_keygen,
        "read_attributes",
        lambda *_args, **_kwargs: {test_mech_keygen.CKA_LOCAL: False},
    )

    with pytest.raises(pytest.xfail.Exception, match="CKA_LOCAL=False"):
        test_mech_keygen.TestMechKeygen().test_local_flag(rs, entry)


def test_mechanism_attribute_local_false_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = SimpleNamespace(
        mech_name="AES_KEY_GEN",
        config=SimpleNamespace(is_param_gen=False, is_keypair=False, key_type=None),
    )
    rs = SimpleNamespace(raw=object(), sh=1)

    monkeypatch.setattr(test_mech_attribute, "needs_domain_params", lambda _config: False)
    monkeypatch.setattr(test_mech_attribute, "gen_symmetric_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_mech_attribute, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        test_mech_attribute,
        "read_attributes",
        lambda *_args, **_kwargs: {test_mech_attribute.CKA_LOCAL: False},
    )

    with pytest.raises(pytest.xfail.Exception, match="CKA_LOCAL=False"):
        test_mech_attribute.TestKeyAttributes().test_local_flag_on_generated_key(rs, entry)


def test_mechanism_attribute_malformed_ulong_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = SimpleNamespace(
        mech_name="DES3_KEY_GEN",
        config=SimpleNamespace(
            is_param_gen=False,
            is_keypair=False,
            key_type=CKK_AES,
        ),
    )
    rs = SimpleNamespace(raw=object(), sh=1)

    monkeypatch.setattr(test_mech_attribute, "needs_domain_params", lambda _config: False)
    monkeypatch.setattr(test_mech_attribute, "gen_symmetric_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_mech_attribute, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        test_mech_attribute,
        "read_attributes",
        lambda *_args, **_kwargs: {test_mech_attribute.CKA_KEY_TYPE: b""},
    )

    with pytest.raises(pytest.xfail.Exception, match="malformed CK_ULONG"):
        test_mech_attribute.TestKeyAttributes().test_key_type_matches_template(rs, entry)


def test_key_gen_mechanism_malformed_ulong_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = SimpleNamespace(raw=object(), sh=1)

    monkeypatch.setattr(
        test_attribute_enforcement,
        "import_secret_key",
        lambda *_args, **_kwargs: 1,
    )
    monkeypatch.setattr(
        test_attribute_enforcement,
        "read_attributes",
        lambda *_args, **_kwargs: {test_attribute_enforcement.CKA_KEY_GEN_MECHANISM: b""},
    )
    monkeypatch.setattr(
        test_attribute_enforcement,
        "destroy_quietly",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(pytest.xfail.Exception, match="malformed CK_ULONG"):
        test_attribute_enforcement.TestKeyGenMechanism().test_imported_key_has_unavailable(rs)


def test_attribute_enforcement_aes_keygen_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("AES_KEY_GEN")
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_attribute_enforcement.TestDestroyable().test_destroyable_readable(rs)


def test_ckr_wrap_mechanism_invalid_skips_without_aes_key_wrap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("AES_KEY_GEN")

    def _unexpected_keygen(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("setup should not run without AES_KEY_WRAP")

    monkeypatch.setattr(test_ckr_wrap, "gen_aes_key", _unexpected_keygen)

    with pytest.raises(pytest.skip.Exception, match="AES_KEY_WRAP not supported"):
        test_ckr_wrap.TestWrapKeyErrors().test_mechanism_invalid(rs, ckr_strict=False)


def test_ckr_wrap_size_range_general_error_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Undersized-wrap stays a 3-way code-conformance check.

    The PKCS#11 spec mandates CKR_WRAPPING_KEY_SIZE_RANGE for C_WrapKey with a
    too-small wrapping key. softhsm2 returns the catch-all CKR_GENERAL_ERROR
    here; the classifier records that as an honest xfail (a documented
    conformance deviation), NOT a silent pass (the old size_range_on_wrap quirk
    masked it as a pass).
    """
    raw = SimpleNamespace(C_WrapKey=lambda *_args: int(CKR_GENERAL_ERROR))
    rs = SimpleNamespace(
        raw=raw,
        sh=1,
        has_mechanism=lambda name: name == "AES_KEY_WRAP",
    )
    p11_config = SimpleNamespace(module="/usr/lib/softhsm/libsofthsm2.so")

    monkeypatch.setattr(test_ckr_wrap, "import_secret_key", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(test_ckr_wrap, "gen_aes_key", lambda *_args, **_kwargs: 12)
    monkeypatch.setattr(test_ckr_wrap, "destroy_quietly", lambda *_args, **_kwargs: None)

    with pytest.raises(pytest.xfail.Exception, match="WRAPPING_KEY_SIZE_RANGE"):
        test_ckr_wrap.TestWrapKeyErrors().test_wrapping_key_size_range(
            rs,
            p11_config,
            ckr_strict=False,
        )


def test_attribute_enforcement_date_setup_python_bug_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("AES_KEY_GEN")

    def _broken_keygen(*_args: Any, **_kwargs: Any) -> int:
        raise ValueError("date setup bug with CKR_FUNCTION_FAILED text")

    monkeypatch.setattr(test_attribute_enforcement, "gen_aes_key_or_xfail", _broken_keygen)

    try:
        test_attribute_enforcement.TestDateAttributes().test_start_end_date_on_generated_key(rs)
    except BaseException as exc:
        assert isinstance(exc, ValueError)
        assert "date setup bug" in str(exc)
    else:
        pytest.fail("Expected date setup Python bug to propagate")


def test_attribute_enforcement_date_read_python_bug_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("AES_KEY_GEN")
    destroyed: list[int] = []

    monkeypatch.setattr(test_attribute_enforcement, "gen_aes_key_or_xfail", lambda *_a, **_k: 7)
    monkeypatch.setattr(
        test_attribute_enforcement,
        "destroy_quietly",
        lambda *_a: destroyed.append(7),
    )

    def _broken_read(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        raise TypeError("date read bug with CKR_GENERAL_ERROR text")

    monkeypatch.setattr(test_attribute_enforcement, "read_attributes", _broken_read)

    try:
        test_attribute_enforcement.TestDateAttributes().test_start_end_date_on_generated_key(rs)
    except BaseException as exc:
        assert isinstance(exc, TypeError)
        assert "date read bug" in str(exc)
    else:
        pytest.fail("Expected date read Python bug to propagate")

    assert destroyed == [7]


def test_attribute_enforcement_always_auth_malformed_bool_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("RSA_PKCS_KEY_PAIR_GEN")

    monkeypatch.setattr(
        test_attribute_enforcement,
        "gen_rsa_keypair",
        lambda *_args, **_kwargs: (1, 2),
    )
    monkeypatch.setattr(
        test_attribute_enforcement,
        "read_attributes",
        lambda *_args, **_kwargs: {test_attribute_enforcement.CKA_ALWAYS_AUTHENTICATE: b""},
    )
    monkeypatch.setattr(
        test_attribute_enforcement,
        "destroy_quietly",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(pytest.xfail.Exception, match="malformed CK_BBOOL"):
        test_attribute_enforcement.TestAlwaysAuthenticate().test_always_authenticate_readable(rs)


def test_attribute_defaults_malformed_read_bool_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_attribute_defaults,
        "read_attributes",
        lambda *_args, **_kwargs: {test_attribute_defaults.CKA_PRIVATE: b""},
    )

    with pytest.raises(pytest.xfail.Exception, match="malformed CK_BBOOL"):
        test_attribute_defaults._read_attr(object(), 1, 2, test_attribute_defaults.CKA_PRIVATE)


def test_attribute_defaults_direct_malformed_bool_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = SimpleNamespace(raw=object(), sh=1)
    monkeypatch.setattr(
        test_attribute_defaults,
        "read_attributes",
        lambda *_args, **_kwargs: {test_attribute_defaults.CKA_TOKEN: b""},
    )

    with pytest.raises(pytest.xfail.Exception, match="malformed CK_BBOOL"):
        test_attribute_defaults.TestDataObjectDefaults().test_token_is_false((rs, 1))


def test_attribute_defaults_aes_keygen_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("AES_KEY_GEN")
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    monkeypatch.setattr(
        test_attribute_defaults.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    fixture = test_attribute_defaults.TestSecretKeyDefaults().aes_key.__wrapped__
    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        next(fixture(test_attribute_defaults.TestSecretKeyDefaults(), rs))


def test_attribute_defaults_rsa_keygen_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("RSA_PKCS_KEY_PAIR_GEN")
    monkeypatch.setattr(raw_recipes, "gen_rsa_keypair", _raise_attribute_value_invalid)
    monkeypatch.setattr(
        test_attribute_defaults.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    fixture = test_attribute_defaults.TestKeyPairDefaults().rsa_keypair.__wrapped__
    with pytest.raises(pytest.xfail.Exception, match="RSA_PKCS_KEY_PAIR_GEN advertised"):
        next(fixture(test_attribute_defaults.TestKeyPairDefaults(), rs))


def test_mechanism_attribute_local_malformed_bool_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = SimpleNamespace(
        mech_name="DES3_KEY_GEN",
        config=SimpleNamespace(is_param_gen=False, is_keypair=False),
    )
    rs = SimpleNamespace(raw=object(), sh=1)

    monkeypatch.setattr(test_mech_attribute, "needs_domain_params", lambda _config: False)
    monkeypatch.setattr(test_mech_attribute, "gen_symmetric_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_mech_attribute, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        test_mech_attribute,
        "read_attributes",
        lambda *_args, **_kwargs: {test_mech_attribute.CKA_LOCAL: b""},
    )

    with pytest.raises(pytest.xfail.Exception, match="malformed CK_BBOOL"):
        test_mech_attribute.TestKeyAttributes().test_local_flag_on_generated_key(rs, entry)


def test_mechanism_attribute_token_malformed_bool_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = SimpleNamespace(
        mech_name="DES3_KEY_GEN",
        config=SimpleNamespace(is_param_gen=False, is_keypair=False),
    )
    rs = SimpleNamespace(raw=object(), sh=1)

    monkeypatch.setattr(test_mech_attribute, "needs_domain_params", lambda _config: False)
    monkeypatch.setattr(test_mech_attribute, "gen_symmetric_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_mech_attribute, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        test_mech_attribute,
        "read_attributes",
        lambda *_args, **_kwargs: {test_mech_attribute.CKA_TOKEN: b""},
    )

    with pytest.raises(pytest.xfail.Exception, match="malformed CK_BBOOL"):
        test_mech_attribute.TestKeyAttributes().test_token_flag_matches_template(rs, entry)


def test_interop_malformed_rsa_public_attrs_are_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("RSA_PKCS_KEY_PAIR_GEN")

    monkeypatch.setattr(test_interop, "gen_rsa_keypair", lambda *_args, **_kwargs: (1, 2))
    monkeypatch.setattr(
        _rsa_export,
        "read_attributes",
        lambda *_args, **_kwargs: {
            _rsa_export.CKA_MODULUS: b"",
            _rsa_export.CKA_PUBLIC_EXPONENT: b"\x01\x00\x01",
        },
    )
    monkeypatch.setattr(test_interop, "destroy_quietly", lambda *_args, **_kwargs: None)

    with pytest.raises(pytest.xfail.Exception, match="malformed RSA public attributes"):
        test_interop.TestRSAInterop().test_rsa_pubkey_pem_roundtrip(rs)


def test_interop_missing_rsa_hash_mechanism_skips_before_keygen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("RSA_PKCS_KEY_PAIR_GEN")

    monkeypatch.setattr(
        test_interop,
        "gen_rsa_keypair",
        lambda *_args, **_kwargs: pytest.fail("keygen should not run"),
    )

    with pytest.raises(pytest.skip.Exception, match="SHA256_RSA_PKCS not supported"):
        test_interop.TestRSAInterop().test_sign_in_p11_verify_in_crypto(rs)


def test_interop_missing_ecdsa_mechanism_skips_before_keygen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("EC_KEY_PAIR_GEN")

    monkeypatch.setattr(
        test_interop,
        "gen_ec_keypair",
        lambda *_args, **_kwargs: pytest.fail("EC keygen should not run"),
    )

    with pytest.raises(pytest.skip.Exception, match="ECDSA not supported"):
        test_interop.TestECDSAInterop().test_ecdsa_sign_p11_verify_crypto(rs)


def test_crossverify_missing_aes_ecb_skips_before_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms()

    monkeypatch.setattr(
        test_crossverify,
        "_import_aes_key_raw",
        lambda *_args, **_kwargs: pytest.fail("AES import should not run"),
    )

    with pytest.raises(pytest.skip.Exception, match="AES_ECB not supported"):
        test_crossverify.TestAESCrossVerify().test_aes_256_ecb_encrypt(rs)


def test_crossverify_missing_digest_mechanism_skips_before_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms()

    monkeypatch.setattr(
        test_crossverify,
        "digest_single",
        lambda *_args, **_kwargs: pytest.fail("digest should not run"),
    )

    with pytest.raises(pytest.skip.Exception, match="SHA256 not supported"):
        test_crossverify.TestDigestCrossVerify().test_sha256(rs)


def test_crossverify_aes_import_sets_allowed_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    rs = _session_with_mechanisms("AES_ECB")

    def _capture_import(*_args: Any, attrs: dict[Any, Any] | None = None) -> int:
        captured["attrs"] = attrs
        return 1

    monkeypatch.setattr(test_crossverify, "import_secret_key", _capture_import)

    key = test_crossverify._import_aes_key_raw(rs, bytes(range(16)), test_crossverify.CKM_AES_ECB)

    assert key == 1
    assert captured["attrs"][test_crossverify.CKA_ALLOWED_MECHANISMS] == [
        test_crossverify.CKM_AES_ECB
    ]


def test_crossverify_rsa_keygen_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_mechanisms("RSA_PKCS_KEY_PAIR_GEN", "SHA256_RSA_PKCS")

    monkeypatch.setattr(raw_recipes, "gen_rsa_keypair", _raise_attribute_value_invalid)

    with pytest.raises(pytest.xfail.Exception, match="RSA_PKCS_KEY_PAIR_GEN advertised"):
        test_crossverify.TestRSACrossVerify().test_rsa_4096_sign(rs)


def test_crossverify_missing_rsa_private_attrs_are_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "RSA_PKCS_OAEP",
    )

    monkeypatch.setattr(
        test_crossverify_extended,
        "gen_rsa_keypair",
        lambda *_args, **_kwargs: (1, 2),
    )
    monkeypatch.setattr(
        test_crossverify_extended,
        "encrypt_single",
        lambda *_args, **_kwargs: b"ct",
    )
    monkeypatch.setattr(
        _rsa_export,
        "read_attributes",
        lambda *_args, **_kwargs: {
            _rsa_export.CKA_MODULUS: (2**2048 - 159).to_bytes(256, "big"),
            _rsa_export.CKA_PUBLIC_EXPONENT: b"\x01\x00\x01",
        },
    )
    monkeypatch.setattr(
        test_crossverify_extended,
        "destroy_quietly",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(pytest.xfail.Exception, match="missing RSA private attribute"):
        test_crossverify_extended.TestRSAOAEPCrossVerify().test_rsa_oaep_encrypt_p11_decrypt_crypto(
            rs
        )


def test_raw_state_setup_keygen_failure_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_ckr_raw_state,
        "_run",
        lambda *_args, **_kwargs: (
            0,
            "SETUP_XFAIL:C_GenerateKey failed:CKR_MECHANISM_INVALID",
            "",
        ),
    )
    config = SimpleNamespace(module="/tmp/provider.so", pin=None)

    with pytest.raises(pytest.xfail.Exception, match="C_GenerateKey failed"):
        test_ckr_raw_state.TestOperationActive().test_double_encrypt_init(config)


def test_raw_state_script_formats_setup_ckr_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def _run_subprocess(args: list[str], **_kwargs: Any) -> SimpleNamespace:
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout="OK\n", stderr="")

    monkeypatch.setattr(test_ckr_raw_state.subprocess, "run", _run_subprocess)

    rc, out, err = test_ckr_raw_state._run("/tmp/provider.so", None, "print('OK')\n")

    assert rc == 0
    assert out == "OK"
    assert err == ""
    assert "SETUP_XFAIL:C_GenerateKey failed:{ckr_name(rv)}" in calls[0][2]


def test_mech_wrap_builds_rc2_cbc_params() -> None:
    entry = SimpleNamespace(
        mech_name="RC2_CBC",
        mech_id=int(CKM_RC2_CBC),
        config=SimpleNamespace(
            param_required=True,
            param_recipe=ParamRecipe("rc2_cbc", defaults={"effective_bits": 128}),
        ),
    )

    assert test_mech_wrap._make_wrap_mech_param(entry) is not None


def test_mech_wrap_kwp_uses_output_size_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = SimpleNamespace(
        mech_name="AES_KEY_WRAP_KWP",
        mech_id=int(CKM_AES_KEY_WRAP_KWP),
        config=SimpleNamespace(
            key_type=CKK_AES,
            input_constraint="none",
            param_required=False,
            param_recipe=ParamRecipe("none"),
        ),
    )
    rs = _session_with_mechanisms("AES_KEY_WRAP_KWP")
    output_hints: list[int] = []

    monkeypatch.setattr(test_mech_wrap, "_build_aes_wrap_key", lambda *_args: 10)
    monkeypatch.setattr(test_mech_wrap, "_build_target_aes_key", lambda *_args: 20)
    monkeypatch.setattr(
        test_mech_wrap,
        "read_attributes",
        lambda *_args, **_kwargs: {test_mech_wrap.CKA_VALUE: b"\x5a" * 16},
    )
    monkeypatch.setattr(
        test_mech_wrap,
        "encrypt_single",
        lambda *_args, **_kwargs: b"ciphertext",
    )
    monkeypatch.setattr(
        test_mech_wrap,
        "decrypt_single",
        lambda *_args, **_kwargs: b"\x5a\xa5\x5a\xa5" * 4,
    )
    monkeypatch.setattr(
        test_mech_wrap,
        "unwrap_key_for_mechanism_roundtrip",
        lambda *_args, **_kwargs: 30,
    )
    monkeypatch.setattr(test_mech_wrap, "destroy_quietly", lambda *_args, **_kwargs: None)

    def _wrap_key(*_args: Any, output_size_hint: int = 0, **_kwargs: Any) -> bytes:
        output_hints.append(output_size_hint)
        return b"wrapped-key"

    monkeypatch.setattr(test_mech_wrap, "wrap_key", _wrap_key)

    test_mech_wrap.TestMechWrapRoundtrip().test_wrap_unwrap_aes_key(
        rs, SimpleNamespace(module="/tmp/vendor-pkcs11.so"), entry
    )

    assert output_hints == [64]


def test_mech_wrap_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = SimpleNamespace(
        mech_name="AES_CBC",
        mech_id=1,
        config=SimpleNamespace(
            key_type=CKK_AES,
            input_constraint="block_aligned",
            param_required=False,
            param_recipe=ParamRecipe("none"),
        ),
    )
    rs = _session_with_mechanisms("1")

    monkeypatch.setattr(test_mech_wrap, "ckm_name", lambda _mech_id: "CKM_1")
    monkeypatch.setattr(test_mech_wrap, "_build_aes_wrap_key", lambda *_args: 10)
    monkeypatch.setattr(test_mech_wrap, "_build_target_aes_key", lambda *_args: 20)
    monkeypatch.setattr(
        test_mech_wrap,
        "read_attributes",
        lambda *_args, **_kwargs: {test_mech_wrap.CKA_VALUE: b"\x5a" * 16},
    )
    monkeypatch.setattr(test_mech_wrap, "encrypt_single", lambda *_args, **_kwargs: b"cipher")
    monkeypatch.setattr(test_mech_wrap, "destroy_quietly", lambda *_args, **_kwargs: None)

    def _wrap_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID",
            int(CKR_MECHANISM_PARAM_INVALID),
        )

    monkeypatch.setattr(test_mech_wrap, "wrap_key", _wrap_reject)

    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        test_mech_wrap.TestMechWrapRoundtrip().test_wrap_unwrap_aes_key(
            rs, SimpleNamespace(module="/tmp/vendor-pkcs11.so"), entry
        )


def test_concurrent_sessions_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    monkeypatch.setattr(
        test_concurrent_sessions, "skip_if_token_write_protected", lambda *_args: None
    )
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        slot_id=1,
        has_mechanism=lambda name: name in {"AES_KEY_GEN", "AES_ECB"},
    )

    with pytest.raises(
        pytest.xfail.Exception, match="AES_KEY_GEN advertised but.*is not operational"
    ):
        test_concurrent_sessions.TestConcurrentObjectCreation().test_rapid_create_destroy_cycle(
            rs, SimpleNamespace()
        )


def test_ckr_codes_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(
        pytest.xfail.Exception, match="AES_KEY_GEN advertised but.*is not operational"
    ):
        test_ckr_codes.TestCKRMechanismErrors().test_ckr_mechanism_invalid(rs)


def test_ckr_object_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(
        pytest.xfail.Exception, match="AES_KEY_GEN advertised but.*is not operational"
    ):
        test_ckr_object.TestGetAttributeErrors().test_destroyed_handle(rs)


def test_ckr_spec_compliance_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(
        pytest.xfail.Exception, match="AES_KEY_GEN advertised but.*is not operational"
    ):
        test_ckr_spec_compliance.TestCKRMechanismCompliance().test_sha256_as_encrypt_returns_mechanism_invalid(
            rs
        )


def test_mech_state_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN", "AES_ECB")

    with pytest.raises(
        pytest.xfail.Exception, match="AES_KEY_GEN advertised but.*is not operational"
    ):
        test_mech_state.TestEncryptState().test_double_encrypt_init(rs)


def test_ro_session_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    monkeypatch.setattr(test_ro_session, "skip_if_token_write_protected", lambda *_args: None)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(
        pytest.xfail.Exception, match="AES_KEY_GEN advertised but.*is not operational"
    ):
        test_ro_session.TestROSessionOperations().test_find_objects_in_ro_session(
            rs, SimpleNamespace()
        )


def test_aead_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN", "AES_GCM")

    with pytest.raises(
        pytest.xfail.Exception, match="AES_KEY_GEN advertised but.*is not operational"
    ):
        test_aead.TestAESGCMProperties().test_gcm_roundtrip(rs)


def test_concurrent_sessions_skip_when_aes_keygen_not_advertised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AES_KEY_GEN absent → skip (was xfail before canonical-helper consolidation)."""
    monkeypatch.setattr(
        test_concurrent_sessions, "skip_if_token_write_protected", lambda *_args: None
    )
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        slot_id=1,
        has_mechanism=lambda _name: False,
    )
    with pytest.raises(pytest.skip.Exception, match="AES_KEY_GEN not supported"):
        test_concurrent_sessions.TestConcurrentObjectCreation().test_rapid_create_destroy_cycle(
            rs, SimpleNamespace()
        )


def test_ckr_codes_skip_when_aes_keygen_not_advertised() -> None:
    """AES_KEY_GEN absent → skip (was xfail/raise before canonical-helper consolidation)."""
    rs = _session_with_mechanisms()
    with pytest.raises(pytest.skip.Exception, match="AES_KEY_GEN not supported"):
        test_ckr_codes.TestCKRMechanismErrors().test_ckr_mechanism_invalid(rs)


def test_ckr_object_skip_when_aes_keygen_not_advertised() -> None:
    """AES_KEY_GEN absent → skip (was xfail/raise before canonical-helper consolidation)."""
    rs = _session_with_mechanisms()
    with pytest.raises(pytest.skip.Exception, match="AES_KEY_GEN not supported"):
        test_ckr_object.TestGetAttributeErrors().test_destroyed_handle(rs)


def test_ckr_spec_compliance_skip_when_aes_keygen_not_advertised() -> None:
    """AES_KEY_GEN absent → skip (was xfail/raise before canonical-helper consolidation)."""
    rs = _session_with_mechanisms()
    with pytest.raises(pytest.skip.Exception, match="AES_KEY_GEN not supported"):
        test_ckr_spec_compliance.TestCKRMechanismCompliance().test_sha256_as_encrypt_returns_mechanism_invalid(
            rs
        )


def test_mech_state_skip_when_aes_keygen_not_advertised() -> None:
    """AES_KEY_GEN absent → skip (was xfail/raise before canonical-helper consolidation)."""
    rs = _session_with_mechanisms("AES_ECB")
    with pytest.raises(pytest.skip.Exception, match="AES keygen not supported"):
        test_mech_state.TestEncryptState().test_double_encrypt_init(rs)


def test_ro_session_skip_when_aes_keygen_not_advertised() -> None:
    """AES_KEY_GEN absent → skip (was xfail/raise before canonical-helper consolidation)."""
    rs = _session_with_mechanisms()
    with pytest.raises(pytest.skip.Exception, match="AES_KEY_GEN not supported"):
        test_ro_session.TestROSessionOperations().test_find_objects_in_ro_session(
            rs, SimpleNamespace()
        )


def test_aead_skip_when_aes_keygen_not_advertised() -> None:
    """AES_KEY_GEN absent → skip (was xfail/raise before canonical-helper consolidation)."""
    rs = _session_with_mechanisms("AES_GCM")
    with pytest.raises(pytest.skip.Exception, match="AES_KEY_GEN not supported"):
        test_aead.TestAESGCMProperties().test_gcm_roundtrip(rs)


def test_mech_flags_missing_expected_flags_are_xfail() -> None:
    entry = SimpleNamespace(
        mech_name="PARTIAL_RSA_PKCS",
        flags=int(CKF_ENCRYPT),
        config=SimpleNamespace(expected_flags=int(CKF_ENCRYPT) | int(CKF_DECRYPT)),
    )

    with pytest.raises(pytest.xfail.Exception, match="missing expected mechanism capability"):
        test_mech_flags.TestMechFlags().test_expected_flags_present(
            SimpleNamespace(),
            entry,
        )


# ---------------------------------------------------------------------------
# Deferred tpm2 advertised-but-not-operational keygen/op setup sites
# (migrated to the canonical conftest helpers: gen_aes_key_or_xfail /
# gen_rsa_keypair_or_xfail / gen_ec_keypair_or_xfail / hmac_sign_or_xfail).
# Each drives the REAL product test with a monkeypatched raw recipe so the
# guard cannot be satisfied by a stub. The post-setup assertion of each
# product test stays OUTSIDE the wrapper -- a real finding on any provider
# still hard-fails.
# ---------------------------------------------------------------------------


# --- RSA keypair setup sites ------------------------------------------------


def test_encrypt_rsa_pkcs_xfail_when_advertised_rsa_keypair_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_rsa_keypair", _raise_attribute_value_invalid)
    rs = _session_with_mechanisms("RSA_PKCS_KEY_PAIR_GEN", "RSA_PKCS")

    with pytest.raises(pytest.xfail.Exception, match="RSA_PKCS_KEY_PAIR_GEN advertised"):
        test_encrypt.TestRSAEncryption().test_rsa_pkcs_roundtrip(rs)


def test_encrypt_rsa_oaep_xfail_when_advertised_rsa_keypair_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_rsa_keypair", _raise_attribute_value_invalid)
    rs = _session_with_mechanisms("RSA_PKCS_KEY_PAIR_GEN", "RSA_PKCS_OAEP")

    with pytest.raises(pytest.xfail.Exception, match="RSA_PKCS_KEY_PAIR_GEN advertised"):
        test_encrypt.TestRSAEncryption().test_rsa_oaep_roundtrip(rs)


def test_mech_sign_recover_xfail_when_advertised_rsa_keypair_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_rsa_keypair", _raise_attribute_value_invalid)

    class _Mod:
        @staticmethod
        def has_mechanism(name: str) -> bool:
            return name in {"RSA_PKCS_KEY_PAIR_GEN", "RSA_X_509"}

    session = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=_Mod.has_mechanism,
    )

    with pytest.raises(pytest.xfail.Exception, match="RSA_PKCS_KEY_PAIR_GEN advertised"):
        test_mech_sign_recover.TestSignRecover().test_rsa_x509_sign_recover_roundtrip(session)


# --- EC keypair setup sites -------------------------------------------------


def test_kdf_ecdh_xfail_when_advertised_ec_keypair_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_ec_keypair", _raise_attribute_value_invalid)
    rs = _session_with_mechanisms("EC_KEY_PAIR_GEN", "ECDH1_DERIVE")

    with pytest.raises(pytest.xfail.Exception, match="EC_KEY_PAIR_GEN advertised"):
        test_kdf.TestECDHDerive().test_ecdh_keypair_independence(rs)


# --- HMAC sign-op setup sites -----------------------------------------------


def test_kdf_hmac_as_kdf_xfail_when_advertised_hmac_sign_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "sign_single", _raise_general_error)
    monkeypatch.setattr(test_kdf, "import_secret_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_kdf, "destroy_quietly", lambda *_a, **_k: None)
    rs = _session_with_mechanisms("SHA256_HMAC")

    with pytest.raises(pytest.xfail.Exception, match="SHA256_HMAC advertised but sign"):
        test_kdf.TestKeyDeriveSoftware().test_hmac_as_kdf(rs)


def test_kdf_hmac_sha512_xfail_when_advertised_hmac_sign_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "sign_single", _raise_general_error)
    monkeypatch.setattr(test_kdf, "import_secret_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_kdf, "destroy_quietly", lambda *_a, **_k: None)
    rs = _session_with_mechanisms("SHA512_HMAC")

    with pytest.raises(pytest.xfail.Exception, match="SHA512_HMAC advertised but sign"):
        test_kdf.TestKeyDeriveSoftware().test_hmac_sha512_as_kdf(rs)


def test_kdf_hmac_as_kdf_skips_when_sha256_hmac_not_advertised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Capability absent (not advertised) → skip, not xfail."""

    def _unexpected_sign(*_a: Any, **_k: Any) -> bytes:
        raise AssertionError("sign_single should not run when SHA256_HMAC is not advertised")

    monkeypatch.setattr(raw_recipes, "sign_single", _unexpected_sign)
    monkeypatch.setattr(test_kdf, "import_secret_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_kdf, "destroy_quietly", lambda *_a, **_k: None)
    rs = _session_with_mechanisms()  # SHA256_HMAC absent

    with pytest.raises(pytest.skip.Exception, match="SHA256_HMAC not advertised"):
        test_kdf.TestKeyDeriveSoftware().test_hmac_as_kdf(rs)


def test_kdf_hmac_sha512_skips_when_sha512_hmac_not_advertised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Capability absent (not advertised) → skip, not xfail."""

    def _unexpected_sign(*_a: Any, **_k: Any) -> bytes:
        raise AssertionError("sign_single should not run when SHA512_HMAC is not advertised")

    monkeypatch.setattr(raw_recipes, "sign_single", _unexpected_sign)
    monkeypatch.setattr(test_kdf, "import_secret_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_kdf, "destroy_quietly", lambda *_a, **_k: None)
    rs = _session_with_mechanisms()  # SHA512_HMAC absent

    with pytest.raises(pytest.skip.Exception, match="SHA512_HMAC not advertised"):
        test_kdf.TestKeyDeriveSoftware().test_hmac_sha512_as_kdf(rs)


def test_kdf_hmac_as_kdf_wrong_mac_is_hard_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wrong MAC (CKR_OK + mismatch) must not be swallowed by hmac_sign_or_xfail."""

    def _sign_wrong_mac(*_a: Any, **_k: Any) -> bytes:
        # Return wrong bytes — caller's assert p11_mac == py_mac must fail
        return b"\xff" * 32

    monkeypatch.setattr(raw_recipes, "sign_single", _sign_wrong_mac)
    monkeypatch.setattr(test_kdf, "import_secret_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_kdf, "destroy_quietly", lambda *_a, **_k: None)
    rs = _session_with_mechanisms("SHA256_HMAC")

    with pytest.raises(AssertionError):
        test_kdf.TestKeyDeriveSoftware().test_hmac_as_kdf(rs)


# --- Remaining AES keygen setup sites ---------------------------------------


def test_ckr_derive_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_ckr_derive.TestDeriveKeyErrors().test_mechanism_invalid(rs, True)


def test_ckr_priority_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_ckr_priority.TestErrorPriority().test_bad_mechanism_with_bad_key_size(rs)


def test_ckr_sign_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_ckr_sign.TestSignInitErrors().test_key_type_inconsistent(rs, True)


def test_ckr_verify_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_ckr_verify.TestVerifyInitErrors().test_key_type_inconsistent(rs, True)


def test_duplicate_labels_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_duplicate_labels.TestDuplicateLabels().test_two_keys_same_label(rs)


def test_large_objects_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN", "AES_ECB")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_large_objects.TestLargeEncryption().test_encrypt_64kb_aes_ecb(rs)


def test_surface_audit_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    monkeypatch.setattr(test_surface_audit, "get_mechanism_info", lambda *_a, **_k: {})
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        slot_id=1,
        has_mechanism=lambda name: name in {"AES_KEY_GEN", "AES_ECB"},
    )

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_surface_audit.TestMechanismFlagsConsistency().test_aes_encrypt_flag_matches_capability(
            rs
        )


def test_parameter_validation_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN", "AES_CBC")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_parameter_validation.TestCbcIvAllZeros().test_cbc_iv_all_zeros(rs)


def test_tookan_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_tookan.TestSensitivePreservation().test_sensitive_preserved_on_copy(rs)


def test_interface_v30_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("CKM_AES_CBC_PAD")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_interface.TestInterfaceV30().test_v30_encrypt_decrypt_aes(rs)


# --- Alternate-session AES keygen setup sites (sh override) ------------------


def test_session_info_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    monkeypatch.setattr(test_session_info, "raw_open_session", lambda *_a, **_k: 7)
    monkeypatch.setattr(test_session_info, "login_user", lambda *_a, **_k: None)
    monkeypatch.setattr(test_session_info, "close_session_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(test_session_info, "get_pin_bytes", lambda _c: None)
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        slot_id=1,
        has_mechanism=lambda name: name == "AES_KEY_GEN",
    )

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_session_info.TestSessionInfo().test_session_has_token(rs, SimpleNamespace())


# --- AES-GCM crossverify op-capability gates (skip, not keygen wrapper) ------


def test_aead_gcm_crossverify_skips_when_gcm_not_advertised() -> None:
    """The 3 GCM crossverify tests must skip (not hard-fail) when a module does
    not advertise CKM_AES_GCM -- an op-capability gate, distinct from the
    keygen-setup wrapper class."""
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: False,  # AES_GCM absent
    )
    crossverify = test_aead.TestAESGCMCrossVerify()
    for method in (
        crossverify.test_gcm_256_encrypt_crossverify,
        crossverify.test_gcm_128_encrypt_crossverify,
        crossverify.test_gcm_decrypt_crossverify,
    ):
        with pytest.raises(pytest.skip.Exception, match="CKM_AES_GCM not supported"):
            method(rs)


def test_session_edge_cases_wrap_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_session_edge_cases.TestSoftHSM2IssueRegressions().test_wrap_unsupported_mechanism_returns_proper_ckr(
            rs
        )


def test_session_exhaustion_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    monkeypatch.setattr(test_session_exhaustion, "raw_open_session", lambda *_a, **_k: 7)
    monkeypatch.setattr(test_session_exhaustion, "close_session_quietly", lambda *_a, **_k: None)
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        slot_id=1,
        has_mechanism=lambda name: name == "AES_KEY_GEN",
    )
    config = SimpleNamespace(pin=None)

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_session_exhaustion.TestSessionExhaustion().test_open_many_sessions(rs, config)


def test_v30_session_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    monkeypatch.setattr(test_v30_session, "raw_open_session", lambda *_a, **_k: 7)
    monkeypatch.setattr(test_v30_session, "_pin_bytes", lambda _c: b"1234")
    monkeypatch.setattr(test_v30_session, "_raw_login", lambda *_a, **_k: int(CKR_OK))
    monkeypatch.setattr(test_v30_session, "_raw_logout", lambda *_a, **_k: int(CKR_OK))
    monkeypatch.setattr(test_v30_session, "close_session_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(test_v30_session, "destroy_quietly", lambda *_a, **_k: None)
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        slot_id=1,
        has_mechanism=lambda name: name == "AES_KEY_GEN",
    )

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_v30_session.TestLoginLogoutCycle().test_normal_login_logout(rs, SimpleNamespace())
