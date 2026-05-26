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
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases import (
    _rsa_export,
    test_access_levels,
    test_aes_modes,
    test_attribute_defaults,
    test_attribute_enforcement,
    test_authenticated_wrap,
    test_buffers,
    test_crossverify,
    test_crossverify_extended,
    test_generic_secret,
    test_interop,
    test_key_usage_policy,
    test_mech_attribute,
    test_mech_flags,
    test_mech_keygen,
    test_mech_wrap,
    test_mechanism_fuzz,
    test_object_size,
    test_rsa_oaep,
    test_sensitivity,
    test_sign_recover,
    test_stateful,
)
from pkcs11_check.testcases.ckr import (
    test_ckr_decrypt,
    test_ckr_encrypt,
    test_ckr_raw_state,
    test_ckr_wrap,
)
from pkcs11_check.testcases.mechanism_registry import ParamRecipe
from pkcs11_check.testcases.security import test_nonce_quality, test_padding_oracle


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


def test_ckr_wrap_size_range_uses_documented_softhsm2_quirk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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

    with pytest.raises(pytest.xfail.Exception, match="wrap rejected at runtime"):
        test_mech_wrap.TestMechWrapRoundtrip().test_wrap_unwrap_aes_key(
            rs, SimpleNamespace(module="/tmp/vendor-pkcs11.so"), entry
        )


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
