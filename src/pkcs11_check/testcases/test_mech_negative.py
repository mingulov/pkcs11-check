"""Negative tests for mechanism error handling.

Includes both explicit smoke examples and registry-driven operation-family cases.

Tests verify that the module correctly rejects operations with:
- Wrong key type (AES mechanism with RSA key, etc.)
- Missing CKA_* permission flags (CKA_ENCRYPT=False, etc.)

Each test is self-contained: it generates its own key, attempts the forbidden
operation, asserts CKR != CKR_OK, then destroys the key.
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import attr_ulong, mech_bytes, mech_simple, template
from pkcs11_check.raw.pack_mechanisms import mech_string_data
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
    encrypt_single,
    pack_attrs,
    read_attributes,
    sign_single,
    unwrap_key,
    wrap_key,
)
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKA_WRAP,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM,
    CKM_AES_ECB,
    CKM_AES_KEY_WRAP_KWP,
    CKM_ECDSA,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKM_RSA_PKCS,
    CKM_SHA256_HMAC,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
    CKR_WRAPPED_KEY_INVALID,
    CKR_WRAPPED_KEY_LEN_RANGE,
    CKR_WRAPPING_KEY_SIZE_RANGE,
    CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import (
    CIPHER_OP_RUNTIME_REJECT_RVS,
    IMPORT_STORAGE_SHAPE_REJECTS,
    classify_negative_rv,
    classify_policy_enforcement,
    gen_aes_key_or_xfail,
    gen_ec_keypair_or_xfail,
    gen_rsa_keypair_or_xfail,
    import_secret_key_negotiated,
    reject_or_classify,
    xfail_if_known_ckr,
)
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_helpers import (
    gen_symmetric_key,
    generate_key_for_encrypt,
    generate_key_for_sign,
    make_mech_param_or_skip,
)

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.negative]

_P256_OID: bytes = encode_named_curve_parameters("secp256r1")
_SECRET_KEY_RECIPE_STYLES = frozenset({"symmetric", "fixed_length", "generic"})
_WRONG_KEY_SETUP_REJECTS = (
    *IMPORT_STORAGE_SHAPE_REJECTS,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
)
_NO_SPECIFIC_WRAP_PERMISSION_RVS: tuple[int, ...] = ()
_MISSING_REQUIRED_PARAM_RVS = (CKR_MECHANISM_PARAM_INVALID,)
_MALFORMED_REQUIRED_PARAM_RVS = (CKR_MECHANISM_PARAM_INVALID, CKR_ARGUMENTS_BAD)
_MALFORMED_WRAPPED_BLOB_RVS = (
    CKR_WRAPPED_KEY_LEN_RANGE,
    CKR_WRAPPED_KEY_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ARGUMENTS_BAD,
)
_WRAP_SETUP_REJECT_RVS = (
    *CIPHER_OP_RUNTIME_REJECT_RVS,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_WRAPPING_KEY_SIZE_RANGE,
    CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
)


def _wrap_output_size_hint(entry: MechEntry) -> int:
    if int(entry.mech_id) == int(CKM_AES_KEY_WRAP_KWP):
        return 64
    return 0


_DERIVE_SHA_KEY_DERIV_MECHS: set[int] = set()
try:
    from pkcs11_check.raw.types_std import (
        CKM_SHA1_KEY_DERIVATION,
        CKM_SHA3_224_KEY_DERIVATION,
        CKM_SHA3_256_KEY_DERIVATION,
        CKM_SHA3_384_KEY_DERIVATION,
        CKM_SHA3_512_KEY_DERIVATION,
        CKM_SHA224_KEY_DERIVATION,
        CKM_SHA256_KEY_DERIVATION,
        CKM_SHA384_KEY_DERIVATION,
        CKM_SHA512_224_KEY_DERIVATION,
        CKM_SHA512_256_KEY_DERIVATION,
        CKM_SHA512_KEY_DERIVATION,
        CKM_SHA512_T_KEY_DERIVATION,
        CKM_SHAKE_128_KEY_DERIVATION,
        CKM_SHAKE_256_KEY_DERIVATION,
    )

    _DERIVE_SHA_KEY_DERIV_MECHS = {
        int(CKM_SHA1_KEY_DERIVATION),
        int(CKM_SHA224_KEY_DERIVATION),
        int(CKM_SHA256_KEY_DERIVATION),
        int(CKM_SHA384_KEY_DERIVATION),
        int(CKM_SHA512_KEY_DERIVATION),
        int(CKM_SHA512_224_KEY_DERIVATION),
        int(CKM_SHA512_256_KEY_DERIVATION),
        int(CKM_SHA512_T_KEY_DERIVATION),
        int(CKM_SHA3_224_KEY_DERIVATION),
        int(CKM_SHA3_256_KEY_DERIVATION),
        int(CKM_SHA3_384_KEY_DERIVATION),
        int(CKM_SHA3_512_KEY_DERIVATION),
        int(CKM_SHAKE_128_KEY_DERIVATION),
        int(CKM_SHAKE_256_KEY_DERIVATION),
    }
except ImportError:
    pass

_DERIVE_STRING_DATA_MECHS: set[int] = set()
_DERIVE_CONCAT_KEY_MECH_ID: int = 0
_DERIVE_EXTRACT_MECH_ID: int = 0
try:
    from pkcs11_check.raw.types_std import (
        CKM_CONCATENATE_BASE_AND_DATA,
        CKM_CONCATENATE_BASE_AND_KEY,
        CKM_CONCATENATE_DATA_AND_BASE,
        CKM_EXTRACT_KEY_FROM_KEY,
        CKM_XOR_BASE_AND_DATA,
    )

    _DERIVE_STRING_DATA_MECHS = {
        int(CKM_CONCATENATE_BASE_AND_DATA),
        int(CKM_CONCATENATE_DATA_AND_BASE),
        int(CKM_XOR_BASE_AND_DATA),
    }
    _DERIVE_CONCAT_KEY_MECH_ID = int(CKM_CONCATENATE_BASE_AND_KEY)
    _DERIVE_EXTRACT_MECH_ID = int(CKM_EXTRACT_KEY_FROM_KEY)
except ImportError:
    pass

_DERIVE_AES_ECB_ENCRYPT_DATA_ID: int = 0
try:
    from pkcs11_check.raw.types_std import CKM_AES_ECB_ENCRYPT_DATA

    _DERIVE_AES_ECB_ENCRYPT_DATA_ID = int(CKM_AES_ECB_ENCRYPT_DATA)
except ImportError:
    pass

_DERIVED_GENERIC_SECRET_ATTRS: dict[int, Any] = {
    CKA_CLASS: CKO_SECRET_KEY,
    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
    CKA_VALUE_LEN: 16,
    CKA_DERIVE: True,
    CKA_TOKEN: False,
    CKA_EXTRACTABLE: True,
    CKA_SENSITIVE: False,
}


def _derive_negative_param_or_skip(
    rs: RawSession,
    entry: MechEntry,
) -> tuple[Any | None, list[int]]:
    mech_id = int(entry.mech_id)
    if mech_id in _DERIVE_SHA_KEY_DERIV_MECHS:
        return None, []
    if _DERIVE_AES_ECB_ENCRYPT_DATA_ID and mech_id == _DERIVE_AES_ECB_ENCRYPT_DATA_ID:
        return mech_string_data(CKM(mech_id), b"derive__test__01"), []
    if mech_id in _DERIVE_STRING_DATA_MECHS:
        return mech_string_data(CKM(mech_id), b"pkcs11-check-derive"), []
    if _DERIVE_EXTRACT_MECH_ID and mech_id == _DERIVE_EXTRACT_MECH_ID:
        bit_index = ctypes.c_ulong(0)
        param_bytes = bytes(ctypes.string_at(ctypes.addressof(bit_index), ctypes.sizeof(bit_index)))
        return mech_bytes(CKM(mech_id), param_bytes), []
    if _DERIVE_CONCAT_KEY_MECH_ID and mech_id == _DERIVE_CONCAT_KEY_MECH_ID:
        config = entry.config
        assert config is not None
        addon_key = gen_symmetric_key(
            rs,
            entry,
            config,
            extra_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
        )
        handle_ctype = CK_OBJECT_HANDLE(addon_key)
        param_bytes = bytes(
            ctypes.string_at(ctypes.addressof(handle_ctype), ctypes.sizeof(handle_ctype))
        )
        return mech_bytes(CKM(mech_id), param_bytes), [addon_key]
    pytest.skip(f"{entry.mech_name}: registry derive negative needs dedicated params")


def _skip_if_not_secret_key_registry_case(entry: MechEntry) -> None:
    config = entry.config
    if config is None:
        pytest.skip(f"{entry.mech_name}: no registry config")
    if config.keygen_recipe.style not in _SECRET_KEY_RECIPE_STYLES:
        pytest.skip(f"{entry.mech_name}: registry negative permission test needs secret-key keygen")


def _skip_if_not_required_param_registry_case(entry: MechEntry) -> None:
    config = entry.config
    if config is None:
        pytest.skip(f"{entry.mech_name}: no registry config")
    if not config.param_required:
        pytest.skip(f"{entry.mech_name}: mechanism params are not required")


def _finish_digest_after_unexpected_ok(rs: RawSession) -> None:
    out_len = CK_ULONG(0)
    rv = rs.raw.C_DigestFinal(rs.sh, None, byref(out_len))
    if rv == CKR_OK and out_len.value > 0:
        out_buf = (ctypes.c_ubyte * out_len.value)()
        rs.raw.C_DigestFinal(rs.sh, out_buf, byref(out_len))


def _gen_claimed_false_secret_key(
    rs: RawSession,
    entry: MechEntry,
    flag: int,
    *,
    companion_attrs: dict[int, Any] | None = None,
) -> int:
    config = entry.config
    assert config is not None
    attrs: dict[int, Any] = {flag: False, CKA_TOKEN: False}
    if companion_attrs:
        attrs.update(companion_attrs)
    return gen_symmetric_key(rs, entry, config, extra_attrs=attrs)


def _claim_false_or_xfail(rs: RawSession, key: int, flag: int, label: str) -> None:
    attrs = read_attributes(rs.raw, rs.sh, key, [flag])
    claimed_false = attrs.get(flag) is False
    if not claimed_false:
        classify_policy_enforcement(
            claimed=False,
            violated=False,
            label=label,
        )


def _wrong_secret_key_type(entry: MechEntry) -> int:
    config = entry.config
    assert config is not None
    assert config.key_type is not None
    expected_key_type = int(config.key_type)
    if (
        expected_key_type != int(CKK_GENERIC_SECRET)
        and config.keygen_mech == CKM_GENERIC_SECRET_KEY_GEN
    ):
        pytest.skip(f"{entry.mech_name}: generic-secret key type may be valid")
    if expected_key_type == int(CKK_GENERIC_SECRET):
        return int(CKK_AES)
    return int(CKK_GENERIC_SECRET)


def _import_wrong_secret_key_or_xfail(
    rs: RawSession,
    entry: MechEntry,
    *,
    attrs: dict[int, Any],
) -> int:
    wrong_key_type = _wrong_secret_key_type(entry)
    try:
        return import_secret_key_negotiated(
            rs,
            wrong_key_type,
            b"\x42" * 32,
            attrs=attrs,
            purpose=f"{entry.mech_name} wrong-key negative setup",
        )
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            _WRONG_KEY_SETUP_REJECTS,
            f"{entry.mech_name}: wrong-key setup import rejected",
        )
        raise


class TestWrongKeyType:
    """EncryptInit/SignInit with wrong key type must be rejected."""

    def test_aes_ecb_with_rsa_key_rejected(self, p11_module_session: RawSession) -> None:
        """CKM_AES_ECB with an RSA private key must fail EncryptInit."""
        rs = p11_module_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")

        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            mech = mech_simple(CKM_AES_ECB)
            # Use the RSA private key handle with an AES mechanism
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), priv)
            assert rv != CKR_OK, (
                "C_EncryptInit(CKM_AES_ECB, RSA_priv) should fail but returned CKR_OK"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_pkcs_with_aes_key_rejected(self, p11_module_session: RawSession) -> None:
        """CKM_RSA_PKCS with an AES key must fail EncryptInit."""
        rs = p11_module_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("AES keygen not supported")

        key = gen_aes_key_or_xfail(rs, 256, purpose="wrong-key negative test setup")
        try:
            mech = mech_simple(CKM_RSA_PKCS)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            assert rv != CKR_OK, (
                "C_EncryptInit(CKM_RSA_PKCS, AES_key) should fail but returned CKR_OK"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_ecdsa_with_rsa_key_rejected(self, p11_module_session: RawSession) -> None:
        """CKM_ECDSA with an RSA key must fail SignInit."""
        rs = p11_module_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")

        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            mech = mech_simple(CKM_ECDSA)
            rv = rs.raw.C_SignInit(rs.sh, mech.byref(), priv)
            assert rv != CKR_OK, "C_SignInit(CKM_ECDSA, RSA_priv) should fail but returned CKR_OK"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_hmac_sha256_with_rsa_key_rejected(self, p11_module_session: RawSession) -> None:
        """CKM_SHA256_HMAC with an RSA key must fail SignInit."""
        rs = p11_module_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")

        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            mech = mech_simple(CKM_SHA256_HMAC)
            rv = rs.raw.C_SignInit(rs.sh, mech.byref(), priv)
            assert rv != CKR_OK, (
                "C_SignInit(CKM_SHA256_HMAC, RSA_priv) should fail but returned CKR_OK"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_aes_ecb_with_ec_key_rejected(self, p11_module_session: RawSession) -> None:
        """CKM_AES_ECB with an EC private key must fail EncryptInit."""
        rs = p11_module_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC keygen not supported")

        pub, priv = gen_ec_keypair_or_xfail(rs, _P256_OID)
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), priv)
            assert rv != CKR_OK, (
                "C_EncryptInit(CKM_AES_ECB, EC_priv) should fail but returned CKR_OK"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_registry_encrypt_wrong_key_type(
        self, p11_module_session: RawSession, mech_encrypt_entry: MechEntry
    ) -> None:
        """Registry-driven wrong-secret-key-type check for advertised encrypt mechanisms."""
        rs = p11_module_session
        entry = mech_encrypt_entry
        _skip_if_not_secret_key_registry_case(entry)

        key = _import_wrong_secret_key_or_xfail(
            rs,
            entry,
            attrs={CKA_TOKEN: False, CKA_ENCRYPT: True, CKA_DECRYPT: True},
        )
        label = f"{entry.mech_name} encrypt with wrong key type"
        try:
            mech_param = make_mech_param_or_skip(entry)
            exc: AssertionError | None = None
            try:
                encrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    entry.mech_id,
                    b"\x00" * 32,
                    mech_param=mech_param,
                    output_overhead=16,
                    retry_on_buffer_too_small=True,
                )
            except AssertionError as caught:
                exc = caught
            reject_or_classify(exc, (CKR_KEY_TYPE_INCONSISTENT,), label=label)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_registry_decrypt_wrong_key_type(
        self, p11_module_session: RawSession, mech_encrypt_entry: MechEntry
    ) -> None:
        """Registry-driven wrong-secret-key-type check for advertised decrypt mechanisms."""
        rs = p11_module_session
        entry = mech_encrypt_entry
        _skip_if_not_secret_key_registry_case(entry)

        key = _import_wrong_secret_key_or_xfail(
            rs,
            entry,
            attrs={CKA_TOKEN: False, CKA_ENCRYPT: True, CKA_DECRYPT: True},
        )
        label = f"{entry.mech_name} decrypt with wrong key type"
        try:
            mech_param = make_mech_param_or_skip(entry)
            mech = mech_param if mech_param is not None else mech_simple(entry.mech_id)
            rv = rs.raw.C_DecryptInit(rs.sh, mech.byref(), key)
            classify_negative_rv(rv, (CKR_KEY_TYPE_INCONSISTENT,), label=label)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_registry_sign_wrong_key_type(
        self, p11_module_session: RawSession, mech_sign_entry: MechEntry
    ) -> None:
        """Registry-driven wrong-secret-key-type check for advertised sign mechanisms."""
        rs = p11_module_session
        entry = mech_sign_entry
        _skip_if_not_secret_key_registry_case(entry)

        key = _import_wrong_secret_key_or_xfail(
            rs,
            entry,
            attrs={CKA_TOKEN: False, CKA_SIGN: True, CKA_VERIFY: True},
        )
        label = f"{entry.mech_name} sign with wrong key type"
        try:
            mech_param = make_mech_param_or_skip(entry)
            exc: AssertionError | None = None
            try:
                sign_single(
                    rs.raw,
                    rs.sh,
                    key,
                    entry.mech_id,
                    b"\x00" * 32,
                    mech_param=mech_param,
                )
            except AssertionError as caught:
                exc = caught
            reject_or_classify(exc, (CKR_KEY_TYPE_INCONSISTENT,), label=label)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_registry_verify_wrong_key_type(
        self, p11_module_session: RawSession, mech_sign_entry: MechEntry
    ) -> None:
        """Registry-driven wrong-secret-key-type check for advertised verify mechanisms."""
        rs = p11_module_session
        entry = mech_sign_entry
        _skip_if_not_secret_key_registry_case(entry)

        key = _import_wrong_secret_key_or_xfail(
            rs,
            entry,
            attrs={CKA_TOKEN: False, CKA_SIGN: True, CKA_VERIFY: True},
        )
        label = f"{entry.mech_name} verify with wrong key type"
        try:
            mech_param = make_mech_param_or_skip(entry)
            mech = mech_param if mech_param is not None else mech_simple(entry.mech_id)
            rv = rs.raw.C_VerifyInit(rs.sh, mech.byref(), key)
            classify_negative_rv(rv, (CKR_KEY_TYPE_INCONSISTENT,), label=label)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_registry_wrap_wrong_key_type(
        self, p11_module_session: RawSession, mech_wrap_entry: MechEntry
    ) -> None:
        """Registry-driven wrong-secret-key-type check for advertised wrap mechanisms."""
        rs = p11_module_session
        entry = mech_wrap_entry
        _skip_if_not_secret_key_registry_case(entry)

        wrapping_key = _import_wrong_secret_key_or_xfail(
            rs,
            entry,
            attrs={CKA_TOKEN: False, CKA_WRAP: True, CKA_UNWRAP: True},
        )
        target_key = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False, CKA_TOKEN: False},
            purpose="registry wrap wrong-key target setup",
        )
        label = f"{entry.mech_name} wrap with wrong key type"
        try:
            mech_param = make_mech_param_or_skip(entry)
            mech = mech_param if mech_param is not None else mech_simple(entry.mech_id)
            out_len = CK_ULONG(0)
            rv = rs.raw.C_WrapKey(
                rs.sh,
                mech.byref(),
                wrapping_key,
                target_key,
                None,
                byref(out_len),
            )
            classify_negative_rv(rv, (CKR_WRAPPING_KEY_TYPE_INCONSISTENT,), label=label)
        finally:
            destroy_quietly(rs.raw, rs.sh, wrapping_key)
            destroy_quietly(rs.raw, rs.sh, target_key)

    def test_registry_unwrap_wrong_key_type(
        self, p11_module_session: RawSession, mech_wrap_entry: MechEntry
    ) -> None:
        """Registry-driven wrong-secret-key-type check for advertised unwrap mechanisms."""
        rs = p11_module_session
        entry = mech_wrap_entry
        _skip_if_not_secret_key_registry_case(entry)
        config = entry.config
        assert config is not None

        wrapping_key = gen_symmetric_key(
            rs,
            entry,
            config,
            extra_attrs={CKA_WRAP: True, CKA_UNWRAP: True, CKA_TOKEN: False},
        )
        unwrapping_key = _import_wrong_secret_key_or_xfail(
            rs,
            entry,
            attrs={CKA_TOKEN: False, CKA_WRAP: True, CKA_UNWRAP: True},
        )
        target_key = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False, CKA_TOKEN: False},
            purpose="registry unwrap wrong-key target setup",
        )
        unwrapped_key = 0
        label = f"{entry.mech_name} unwrap with wrong key type"
        try:
            mech_param = make_mech_param_or_skip(entry)
            try:
                wrapped = wrap_key(
                    rs.raw,
                    rs.sh,
                    wrapping_key,
                    target_key,
                    entry.mech_id,
                    mech_param=mech_param,
                    output_size_hint=_wrap_output_size_hint(entry),
                )
            except AssertionError as setup_exc:
                xfail_if_known_ckr(
                    setup_exc,
                    _WRAP_SETUP_REJECT_RVS,
                    f"{entry.mech_name} wrap setup not operational",
                )
                raise

            unwrap_exc: AssertionError | None = None
            try:
                unwrapped_key = unwrap_key(
                    rs.raw,
                    rs.sh,
                    unwrapping_key,
                    wrapped,
                    entry.mech_id,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_TOKEN: False,
                    },
                    mech_param=mech_param,
                )
            except AssertionError as caught:
                unwrap_exc = caught
            reject_or_classify(
                unwrap_exc,
                (CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,),
                label=label,
            )
        finally:
            if unwrapped_key != 0:
                destroy_quietly(rs.raw, rs.sh, unwrapped_key)
            destroy_quietly(rs.raw, rs.sh, wrapping_key)
            destroy_quietly(rs.raw, rs.sh, unwrapping_key)
            destroy_quietly(rs.raw, rs.sh, target_key)

    def test_registry_derive_wrong_key_type(
        self, p11_module_session: RawSession, mech_derive_entry: MechEntry
    ) -> None:
        """Registry-driven wrong-secret-key-type check for advertised derive mechanisms."""
        rs = p11_module_session
        entry = mech_derive_entry
        _skip_if_not_secret_key_registry_case(entry)

        base_key = 0
        derived_key = 0
        param_handles: list[int] = []
        label = f"{entry.mech_name} derive with wrong key type"
        try:
            mech_param, param_handles = _derive_negative_param_or_skip(rs, entry)
            base_key = _import_wrong_secret_key_or_xfail(
                rs,
                entry,
                attrs={CKA_TOKEN: False, CKA_DERIVE: True},
            )

            derive_exc: AssertionError | None = None
            try:
                derived_key = derive_key(
                    rs.raw,
                    rs.sh,
                    base_key,
                    entry.mech_id,
                    attrs=_DERIVED_GENERIC_SECRET_ATTRS,
                    mech_param=mech_param,
                )
            except AssertionError as caught:
                derive_exc = caught
            reject_or_classify(derive_exc, (CKR_KEY_TYPE_INCONSISTENT,), label=label, kind="policy")
        finally:
            if derived_key != 0:
                destroy_quietly(rs.raw, rs.sh, derived_key)
            if base_key != 0:
                destroy_quietly(rs.raw, rs.sh, base_key)
            for handle in param_handles:
                destroy_quietly(rs.raw, rs.sh, handle)


class TestBadParameters:
    """Mechanisms requiring params must reject missing or malformed mechanism parameters."""

    def test_registry_encrypt_missing_required_param(
        self, p11_module_session: RawSession, mech_encrypt_entry: MechEntry
    ) -> None:
        """Registry-driven missing-required-param check for advertised encrypt mechanisms."""
        rs = p11_module_session
        entry = mech_encrypt_entry
        _skip_if_not_required_param_registry_case(entry)
        config = entry.config
        assert config is not None

        encrypt_key = 0
        decrypt_key: int | None = None
        label = f"{entry.mech_name} C_EncryptInit with missing required params"
        try:
            encrypt_key, decrypt_key = generate_key_for_encrypt(rs, entry, config)
            mech = mech_simple(entry.mech_id)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), encrypt_key)
            classify_negative_rv(rv, _MISSING_REQUIRED_PARAM_RVS, label=label)
        finally:
            destroy_quietly(rs.raw, rs.sh, encrypt_key)
            if decrypt_key is not None and decrypt_key != encrypt_key:
                destroy_quietly(rs.raw, rs.sh, decrypt_key)

    def test_registry_encrypt_malformed_required_param(
        self, p11_module_session: RawSession, mech_encrypt_entry: MechEntry
    ) -> None:
        """Registry-driven malformed-param check for advertised encrypt mechanisms."""
        rs = p11_module_session
        entry = mech_encrypt_entry
        _skip_if_not_required_param_registry_case(entry)
        config = entry.config
        assert config is not None

        encrypt_key = 0
        decrypt_key: int | None = None
        label = f"{entry.mech_name} C_EncryptInit with malformed non-NULL params"
        try:
            encrypt_key, decrypt_key = generate_key_for_encrypt(rs, entry, config)
            mech = mech_bytes(entry.mech_id, b"\x00")
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), encrypt_key)
            classify_negative_rv(rv, _MALFORMED_REQUIRED_PARAM_RVS, label=label)
        finally:
            destroy_quietly(rs.raw, rs.sh, encrypt_key)
            if decrypt_key is not None and decrypt_key != encrypt_key:
                destroy_quietly(rs.raw, rs.sh, decrypt_key)

    def test_registry_decrypt_missing_required_param(
        self, p11_module_session: RawSession, mech_encrypt_entry: MechEntry
    ) -> None:
        """Registry-driven missing-required-param check for advertised decrypt mechanisms."""
        rs = p11_module_session
        entry = mech_encrypt_entry
        _skip_if_not_required_param_registry_case(entry)
        config = entry.config
        assert config is not None

        encrypt_key = 0
        decrypt_key: int | None = None
        label = f"{entry.mech_name} C_DecryptInit with missing required params"
        try:
            encrypt_key, decrypt_key = generate_key_for_encrypt(rs, entry, config)
            key = decrypt_key if decrypt_key is not None else encrypt_key
            mech = mech_simple(entry.mech_id)
            rv = rs.raw.C_DecryptInit(rs.sh, mech.byref(), key)
            classify_negative_rv(rv, _MISSING_REQUIRED_PARAM_RVS, label=label)
        finally:
            destroy_quietly(rs.raw, rs.sh, encrypt_key)
            if decrypt_key is not None and decrypt_key != encrypt_key:
                destroy_quietly(rs.raw, rs.sh, decrypt_key)

    def test_registry_decrypt_malformed_required_param(
        self, p11_module_session: RawSession, mech_encrypt_entry: MechEntry
    ) -> None:
        """Registry-driven malformed-param check for advertised decrypt mechanisms."""
        rs = p11_module_session
        entry = mech_encrypt_entry
        _skip_if_not_required_param_registry_case(entry)
        config = entry.config
        assert config is not None

        encrypt_key = 0
        decrypt_key: int | None = None
        label = f"{entry.mech_name} C_DecryptInit with malformed non-NULL params"
        try:
            encrypt_key, decrypt_key = generate_key_for_encrypt(rs, entry, config)
            key = decrypt_key if decrypt_key is not None else encrypt_key
            mech = mech_bytes(entry.mech_id, b"\x00")
            rv = rs.raw.C_DecryptInit(rs.sh, mech.byref(), key)
            classify_negative_rv(rv, _MALFORMED_REQUIRED_PARAM_RVS, label=label)
        finally:
            destroy_quietly(rs.raw, rs.sh, encrypt_key)
            if decrypt_key is not None and decrypt_key != encrypt_key:
                destroy_quietly(rs.raw, rs.sh, decrypt_key)

    def test_registry_sign_missing_required_param(
        self, p11_module_session: RawSession, mech_sign_entry: MechEntry
    ) -> None:
        """Registry-driven missing-required-param check for advertised sign mechanisms."""
        rs = p11_module_session
        entry = mech_sign_entry
        _skip_if_not_required_param_registry_case(entry)
        config = entry.config
        assert config is not None

        sign_key = 0
        verify_key: int | None = None
        label = f"{entry.mech_name} C_SignInit with missing required params"
        try:
            sign_key, verify_key = generate_key_for_sign(rs, entry, config)
            mech = mech_simple(entry.mech_id)
            rv = rs.raw.C_SignInit(rs.sh, mech.byref(), sign_key)
            classify_negative_rv(rv, _MISSING_REQUIRED_PARAM_RVS, label=label, kind="crypto")
        finally:
            destroy_quietly(rs.raw, rs.sh, sign_key)
            if verify_key is not None and verify_key != sign_key:
                destroy_quietly(rs.raw, rs.sh, verify_key)

    def test_registry_sign_malformed_required_param(
        self, p11_module_session: RawSession, mech_sign_entry: MechEntry
    ) -> None:
        """Registry-driven malformed-param check for advertised sign mechanisms."""
        rs = p11_module_session
        entry = mech_sign_entry
        _skip_if_not_required_param_registry_case(entry)
        config = entry.config
        assert config is not None

        sign_key = 0
        verify_key: int | None = None
        label = f"{entry.mech_name} C_SignInit with malformed non-NULL params"
        try:
            sign_key, verify_key = generate_key_for_sign(rs, entry, config)
            mech = mech_bytes(entry.mech_id, b"\x00")
            rv = rs.raw.C_SignInit(rs.sh, mech.byref(), sign_key)
            classify_negative_rv(rv, _MALFORMED_REQUIRED_PARAM_RVS, label=label)
        finally:
            destroy_quietly(rs.raw, rs.sh, sign_key)
            if verify_key is not None and verify_key != sign_key:
                destroy_quietly(rs.raw, rs.sh, verify_key)

    def test_registry_verify_missing_required_param(
        self, p11_module_session: RawSession, mech_sign_entry: MechEntry
    ) -> None:
        """Registry-driven missing-required-param check for advertised verify mechanisms."""
        rs = p11_module_session
        entry = mech_sign_entry
        _skip_if_not_required_param_registry_case(entry)
        config = entry.config
        assert config is not None

        sign_key = 0
        verify_key: int | None = None
        label = f"{entry.mech_name} C_VerifyInit with missing required params"
        try:
            sign_key, verify_key = generate_key_for_sign(rs, entry, config)
            key = verify_key if verify_key is not None else sign_key
            mech = mech_simple(entry.mech_id)
            rv = rs.raw.C_VerifyInit(rs.sh, mech.byref(), key)
            classify_negative_rv(rv, _MISSING_REQUIRED_PARAM_RVS, label=label)
        finally:
            destroy_quietly(rs.raw, rs.sh, sign_key)
            if verify_key is not None and verify_key != sign_key:
                destroy_quietly(rs.raw, rs.sh, verify_key)

    def test_registry_verify_malformed_required_param(
        self, p11_module_session: RawSession, mech_sign_entry: MechEntry
    ) -> None:
        """Registry-driven malformed-param check for advertised verify mechanisms."""
        rs = p11_module_session
        entry = mech_sign_entry
        _skip_if_not_required_param_registry_case(entry)
        config = entry.config
        assert config is not None

        sign_key = 0
        verify_key: int | None = None
        label = f"{entry.mech_name} C_VerifyInit with malformed non-NULL params"
        try:
            sign_key, verify_key = generate_key_for_sign(rs, entry, config)
            key = verify_key if verify_key is not None else sign_key
            mech = mech_bytes(entry.mech_id, b"\x00")
            rv = rs.raw.C_VerifyInit(rs.sh, mech.byref(), key)
            classify_negative_rv(rv, _MALFORMED_REQUIRED_PARAM_RVS, label=label)
        finally:
            destroy_quietly(rs.raw, rs.sh, sign_key)
            if verify_key is not None and verify_key != sign_key:
                destroy_quietly(rs.raw, rs.sh, verify_key)

    def _wrap_required_param_must_reject(
        self,
        rs: RawSession,
        entry: MechEntry,
        *,
        mech_param: Any,
        expected_rvs: tuple[int, ...],
        label_suffix: str,
    ) -> None:
        _skip_if_not_required_param_registry_case(entry)
        _skip_if_not_secret_key_registry_case(entry)
        config = entry.config
        assert config is not None

        wrapping_key = gen_symmetric_key(
            rs,
            entry,
            config,
            extra_attrs={CKA_WRAP: True, CKA_UNWRAP: True, CKA_TOKEN: False},
        )
        target_key = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False, CKA_TOKEN: False},
            purpose="registry wrap required-param target setup",
        )
        label = f"{entry.mech_name} C_WrapKey with {label_suffix}"
        try:
            out_len = CK_ULONG(0)
            rv = rs.raw.C_WrapKey(
                rs.sh,
                mech_param.byref(),
                wrapping_key,
                target_key,
                None,
                byref(out_len),
            )
            classify_negative_rv(rv, expected_rvs, label=label)
        finally:
            destroy_quietly(rs.raw, rs.sh, wrapping_key)
            destroy_quietly(rs.raw, rs.sh, target_key)

    def test_registry_wrap_missing_required_param(
        self, p11_module_session: RawSession, mech_wrap_entry: MechEntry
    ) -> None:
        """Registry-driven missing-required-param check for advertised wrap mechanisms."""
        self._wrap_required_param_must_reject(
            p11_module_session,
            mech_wrap_entry,
            mech_param=mech_simple(mech_wrap_entry.mech_id),
            expected_rvs=_MISSING_REQUIRED_PARAM_RVS,
            label_suffix="missing required params",
        )

    def test_registry_wrap_malformed_required_param(
        self, p11_module_session: RawSession, mech_wrap_entry: MechEntry
    ) -> None:
        """Registry-driven malformed-param check for advertised wrap mechanisms."""
        self._wrap_required_param_must_reject(
            p11_module_session,
            mech_wrap_entry,
            mech_param=mech_bytes(mech_wrap_entry.mech_id, b"\x00"),
            expected_rvs=_MALFORMED_REQUIRED_PARAM_RVS,
            label_suffix="malformed non-NULL params",
        )

    def _unwrap_required_param_must_reject(
        self,
        rs: RawSession,
        entry: MechEntry,
        *,
        mech_param: Any,
        expected_rvs: tuple[int, ...],
        label_suffix: str,
    ) -> None:
        _skip_if_not_required_param_registry_case(entry)
        _skip_if_not_secret_key_registry_case(entry)
        config = entry.config
        assert config is not None

        wrapping_key = gen_symmetric_key(
            rs,
            entry,
            config,
            extra_attrs={CKA_WRAP: True, CKA_UNWRAP: True, CKA_TOKEN: False},
        )
        target_key = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False, CKA_TOKEN: False},
            purpose="registry unwrap required-param target setup",
        )
        unwrapped_key = 0
        label = f"{entry.mech_name} C_UnwrapKey with {label_suffix}"
        try:
            valid_param = make_mech_param_or_skip(entry)
            try:
                wrapped = wrap_key(
                    rs.raw,
                    rs.sh,
                    wrapping_key,
                    target_key,
                    entry.mech_id,
                    mech_param=valid_param,
                    output_size_hint=_wrap_output_size_hint(entry),
                )
            except AssertionError as setup_exc:
                xfail_if_known_ckr(
                    setup_exc,
                    _WRAP_SETUP_REJECT_RVS,
                    f"{entry.mech_name} unwrap required-param setup not operational",
                )
                raise

            unwrap_exc: AssertionError | None = None
            try:
                unwrapped_key = unwrap_key(
                    rs.raw,
                    rs.sh,
                    wrapping_key,
                    wrapped,
                    entry.mech_id,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_TOKEN: False,
                    },
                    mech_param=mech_param,
                )
            except AssertionError as caught:
                unwrap_exc = caught
            if unwrap_exc is None and unwrapped_key != 0:
                destroy_quietly(rs.raw, rs.sh, unwrapped_key)
                unwrapped_key = 0
            reject_or_classify(unwrap_exc, expected_rvs, label=label)
        finally:
            if unwrapped_key != 0:
                destroy_quietly(rs.raw, rs.sh, unwrapped_key)
            destroy_quietly(rs.raw, rs.sh, wrapping_key)
            destroy_quietly(rs.raw, rs.sh, target_key)

    def test_registry_unwrap_missing_required_param(
        self, p11_module_session: RawSession, mech_wrap_entry: MechEntry
    ) -> None:
        """Registry-driven missing-required-param check for advertised unwrap mechanisms."""
        self._unwrap_required_param_must_reject(
            p11_module_session,
            mech_wrap_entry,
            mech_param=mech_simple(mech_wrap_entry.mech_id),
            expected_rvs=_MISSING_REQUIRED_PARAM_RVS,
            label_suffix="missing required params",
        )

    def test_registry_unwrap_malformed_required_param(
        self, p11_module_session: RawSession, mech_wrap_entry: MechEntry
    ) -> None:
        """Registry-driven malformed-param check for advertised unwrap mechanisms."""
        self._unwrap_required_param_must_reject(
            p11_module_session,
            mech_wrap_entry,
            mech_param=mech_bytes(mech_wrap_entry.mech_id, b"\x00"),
            expected_rvs=_MALFORMED_REQUIRED_PARAM_RVS,
            label_suffix="malformed non-NULL params",
        )

    def test_registry_digest_missing_required_param(
        self, p11_module_session: RawSession, mech_digest_entry: MechEntry
    ) -> None:
        """Registry-driven missing-required-param check for advertised digest mechanisms."""
        rs = p11_module_session
        entry = mech_digest_entry
        _skip_if_not_required_param_registry_case(entry)

        label = f"{entry.mech_name} C_DigestInit with missing required params"
        mech = mech_simple(entry.mech_id)
        rv = rs.raw.C_DigestInit(rs.sh, mech.byref())
        if rv == CKR_OK:
            _finish_digest_after_unexpected_ok(rs)
        classify_negative_rv(rv, _MISSING_REQUIRED_PARAM_RVS, label=label)

    def test_registry_digest_malformed_required_param(
        self, p11_module_session: RawSession, mech_digest_entry: MechEntry
    ) -> None:
        """Registry-driven malformed-param check for advertised digest mechanisms."""
        rs = p11_module_session
        entry = mech_digest_entry
        _skip_if_not_required_param_registry_case(entry)

        label = f"{entry.mech_name} C_DigestInit with malformed non-NULL params"
        mech = mech_bytes(entry.mech_id, b"\x00")
        rv = rs.raw.C_DigestInit(rs.sh, mech.byref())
        if rv == CKR_OK:
            _finish_digest_after_unexpected_ok(rs)
        classify_negative_rv(rv, _MALFORMED_REQUIRED_PARAM_RVS, label=label)

    def test_registry_derive_missing_required_param(
        self, p11_module_session: RawSession, mech_derive_entry: MechEntry
    ) -> None:
        """Registry-driven missing-required-param check for simple advertised derive mechanisms."""
        rs = p11_module_session
        entry = mech_derive_entry
        _skip_if_not_required_param_registry_case(entry)
        _skip_if_not_secret_key_registry_case(entry)
        config = entry.config
        assert config is not None

        base_key = 0
        derived_key = 0
        param_handles: list[int] = []
        label = f"{entry.mech_name} C_DeriveKey with missing required params"
        try:
            _valid_param, param_handles = _derive_negative_param_or_skip(rs, entry)
            base_key = gen_symmetric_key(
                rs,
                entry,
                config,
                extra_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
            )

            derive_exc: AssertionError | None = None
            try:
                derived_key = derive_key(
                    rs.raw,
                    rs.sh,
                    base_key,
                    entry.mech_id,
                    attrs=_DERIVED_GENERIC_SECRET_ATTRS,
                )
            except AssertionError as caught:
                derive_exc = caught
            if derive_exc is None and derived_key != 0:
                destroy_quietly(rs.raw, rs.sh, derived_key)
                derived_key = 0
            reject_or_classify(
                derive_exc,
                _MISSING_REQUIRED_PARAM_RVS,
                label=label,
            )
        finally:
            if derived_key != 0:
                destroy_quietly(rs.raw, rs.sh, derived_key)
            if base_key != 0:
                destroy_quietly(rs.raw, rs.sh, base_key)
            for handle in param_handles:
                destroy_quietly(rs.raw, rs.sh, handle)

    def test_registry_derive_malformed_required_param(
        self, p11_module_session: RawSession, mech_derive_entry: MechEntry
    ) -> None:
        """Registry-driven malformed-param check for simple advertised derive mechanisms."""
        rs = p11_module_session
        entry = mech_derive_entry
        _skip_if_not_required_param_registry_case(entry)
        _skip_if_not_secret_key_registry_case(entry)
        config = entry.config
        assert config is not None

        base_key = 0
        derived_key = 0
        param_handles: list[int] = []
        label = f"{entry.mech_name} C_DeriveKey with malformed non-NULL params"
        try:
            _valid_param, param_handles = _derive_negative_param_or_skip(rs, entry)
            base_key = gen_symmetric_key(
                rs,
                entry,
                config,
                extra_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
            )

            derive_exc: AssertionError | None = None
            try:
                derived_key = derive_key(
                    rs.raw,
                    rs.sh,
                    base_key,
                    entry.mech_id,
                    attrs=_DERIVED_GENERIC_SECRET_ATTRS,
                    mech_param=mech_bytes(entry.mech_id, b"\x00"),
                )
            except AssertionError as caught:
                derive_exc = caught
            if derive_exc is None and derived_key != 0:
                destroy_quietly(rs.raw, rs.sh, derived_key)
                derived_key = 0
            reject_or_classify(
                derive_exc,
                _MALFORMED_REQUIRED_PARAM_RVS,
                label=label,
            )
        finally:
            if derived_key != 0:
                destroy_quietly(rs.raw, rs.sh, derived_key)
            if base_key != 0:
                destroy_quietly(rs.raw, rs.sh, base_key)
            for handle in param_handles:
                destroy_quietly(rs.raw, rs.sh, handle)


class TestMalformedWrappedBlob:
    """C_UnwrapKey must reject malformed wrapped-key bytes."""

    def _registry_unwrap_rejects_literal_blob(
        self,
        rs: RawSession,
        entry: MechEntry,
        wrapped_blob: bytes,
        label_suffix: str,
    ) -> None:
        _skip_if_not_secret_key_registry_case(entry)
        config = entry.config
        assert config is not None

        wrapping_key = gen_symmetric_key(
            rs,
            entry,
            config,
            extra_attrs={CKA_WRAP: True, CKA_UNWRAP: True, CKA_TOKEN: False},
        )
        unwrapped_key = 0
        label = f"{entry.mech_name} C_UnwrapKey with {label_suffix} wrapped blob"
        try:
            mech_param = make_mech_param_or_skip(entry)
            unwrap_exc: AssertionError | None = None
            try:
                unwrapped_key = unwrap_key(
                    rs.raw,
                    rs.sh,
                    wrapping_key,
                    wrapped_blob,
                    entry.mech_id,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_TOKEN: False,
                    },
                    mech_param=mech_param,
                )
            except AssertionError as caught:
                unwrap_exc = caught
            if unwrap_exc is None and unwrapped_key != 0:
                destroy_quietly(rs.raw, rs.sh, unwrapped_key)
                unwrapped_key = 0
            reject_or_classify(
                unwrap_exc,
                _MALFORMED_WRAPPED_BLOB_RVS,
                label=label,
            )
        finally:
            if unwrapped_key != 0:
                destroy_quietly(rs.raw, rs.sh, unwrapped_key)
            destroy_quietly(rs.raw, rs.sh, wrapping_key)

    def test_registry_unwrap_rejects_empty_blob(
        self, p11_module_session: RawSession, mech_wrap_entry: MechEntry
    ) -> None:
        """Registry-driven empty wrapped-blob check for advertised unwrap mechanisms."""
        self._registry_unwrap_rejects_literal_blob(
            p11_module_session,
            mech_wrap_entry,
            b"",
            "empty",
        )

    def test_registry_unwrap_rejects_one_byte_blob(
        self, p11_module_session: RawSession, mech_wrap_entry: MechEntry
    ) -> None:
        """Registry-driven one-byte wrapped-blob check for advertised unwrap mechanisms."""
        self._registry_unwrap_rejects_literal_blob(
            p11_module_session,
            mech_wrap_entry,
            b"\x00",
            "one-byte",
        )

    def test_registry_unwrap_rejects_truncated_blob(
        self, p11_module_session: RawSession, mech_wrap_entry: MechEntry
    ) -> None:
        """Registry-driven truncated wrapped-blob check for advertised unwrap mechanisms."""
        rs = p11_module_session
        entry = mech_wrap_entry
        _skip_if_not_secret_key_registry_case(entry)
        config = entry.config
        assert config is not None

        wrapping_key = gen_symmetric_key(
            rs,
            entry,
            config,
            extra_attrs={CKA_WRAP: True, CKA_UNWRAP: True, CKA_TOKEN: False},
        )
        target_key = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False, CKA_TOKEN: False},
            purpose="registry unwrap truncated-blob target setup",
        )
        unwrapped_key = 0
        label = f"{entry.mech_name} C_UnwrapKey with truncated wrapped blob"
        try:
            mech_param = make_mech_param_or_skip(entry)
            try:
                wrapped = wrap_key(
                    rs.raw,
                    rs.sh,
                    wrapping_key,
                    target_key,
                    entry.mech_id,
                    mech_param=mech_param,
                    output_size_hint=_wrap_output_size_hint(entry),
                )
            except AssertionError as setup_exc:
                xfail_if_known_ckr(
                    setup_exc,
                    _WRAP_SETUP_REJECT_RVS,
                    f"{entry.mech_name} wrap setup not operational",
                )
                raise
            if len(wrapped) < 2:
                classify(
                    "honest_deviation",
                    kind="crypto",
                    label=label,
                    operation="C_WrapKey",
                    mechanism=entry.mech_name,
                    summary=f"{entry.mech_name}: wrap output too short to truncate",
                )

            unwrap_exc: AssertionError | None = None
            try:
                unwrapped_key = unwrap_key(
                    rs.raw,
                    rs.sh,
                    wrapping_key,
                    wrapped[:-1],
                    entry.mech_id,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_TOKEN: False,
                    },
                    mech_param=mech_param,
                )
            except AssertionError as caught:
                unwrap_exc = caught
            if unwrap_exc is None and unwrapped_key != 0:
                destroy_quietly(rs.raw, rs.sh, unwrapped_key)
                unwrapped_key = 0
            reject_or_classify(
                unwrap_exc,
                _MALFORMED_WRAPPED_BLOB_RVS,
                label=label,
            )
        finally:
            if unwrapped_key != 0:
                destroy_quietly(rs.raw, rs.sh, unwrapped_key)
            destroy_quietly(rs.raw, rs.sh, wrapping_key)
            destroy_quietly(rs.raw, rs.sh, target_key)


class TestMissingPermission:
    """Keys with required CKA flags set to False must be rejected."""

    def test_registry_encrypt_without_flag(
        self, p11_module_session: RawSession, mech_encrypt_entry: MechEntry
    ) -> None:
        """Registry-driven CKA_ENCRYPT=False check for advertised encrypt mechanisms."""
        rs = p11_module_session
        entry = mech_encrypt_entry
        _skip_if_not_secret_key_registry_case(entry)

        key = _gen_claimed_false_secret_key(
            rs,
            entry,
            CKA_ENCRYPT,
            companion_attrs={CKA_DECRYPT: True},
        )
        label = f"{entry.mech_name} C_EncryptInit with CKA_ENCRYPT=False"
        try:
            _claim_false_or_xfail(rs, key, CKA_ENCRYPT, label)
            mech_param = make_mech_param_or_skip(entry)
            mech = mech_param if mech_param is not None else mech_simple(entry.mech_id)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            if rv == CKR_OK:
                classify_policy_enforcement(claimed=True, violated=True, label=label)
            classify_negative_rv(rv, (CKR_KEY_FUNCTION_NOT_PERMITTED,), label=label)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_registry_decrypt_without_flag(
        self, p11_module_session: RawSession, mech_encrypt_entry: MechEntry
    ) -> None:
        """Registry-driven CKA_DECRYPT=False check for advertised decrypt mechanisms."""
        rs = p11_module_session
        entry = mech_encrypt_entry
        _skip_if_not_secret_key_registry_case(entry)

        key = _gen_claimed_false_secret_key(
            rs,
            entry,
            CKA_DECRYPT,
            companion_attrs={CKA_ENCRYPT: True},
        )
        label = f"{entry.mech_name} C_DecryptInit with CKA_DECRYPT=False"
        try:
            _claim_false_or_xfail(rs, key, CKA_DECRYPT, label)
            mech_param = make_mech_param_or_skip(entry)
            mech = mech_param if mech_param is not None else mech_simple(entry.mech_id)
            rv = rs.raw.C_DecryptInit(rs.sh, mech.byref(), key)
            if rv == CKR_OK:
                classify_policy_enforcement(claimed=True, violated=True, label=label)
            classify_negative_rv(rv, (CKR_KEY_FUNCTION_NOT_PERMITTED,), label=label)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_registry_sign_without_flag(
        self, p11_module_session: RawSession, mech_sign_entry: MechEntry
    ) -> None:
        """Registry-driven CKA_SIGN=False check for advertised sign mechanisms."""
        rs = p11_module_session
        entry = mech_sign_entry
        _skip_if_not_secret_key_registry_case(entry)

        key = _gen_claimed_false_secret_key(
            rs,
            entry,
            CKA_SIGN,
            companion_attrs={CKA_VERIFY: True},
        )
        label = f"{entry.mech_name} C_SignInit with CKA_SIGN=False"
        try:
            _claim_false_or_xfail(rs, key, CKA_SIGN, label)
            mech_param = make_mech_param_or_skip(entry)
            mech = mech_param if mech_param is not None else mech_simple(entry.mech_id)
            rv = rs.raw.C_SignInit(rs.sh, mech.byref(), key)
            if rv == CKR_OK:
                classify_policy_enforcement(claimed=True, violated=True, label=label)
            classify_negative_rv(rv, (CKR_KEY_FUNCTION_NOT_PERMITTED,), label=label)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_registry_verify_without_flag(
        self, p11_module_session: RawSession, mech_sign_entry: MechEntry
    ) -> None:
        """Registry-driven CKA_VERIFY=False check for advertised verify mechanisms."""
        rs = p11_module_session
        entry = mech_sign_entry
        _skip_if_not_secret_key_registry_case(entry)

        key = _gen_claimed_false_secret_key(
            rs,
            entry,
            CKA_VERIFY,
            companion_attrs={CKA_SIGN: True},
        )
        label = f"{entry.mech_name} C_VerifyInit with CKA_VERIFY=False"
        try:
            _claim_false_or_xfail(rs, key, CKA_VERIFY, label)
            mech_param = make_mech_param_or_skip(entry)
            mech = mech_param if mech_param is not None else mech_simple(entry.mech_id)
            rv = rs.raw.C_VerifyInit(rs.sh, mech.byref(), key)
            if rv == CKR_OK:
                classify_policy_enforcement(claimed=True, violated=True, label=label)
            classify_negative_rv(rv, (CKR_KEY_FUNCTION_NOT_PERMITTED,), label=label)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_registry_wrap_without_flag(
        self, p11_module_session: RawSession, mech_wrap_entry: MechEntry
    ) -> None:
        """Registry-driven CKA_WRAP=False check for advertised wrap mechanisms."""
        rs = p11_module_session
        entry = mech_wrap_entry
        _skip_if_not_secret_key_registry_case(entry)

        wrapping_key = _gen_claimed_false_secret_key(
            rs,
            entry,
            CKA_WRAP,
            companion_attrs={CKA_UNWRAP: True},
        )
        target_key = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False, CKA_TOKEN: False},
            purpose="registry wrap-permission target setup",
        )
        label = f"{entry.mech_name} C_WrapKey with CKA_WRAP=False"
        try:
            _claim_false_or_xfail(rs, wrapping_key, CKA_WRAP, label)
            mech_param = make_mech_param_or_skip(entry)
            mech = mech_param if mech_param is not None else mech_simple(entry.mech_id)
            out_len = CK_ULONG(0)
            rv = rs.raw.C_WrapKey(
                rs.sh,
                mech.byref(),
                wrapping_key,
                target_key,
                None,
                byref(out_len),
            )
            if rv == CKR_OK:
                classify_policy_enforcement(claimed=True, violated=True, label=label)
            classify_negative_rv(rv, _NO_SPECIFIC_WRAP_PERMISSION_RVS, label=label)
        finally:
            destroy_quietly(rs.raw, rs.sh, wrapping_key)
            destroy_quietly(rs.raw, rs.sh, target_key)

    def test_registry_unwrap_without_flag(
        self, p11_module_session: RawSession, mech_wrap_entry: MechEntry
    ) -> None:
        """Registry-driven CKA_UNWRAP=False check for advertised unwrap mechanisms."""
        rs = p11_module_session
        entry = mech_wrap_entry
        _skip_if_not_secret_key_registry_case(entry)

        unwrapping_key = _gen_claimed_false_secret_key(
            rs,
            entry,
            CKA_UNWRAP,
            companion_attrs={CKA_WRAP: True},
        )
        target_key = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False, CKA_TOKEN: False},
            purpose="registry unwrap-permission target setup",
        )
        unwrapped_key = 0
        label = f"{entry.mech_name} C_UnwrapKey with CKA_UNWRAP=False"
        try:
            _claim_false_or_xfail(rs, unwrapping_key, CKA_UNWRAP, label)
            mech_param = make_mech_param_or_skip(entry)
            try:
                wrapped = wrap_key(
                    rs.raw,
                    rs.sh,
                    unwrapping_key,
                    target_key,
                    entry.mech_id,
                    mech_param=mech_param,
                    output_size_hint=_wrap_output_size_hint(entry),
                )
            except AssertionError as setup_exc:
                xfail_if_known_ckr(
                    setup_exc,
                    _WRAP_SETUP_REJECT_RVS,
                    f"{entry.mech_name} wrap setup not operational",
                )
                raise

            unwrap_exc: AssertionError | None = None
            try:
                unwrapped_key = unwrap_key(
                    rs.raw,
                    rs.sh,
                    unwrapping_key,
                    wrapped,
                    entry.mech_id,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_TOKEN: False,
                    },
                    mech_param=mech_param,
                )
            except AssertionError as caught:
                unwrap_exc = caught
            if unwrap_exc is None:
                classify_policy_enforcement(claimed=True, violated=True, label=label)
            reject_or_classify(
                unwrap_exc,
                (CKR_KEY_FUNCTION_NOT_PERMITTED,),
                label=label,
            )
        finally:
            if unwrapped_key != 0:
                destroy_quietly(rs.raw, rs.sh, unwrapped_key)
            destroy_quietly(rs.raw, rs.sh, unwrapping_key)
            destroy_quietly(rs.raw, rs.sh, target_key)

    def test_registry_derive_without_flag(
        self, p11_module_session: RawSession, mech_derive_entry: MechEntry
    ) -> None:
        """Registry-driven CKA_DERIVE=False check for advertised derive mechanisms."""
        rs = p11_module_session
        entry = mech_derive_entry
        _skip_if_not_secret_key_registry_case(entry)

        base_key = 0
        derived_key = 0
        param_handles: list[int] = []
        label = f"{entry.mech_name} C_DeriveKey with CKA_DERIVE=False"
        try:
            mech_param, param_handles = _derive_negative_param_or_skip(rs, entry)
            base_key = _gen_claimed_false_secret_key(rs, entry, CKA_DERIVE)
            _claim_false_or_xfail(rs, base_key, CKA_DERIVE, label)

            derive_exc: AssertionError | None = None
            try:
                derived_key = derive_key(
                    rs.raw,
                    rs.sh,
                    base_key,
                    entry.mech_id,
                    attrs=_DERIVED_GENERIC_SECRET_ATTRS,
                    mech_param=mech_param,
                )
            except AssertionError as caught:
                derive_exc = caught
            if derive_exc is None:
                classify_policy_enforcement(claimed=True, violated=True, label=label)
            reject_or_classify(
                derive_exc,
                (CKR_KEY_FUNCTION_NOT_PERMITTED,),
                label=label,
            )
        finally:
            if derived_key != 0:
                destroy_quietly(rs.raw, rs.sh, derived_key)
            if base_key != 0:
                destroy_quietly(rs.raw, rs.sh, base_key)
            for handle in param_handles:
                destroy_quietly(rs.raw, rs.sh, handle)

    def test_encrypt_without_flag(self, p11_module_session: RawSession) -> None:
        """Key with CKA_ENCRYPT=False cannot EncryptInit."""
        rs = p11_module_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_ENCRYPT: False, CKA_DECRYPT: True, CKA_TOKEN: False},
            purpose="encrypt-permission negative test setup",
        )
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            assert rv != CKR_OK, (
                "C_EncryptInit with CKA_ENCRYPT=False should fail but returned CKR_OK"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_decrypt_without_flag(self, p11_module_session: RawSession) -> None:
        """Key with CKA_DECRYPT=False cannot DecryptInit."""
        rs = p11_module_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_DECRYPT: False, CKA_ENCRYPT: True, CKA_TOKEN: False},
            purpose="decrypt-permission negative test setup",
        )
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_DecryptInit(rs.sh, mech.byref(), key)
            assert rv != CKR_OK, (
                "C_DecryptInit with CKA_DECRYPT=False should fail but returned CKR_OK"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_sign_without_flag(self, p11_module_session: RawSession) -> None:
        """Key with CKA_SIGN=False cannot SignInit."""
        rs = p11_module_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")
        if not rs.has_mechanism("GENERIC_SECRET_KEY_GEN"):
            pytest.skip("CKM_GENERIC_SECRET_KEY_GEN not supported")

        # Generate a key explicitly without CKA_SIGN
        attrs: dict[int, Any] = {
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_SIGN: False,
            CKA_VERIFY: True,
            CKA_TOKEN: False,
        }
        packed = [attr_ulong(CKA_VALUE_LEN, 32)]
        packed.extend(pack_attrs(attrs, skip={CKA_VALUE_LEN}))
        tmpl = template(*packed)
        mech = mech_simple(CKM_GENERIC_SECRET_KEY_GEN)
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle))
        assert rv == CKR_OK, f"Key gen failed: {rv}"
        key = handle.value
        try:
            sign_mech = mech_simple(CKM_SHA256_HMAC)
            rv2 = rs.raw.C_SignInit(rs.sh, sign_mech.byref(), key)
            assert rv2 != CKR_OK, "C_SignInit with CKA_SIGN=False should fail but returned CKR_OK"
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_verify_without_flag(self, p11_module_session: RawSession) -> None:
        """Key with CKA_VERIFY=False cannot VerifyInit."""
        rs = p11_module_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")
        if not rs.has_mechanism("GENERIC_SECRET_KEY_GEN"):
            pytest.skip("CKM_GENERIC_SECRET_KEY_GEN not supported")

        attrs: dict[int, Any] = {
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_SIGN: True,
            CKA_VERIFY: False,
            CKA_TOKEN: False,
        }
        packed = [attr_ulong(CKA_VALUE_LEN, 32)]
        packed.extend(pack_attrs(attrs, skip={CKA_VALUE_LEN}))
        tmpl = template(*packed)
        mech = mech_simple(CKM_GENERIC_SECRET_KEY_GEN)
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle))
        assert rv == CKR_OK, f"Key gen failed: {rv}"
        key = handle.value
        try:
            verify_mech = mech_simple(CKM_SHA256_HMAC)
            rv2 = rs.raw.C_VerifyInit(rs.sh, verify_mech.byref(), key)
            assert rv2 != CKR_OK, (
                "C_VerifyInit with CKA_VERIFY=False should fail but returned CKR_OK"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_wrap_without_flag(self, p11_module_session: RawSession) -> None:
        """Wrapping key with CKA_WRAP=False must fail C_WrapKey."""
        rs = p11_module_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("CKM_AES_KEY_WRAP not supported")
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")

        try:
            from pkcs11_check.raw.types_std import CK_ULONG, CKM_AES_KEY_WRAP
        except ImportError:
            pytest.skip("CKM_AES_KEY_WRAP not in types_std")

        wrapping_key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_WRAP: False, CKA_UNWRAP: True, CKA_ENCRYPT: True, CKA_TOKEN: False},
            purpose="wrap-permission negative test setup",
        )
        target_key = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False, CKA_TOKEN: False},
            purpose="wrap target negative test setup",
        )
        try:
            wrap_mech = mech_simple(CKM_AES_KEY_WRAP)
            out_len = CK_ULONG(0)
            rv = rs.raw.C_WrapKey(
                rs.sh, wrap_mech.byref(), wrapping_key, target_key, None, byref(out_len)
            )
            assert rv != CKR_OK, "C_WrapKey with CKA_WRAP=False should fail but returned CKR_OK"
        finally:
            destroy_quietly(rs.raw, rs.sh, wrapping_key)
            destroy_quietly(rs.raw, rs.sh, target_key)

    def test_derive_without_flag(self, p11_module_session: RawSession) -> None:
        """Key with CKA_DERIVE=False cannot be used as derive base key."""
        rs = p11_module_session
        if not rs.has_mechanism("SHA256_KEY_DERIVATION"):
            pytest.skip("CKM_SHA256_KEY_DERIVATION not supported")
        if not rs.has_mechanism("GENERIC_SECRET_KEY_GEN"):
            pytest.skip("CKM_GENERIC_SECRET_KEY_GEN not supported")

        try:
            from pkcs11_check.raw.types_std import CKM_SHA256_KEY_DERIVATION
        except ImportError:
            pytest.skip("CKM_SHA256_KEY_DERIVATION not in types_std")

        # Generate a generic secret key with CKA_DERIVE=False
        attrs: dict[int, Any] = {
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_DERIVE: False,
            CKA_TOKEN: False,
        }
        packed = [attr_ulong(CKA_VALUE_LEN, 32)]
        packed.extend(pack_attrs(attrs, skip={CKA_VALUE_LEN}))
        tmpl = template(*packed)
        mech = mech_simple(CKM_GENERIC_SECRET_KEY_GEN)
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle))
        assert rv == CKR_OK, f"Key gen failed: {rv}"
        base_key = handle.value

        derived_key = CK_OBJECT_HANDLE(0)
        try:
            derive_mech = mech_simple(CKM_SHA256_KEY_DERIVATION)

            # Derived key template
            derived_attrs: dict[int, Any] = {
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_TOKEN: False,
            }
            d_packed = [attr_ulong(CKA_VALUE_LEN, 16)]
            d_packed.extend(pack_attrs(derived_attrs, skip={CKA_VALUE_LEN}))
            d_tmpl = template(*d_packed)

            rv2 = rs.raw.C_DeriveKey(
                rs.sh,
                derive_mech.byref(),
                base_key,
                d_tmpl.ptr,
                d_tmpl.count,
                byref(derived_key),
            )
            assert rv2 != CKR_OK, (
                "C_DeriveKey with CKA_DERIVE=False should fail but returned CKR_OK"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if derived_key.value != 0:
                destroy_quietly(rs.raw, rs.sh, derived_key.value)
