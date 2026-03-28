"""Negative tests for mechanism error handling.

NOT parametrized by mechanism entry — uses explicit test cases.

Tests verify that the module correctly rejects operations with:
- Wrong key type (AES mechanism with RSA key, etc.)
- Missing CKA_* permission flags (CKA_ENCRYPT=False, etc.)

Each test is self-contained: it generates its own key, attempts the forbidden
operation, asserts CKR != CKR_OK, then destroys the key.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import attr_ulong, mech_simple, template
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    gen_ec_keypair,
    gen_rsa_keypair,
    pack_attrs,
)
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
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
    CKK_GENERIC_SECRET,
    CKM,
    CKM_AES_ECB,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKR_OK,
)

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.negative]

_P256_OID: bytes = encode_named_curve_parameters("secp256r1")

# Hard-coded mechanism IDs for mechanisms used as "wrong" mechanism in negative tests
_CKM_RSA_PKCS_ID: int = 0x00000001   # CKM_RSA_PKCS
_CKM_ECDSA_ID: int = 0x00001041       # CKM_ECDSA
_CKM_SHA256_HMAC_ID: int = 0x00000251  # CKM_SHA256_HMAC


def _gen_generic_secret(rs: RawSession, bits: int = 256) -> int:
    """Generate a generic secret key with sign/verify permissions."""
    attrs: dict[int, Any] = {
        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
        CKA_SIGN: True,
        CKA_VERIFY: True,
        CKA_TOKEN: False,
        CKA_EXTRACTABLE: True,
        CKA_SENSITIVE: False,
    }
    packed = [attr_ulong(CKA_VALUE_LEN, bits // 8)]
    packed.extend(pack_attrs(attrs, skip={CKA_VALUE_LEN}))
    tmpl = template(*packed)
    mech = mech_simple(CKM(CKM_GENERIC_SECRET_KEY_GEN))
    handle = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_GenerateKey(  # type: ignore[attr-defined]
        rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle)
    )
    assert rv == CKR_OK, f"Generic secret key gen failed: {rv}"
    return handle.value


class TestWrongKeyType:
    """EncryptInit/SignInit with wrong key type must be rejected."""

    def test_aes_ecb_with_rsa_key_rejected(self, p11_raw_session: RawSession) -> None:
        """CKM_AES_ECB with an RSA private key must fail EncryptInit."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")

        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            mech = mech_simple(CKM_AES_ECB)
            # Use the RSA private key handle with an AES mechanism
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), priv)  # type: ignore[attr-defined]
            assert rv != CKR_OK, (
                "C_EncryptInit(CKM_AES_ECB, RSA_priv) should fail but returned CKR_OK"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_pkcs_with_aes_key_rejected(self, p11_raw_session: RawSession) -> None:
        """CKM_RSA_PKCS with an AES key must fail EncryptInit."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("AES keygen not supported")

        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            mech = mech_simple(CKM(_CKM_RSA_PKCS_ID))
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)  # type: ignore[attr-defined]
            assert rv != CKR_OK, (
                "C_EncryptInit(CKM_RSA_PKCS, AES_key) should fail but returned CKR_OK"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_ecdsa_with_rsa_key_rejected(self, p11_raw_session: RawSession) -> None:
        """CKM_ECDSA with an RSA key must fail SignInit."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")

        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            mech = mech_simple(CKM(_CKM_ECDSA_ID))
            rv = rs.raw.C_SignInit(rs.sh, mech.byref(), priv)  # type: ignore[attr-defined]
            assert rv != CKR_OK, (
                "C_SignInit(CKM_ECDSA, RSA_priv) should fail but returned CKR_OK"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_hmac_sha256_with_rsa_key_rejected(self, p11_raw_session: RawSession) -> None:
        """CKM_SHA256_HMAC with an RSA key must fail SignInit."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")

        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            mech = mech_simple(CKM(_CKM_SHA256_HMAC_ID))
            rv = rs.raw.C_SignInit(rs.sh, mech.byref(), priv)  # type: ignore[attr-defined]
            assert rv != CKR_OK, (
                "C_SignInit(CKM_SHA256_HMAC, RSA_priv) should fail but returned CKR_OK"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_aes_ecb_with_ec_key_rejected(self, p11_raw_session: RawSession) -> None:
        """CKM_AES_ECB with an EC private key must fail EncryptInit."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC keygen not supported")

        pub, priv = gen_ec_keypair(rs.raw, rs.sh, _P256_OID)
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), priv)  # type: ignore[attr-defined]
            assert rv != CKR_OK, (
                "C_EncryptInit(CKM_AES_ECB, EC_priv) should fail but returned CKR_OK"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestMissingPermission:
    """Keys with required CKA flags set to False must be rejected."""

    def test_encrypt_without_flag(self, p11_raw_session: RawSession) -> None:
        """Key with CKA_ENCRYPT=False cannot EncryptInit."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_ENCRYPT: False, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)  # type: ignore[attr-defined]
            assert rv != CKR_OK, (
                "C_EncryptInit with CKA_ENCRYPT=False should fail but returned CKR_OK"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_decrypt_without_flag(self, p11_raw_session: RawSession) -> None:
        """Key with CKA_DECRYPT=False cannot DecryptInit."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_DECRYPT: False, CKA_ENCRYPT: True, CKA_TOKEN: False},
        )
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_DecryptInit(rs.sh, mech.byref(), key)  # type: ignore[attr-defined]
            assert rv != CKR_OK, (
                "C_DecryptInit with CKA_DECRYPT=False should fail but returned CKR_OK"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_sign_without_flag(self, p11_raw_session: RawSession) -> None:
        """Key with CKA_SIGN=False cannot SignInit."""
        rs = p11_raw_session
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
        mech = mech_simple(CKM(CKM_GENERIC_SECRET_KEY_GEN))
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(  # type: ignore[attr-defined]
            rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle)
        )
        assert rv == CKR_OK, f"Key gen failed: {rv}"
        key = handle.value
        try:
            sign_mech = mech_simple(CKM(_CKM_SHA256_HMAC_ID))
            rv2 = rs.raw.C_SignInit(rs.sh, sign_mech.byref(), key)  # type: ignore[attr-defined]
            assert rv2 != CKR_OK, (
                "C_SignInit with CKA_SIGN=False should fail but returned CKR_OK"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_verify_without_flag(self, p11_raw_session: RawSession) -> None:
        """Key with CKA_VERIFY=False cannot VerifyInit."""
        rs = p11_raw_session
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
        mech = mech_simple(CKM(CKM_GENERIC_SECRET_KEY_GEN))
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(  # type: ignore[attr-defined]
            rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle)
        )
        assert rv == CKR_OK, f"Key gen failed: {rv}"
        key = handle.value
        try:
            verify_mech = mech_simple(CKM(_CKM_SHA256_HMAC_ID))
            rv2 = rs.raw.C_VerifyInit(rs.sh, verify_mech.byref(), key)  # type: ignore[attr-defined]
            assert rv2 != CKR_OK, (
                "C_VerifyInit with CKA_VERIFY=False should fail but returned CKR_OK"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_wrap_without_flag(self, p11_raw_session: RawSession) -> None:
        """Wrapping key with CKA_WRAP=False must fail C_WrapKey."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("CKM_AES_KEY_WRAP not supported")
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")

        try:
            from pkcs11_check.raw.types_std import CK_ULONG, CKM_AES_KEY_WRAP
        except ImportError:
            pytest.skip("CKM_AES_KEY_WRAP not in types_std")

        wrapping_key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_WRAP: False, CKA_UNWRAP: True, CKA_ENCRYPT: True, CKA_TOKEN: False},
        )
        target_key = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False, CKA_TOKEN: False},
        )
        try:
            wrap_mech = mech_simple(CKM_AES_KEY_WRAP)
            out_len = CK_ULONG(0)
            rv = rs.raw.C_WrapKey(  # type: ignore[attr-defined]
                rs.sh, wrap_mech.byref(), wrapping_key, target_key, None, byref(out_len)
            )
            assert rv != CKR_OK, (
                "C_WrapKey with CKA_WRAP=False should fail but returned CKR_OK"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrapping_key)
            destroy_quietly(rs.raw, rs.sh, target_key)

    def test_derive_without_flag(self, p11_raw_session: RawSession) -> None:
        """Key with CKA_DERIVE=False cannot be used as derive base key."""
        rs = p11_raw_session
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
        mech = mech_simple(CKM(CKM_GENERIC_SECRET_KEY_GEN))
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(  # type: ignore[attr-defined]
            rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle)
        )
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

            rv2 = rs.raw.C_DeriveKey(  # type: ignore[attr-defined]
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
