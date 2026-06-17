"""Tests for PKCS#11 key management: import, export, wrap, unwrap, derive, copy.

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.der import decode_ec_point
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import mech_ecdh
from pkcs11_check.raw.recipes import (
    copy_object,
    decrypt_single,
    derive_key,
    destroy_quietly,
    encrypt_single,
    import_secret_key,
    read_attributes,
    wrap_key,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_EC_POINT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_WRAP,
    CKD_NULL,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_AES_ECB,
    CKM_AES_KEY_WRAP,
    CKM_ECDH1_DERIVE,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases.conftest import (
    gen_aes_key_or_xfail,
    gen_ec_keypair_or_xfail,
    gen_rsa_keypair_or_xfail,
    import_secret_key_negotiated,
    skip_unless_create_object_supported,
    skip_unless_mechanism,
    unwrap_key_for_mechanism_roundtrip,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.keymgmt

_KEYMGMT_OPERATION_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)


def _aes_keymgmt_key(rs: Any, *, attrs: dict[Any, Any] | None = None) -> int:
    return gen_aes_key_or_xfail(rs, 128, attrs=attrs, purpose="key-management setup")


def _encrypt_or_xfail(rs: Any, key: int, data: bytes) -> bytes:
    skip_unless_mechanism(rs, "AES_ECB")
    try:
        return encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _KEYMGMT_OPERATION_REJECT_RVS, "AES_ECB encrypt rejected")
    raise


def _decrypt_or_xfail(rs: Any, key: int, data: bytes) -> bytes:
    skip_unless_mechanism(rs, "AES_ECB")
    try:
        return decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _KEYMGMT_OPERATION_REJECT_RVS, "AES_ECB decrypt rejected")
    raise


class TestKeyImport:
    @pytest.fixture(autouse=True)
    def _skip_if_no_create_object(self, p11_raw_session: Any) -> None:
        skip_unless_create_object_supported(p11_raw_session)

    def test_import_aes_key(self, p11_raw_session: Any) -> None:
        """Import raw AES key material and verify attributes."""
        rs = p11_raw_session
        key_bytes = bytes(range(32))
        key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
            },
        )
        try:
            assert key != 0
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_KEY_TYPE])
            assert attrs[CKA_KEY_TYPE] == CKK_AES
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_import_aes_key_roundtrip(self, p11_raw_session: Any) -> None:
        """Import AES key, encrypt, decrypt, verify roundtrip."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "AES_ECB")
        key_bytes = bytes(range(32))
        key = import_secret_key_negotiated(
            rs,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
            },
        )
        try:
            plaintext = b"import_rndtrip!!"  # exactly 16 bytes
            ct = _encrypt_or_xfail(rs, key, plaintext)
            pt = _decrypt_or_xfail(rs, key, ct)
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_extractable_key_export(self, p11_raw_session: Any) -> None:
        """Export extractable key and verify material matches."""
        rs = p11_raw_session
        key_bytes = bytes(range(16))
        key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
            },
        )
        try:
            exported = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])[CKA_VALUE]
            assert exported == key_bytes
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_import_multiple_sizes(self, p11_raw_session: Any) -> None:
        """Import AES keys at 128, 192, 256 bit sizes."""
        rs = p11_raw_session
        for size_bytes in [16, 24, 32]:
            key_bytes = bytes(size_bytes)
            key = import_secret_key(
                rs.raw,
                rs.sh,
                CKK_AES,
                key_bytes,
                attrs={
                    CKA_TOKEN: False,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                },
            )
            try:
                exported = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])[CKA_VALUE]
                assert exported == key_bytes
            finally:
                destroy_quietly(rs.raw, rs.sh, key)


class TestKeyExport:
    def test_rsa_modulus_export(self, p11_raw_session: Any) -> None:
        """Export RSA modulus and exponent."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA key generation not supported")
        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_MODULUS, CKA_PUBLIC_EXPONENT])
            modulus = attrs[CKA_MODULUS]
            assert len(modulus) == 256
            exponent = attrs[CKA_PUBLIC_EXPONENT]
            assert len(exponent) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ec_point_export(self, p11_raw_session: Any) -> None:
        """Export EC public key point."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC key generation not supported")
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair_or_xfail(rs, curve_oid)
        try:
            attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_EC_POINT])
            ec_point = attrs[CKA_EC_POINT]
            assert len(ec_point) > 0
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestKeyCopy:
    def test_copy_preserves_attributes(self, p11_raw_session: Any) -> None:
        """Copy a key and verify attributes are preserved."""
        rs = p11_raw_session
        original = _aes_keymgmt_key(rs, attrs={CKA_LABEL: b"original"})
        copy = 0
        try:
            copy = copy_object(
                rs.raw,
                rs.sh,
                original,
                {CKA_LABEL: b"copy"},
            )
            attrs = read_attributes(rs.raw, rs.sh, copy, [CKA_LABEL, CKA_KEY_TYPE])
            assert attrs[CKA_LABEL] in (b"copy", "copy")
            assert attrs[CKA_KEY_TYPE] == CKK_AES
        finally:
            destroy_quietly(rs.raw, rs.sh, original)
            if copy:
                destroy_quietly(rs.raw, rs.sh, copy)

    def test_copy_independent(self, p11_raw_session: Any) -> None:
        """Copied key works independently after original is destroyed."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "AES_ECB")
        original = _aes_keymgmt_key(rs, attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True})
        copy = copy_object(
            rs.raw,
            rs.sh,
            original,
            {CKA_LABEL: b"independent"},
        )
        try:
            destroy_quietly(rs.raw, rs.sh, original)
            ct = _encrypt_or_xfail(rs, copy, b"still works here")
            assert len(ct) > 0
        finally:
            destroy_quietly(rs.raw, rs.sh, copy)


class TestKeyWrapUnwrap:
    def test_wrap_unwrap_roundtrip(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Wrap and unwrap a key, verify material is preserved."""
        rs = p11_raw_session
        skip_unless_create_object_supported(rs)
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("CKM_AES_KEY_WRAP not supported")
        key_bytes = bytes(range(16))
        wrapping_key = _aes_keymgmt_key(rs, attrs={CKA_WRAP: True, CKA_UNWRAP: True})
        target = import_secret_key_negotiated(
            rs,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_TOKEN: False,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
            },
        )
        unwrapped = 0
        try:
            wrapped = wrap_key(rs.raw, rs.sh, wrapping_key, target, CKM_AES_KEY_WRAP)
            assert len(wrapped) > 0

            unwrapped = unwrap_key_for_mechanism_roundtrip(
                rs,
                p11_config,
                unwrapping_key=wrapping_key,
                wrapped_key=wrapped,
                mechanism=CKM_AES_KEY_WRAP,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                },
                purpose="AES-KEY-WRAP keymgmt roundtrip",
            )
            exported = read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE])[CKA_VALUE]
            assert exported == key_bytes
        finally:
            destroy_quietly(rs.raw, rs.sh, wrapping_key)
            destroy_quietly(rs.raw, rs.sh, target)
            if unwrapped:
                destroy_quietly(rs.raw, rs.sh, unwrapped)


class TestKeyDerive:
    def test_ecdh_derive_produces_key(self, p11_raw_session: Any) -> None:
        """ECDH key derivation produces a usable shared secret."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC key generation not supported")
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        _pub_a, priv_a = gen_ec_keypair_or_xfail(rs, curve_oid, private_attrs={CKA_DERIVE: True})
        pub_b, _priv_b = gen_ec_keypair_or_xfail(rs, curve_oid)
        derived = 0
        try:
            # Read pub_b's EC_POINT and unwrap from DER
            ec_point_raw = read_attributes(rs.raw, rs.sh, pub_b, [CKA_EC_POINT])[CKA_EC_POINT]
            point_b = decode_ec_point(bytes(ec_point_raw))

            derived = derive_key(
                rs.raw,
                rs.sh,
                priv_a,
                CKM_ECDH1_DERIVE,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_TOKEN: False,
                },
                mech_param=mech_ecdh(
                    CKM_ECDH1_DERIVE,
                    kdf=CKD_NULL,
                    public_data=point_b,
                ),
            )
            assert derived != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, _pub_a)
            destroy_quietly(rs.raw, rs.sh, priv_a)
            destroy_quietly(rs.raw, rs.sh, pub_b)
            destroy_quietly(rs.raw, rs.sh, _priv_b)
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)
