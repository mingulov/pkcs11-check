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
    gen_aes_key,
    gen_ec_keypair,
    gen_rsa_keypair,
    import_secret_key,
    read_attributes,
    unwrap_key,
    wrap_key,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
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
)

pytestmark = pytest.mark.keymgmt


class TestKeyImport:
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
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
            },
        )
        try:
            plaintext = b"import_rndtrip!!"  # exactly 16 bytes
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, plaintext)
            pt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
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
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
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
        pub, priv = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
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
        original = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_LABEL: b"original"},
        )
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
        original = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True},
        )
        copy = copy_object(
            rs.raw,
            rs.sh,
            original,
            {CKA_LABEL: b"independent"},
        )
        try:
            destroy_quietly(rs.raw, rs.sh, original)
            ct = encrypt_single(rs.raw, rs.sh, copy, CKM_AES_ECB, b"still works here")
            assert len(ct) > 0
        finally:
            destroy_quietly(rs.raw, rs.sh, copy)


class TestKeyWrapUnwrap:
    def test_wrap_unwrap_roundtrip(self, p11_raw_session: Any) -> None:
        """Wrap and unwrap a key, verify material is preserved."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("CKM_AES_KEY_WRAP not supported")
        key_bytes = bytes(range(16))
        wrapping_key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_WRAP: True, CKA_UNWRAP: True},
        )
        target = import_secret_key(
            rs.raw,
            rs.sh,
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

            unwrapped = unwrap_key(
                rs.raw,
                rs.sh,
                wrapping_key,
                wrapped,
                CKM_AES_KEY_WRAP,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                },
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
        _pub_a, priv_a = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
        pub_b, _priv_b = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
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
