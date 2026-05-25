"""Parametrized tests across key sizes for AES and RSA.

Verifies that all standard key sizes work correctly for generation,
encrypt/decrypt, and sign/verify operations.

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_oaep
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    import_secret_key,
    read_attributes,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_MODULUS,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VERIFY,
    CKG_MGF1_SHA1,
    CKK_AES,
    CKM_AES_ECB,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA_1,
)
from pkcs11_check.testcases.conftest import gen_aes_key_or_xfail, gen_rsa_keypair_or_xfail

pytestmark = pytest.mark.keymgmt


class TestAESKeySizes:
    """Test AES operations across all standard key sizes."""

    @pytest.mark.parametrize("key_bits", [128, 192, 256])
    def test_aes_generate(self, p11_raw_session: Any, key_bits: int) -> None:
        """Generate AES key at each standard size."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, key_bits, purpose="key-size coverage")
        try:
            assert key != 0
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_KEY_TYPE])
            assert attrs[CKA_KEY_TYPE] == CKK_AES
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    @pytest.mark.parametrize("key_bits", [128, 192, 256])
    def test_aes_ecb_roundtrip(self, p11_raw_session: Any, key_bits: int) -> None:
        """AES-ECB encrypt/decrypt roundtrip at each key size."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            key_bits,
            attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True},
            purpose="AES-ECB key-size roundtrip",
        )
        plaintext = b"key size test!!!"  # 16 bytes
        try:
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, plaintext)
            pt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    @pytest.mark.parametrize("key_bits", [128, 192, 256])
    def test_aes_import_export(self, p11_raw_session: Any, key_bits: int) -> None:
        """Import and export AES key at each size."""
        rs = p11_raw_session
        key_bytes = bytes(key_bits // 8)
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


class TestRSAKeySizes:
    """Test RSA operations across key sizes."""

    @pytest.mark.parametrize("key_bits", [2048, 3072, 4096])
    def test_rsa_generate(self, p11_raw_session: Any, key_bits: int) -> None:
        """Generate RSA key pair at each size."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair_or_xfail(rs, key_bits)
        try:
            modulus = read_attributes(rs.raw, rs.sh, pub, [CKA_MODULUS])[CKA_MODULUS]
            assert len(modulus) == key_bits // 8
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.parametrize("key_bits", [2048, 3072, 4096])
    def test_rsa_sign_verify(self, p11_raw_session: Any, key_bits: int) -> None:
        """RSA sign/verify at each key size."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            key_bits,
            public_attrs={CKA_VERIFY: True},
            private_attrs={CKA_SIGN: True},
        )
        try:
            data = f"RSA-{key_bits} sign test".encode()
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)
            assert len(sig) == key_bits // 8
            assert verify_single(rs.raw, rs.sh, pub, CKM_SHA256_RSA_PKCS, data, sig)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.parametrize("key_bits", [2048, 4096])
    def test_rsa_oaep_roundtrip(self, p11_raw_session: Any, key_bits: int) -> None:
        """RSA-OAEP encrypt/decrypt at each key size."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_OAEP"):
            pytest.skip("CKM_RSA_PKCS_OAEP not supported")
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            key_bits,
            public_attrs={CKA_ENCRYPT: True},
            private_attrs={CKA_DECRYPT: True},
        )
        try:
            plaintext = f"OAEP-{key_bits}".encode()
            mp = mech_oaep(
                CKM_RSA_PKCS_OAEP,
                hash_mech=CKM_SHA_1,
                mgf=CKG_MGF1_SHA1,
            )
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                pub,
                CKM_RSA_PKCS_OAEP,
                plaintext,
                mech_param=mp,
            )
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                priv,
                CKM_RSA_PKCS_OAEP,
                ct,
                mech_param=mp,
            )
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
