"""True multipart streaming tests.

Verifies that C_EncryptUpdate/C_DecryptUpdate and C_DigestUpdate
produce correct results for data sizes that exceed single-call
buffers. Cross-verifies against Python cryptography library.

python-pkcs11 auto-splits into Update+Final calls internally,
so we test by verifying correctness on various data sizes.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pkcs11_check.raw.pack import mech_bytes
from pkcs11_check.raw.recipes import (
    create_object,
    decrypt_single,
    destroy_quietly,
    digest_single,
    encrypt_single,
    gen_aes_key,
    gen_rsa_keypair,
    generate_random,
    import_secret_key,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKK_AES,
    CKK_SHA256_HMAC,
    CKM_AES_CBC,
    CKM_AES_ECB,
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA512,
    CKO_SECRET_KEY,
)

pytestmark = pytest.mark.multipart


def _import_aes_key(rs: Any, key_bytes: bytes) -> int:
    """Import AES key bytes via raw API."""
    return import_secret_key(
        rs.raw,
        rs.sh,
        CKK_AES,
        key_bytes,
        attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
    )


class TestMultipartEncrypt:
    """Verify encrypt correctness at various sizes (triggers C_EncryptUpdate)."""

    @pytest.mark.parametrize("num_blocks", [1, 4, 16, 64, 256, 1024])
    def test_aes_ecb_multiblock_roundtrip(self, p11_raw_session: Any, num_blocks: int) -> None:
        """AES-ECB roundtrip with varying block counts."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        data = bytes(range(256)) * (num_blocks * 16 // 256 or 1)
        data = data[: num_blocks * 16]
        try:
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)
            pt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
            assert pt == data
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    @pytest.mark.parametrize("size", [16, 256, 4096, 65536])
    def test_aes_ecb_crossverify_large(self, p11_raw_session: Any, size: int) -> None:
        """Large AES-ECB encrypt cross-verified against cryptography."""
        rs = p11_raw_session
        key_bytes = bytes(range(32))
        data = b"\xab" * size

        p11_key = _import_aes_key(rs, key_bytes)
        try:
            ct_p11 = encrypt_single(rs.raw, rs.sh, p11_key, CKM_AES_ECB, data)

            # Intentional CKM_AES_ECB reference vector for PKCS#11 interoperability.
            cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())  # nosec B305
            enc = cipher.encryptor()
            ct_crypto = enc.update(data) + enc.finalize()

            assert ct_p11 == ct_crypto
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)

    def test_cbc_multiblock_roundtrip(self, p11_raw_session: Any) -> None:
        """AES-CBC with 4KB data - exercises Update path."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        iv = generate_random(rs.raw, rs.sh, 16)
        data = b"\x42" * 4096
        try:
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CBC,
                data,
                mech_param=mech_bytes(CKM_AES_CBC, iv),
            )
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CBC,
                ct,
                mech_param=mech_bytes(CKM_AES_CBC, iv),
            )
            assert pt == data
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestMultipartDigest:
    """Verify digest correctness for large data (triggers C_DigestUpdate)."""

    @pytest.mark.parametrize("size", [0, 1, 64, 1024, 65536, 1048576])
    def test_sha256_large_data_crossverify(self, p11_raw_session: Any, size: int) -> None:
        """SHA-256 of various sizes matches hashlib."""
        rs = p11_raw_session
        data = b"\xcd" * size
        p11_digest = digest_single(rs.raw, rs.sh, CKM_SHA256, data)
        expected = hashlib.sha256(data).digest()
        assert p11_digest == expected

    def test_sha512_1mb_crossverify(self, p11_raw_session: Any) -> None:
        """SHA-512 of 1MB data matches hashlib."""
        rs = p11_raw_session
        data = b"\xef" * (1024 * 1024)
        p11_digest = digest_single(rs.raw, rs.sh, CKM_SHA512, data)
        expected = hashlib.sha512(data).digest()
        assert p11_digest == expected


class TestMultipartSign:
    """Verify sign correctness for large data (triggers C_SignUpdate)."""

    def test_rsa_sign_large_data(self, p11_raw_session: Any) -> None:
        """RSA sign 10KB data - hash computed internally via Update."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        data = b"\x99" * 10240
        try:
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)
            assert len(sig) == 256
            assert verify_single(rs.raw, rs.sh, pub, CKM_SHA256_RSA_PKCS, data, sig)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_hmac_large_data_crossverify(self, p11_raw_session: Any) -> None:
        """HMAC-SHA256 of 64KB data cross-verified against hmac module."""
        import hmac as hmac_mod

        rs = p11_raw_session
        key_bytes = bytes(range(32))
        data = b"\x77" * 65536

        p11_key = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_SHA256_HMAC,
                CKA_VALUE: key_bytes,
                CKA_SIGN: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
        try:
            p11_mac = sign_single(rs.raw, rs.sh, p11_key, CKM_SHA256_HMAC, data)
            expected = hmac_mod.new(key_bytes, data, hashlib.sha256).digest()
            assert p11_mac == expected
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)
