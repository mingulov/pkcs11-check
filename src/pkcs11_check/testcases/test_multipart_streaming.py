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
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

from pkcs11_check.testcases.conftest import import_aes_key

pytestmark = pytest.mark.multipart


class TestMultipartEncrypt:
    """Verify encrypt correctness at various sizes (triggers C_EncryptUpdate)."""

    @pytest.mark.parametrize("num_blocks", [1, 4, 16, 64, 256, 1024])
    def test_aes_ecb_multiblock_roundtrip(self, p11_session: Any, num_blocks: int) -> None:
        """AES-ECB roundtrip with varying block counts."""
        key = p11_session.generate_key(KeyType.AES, 256)
        data = bytes(range(256)) * (num_blocks * 16 // 256 or 1)
        data = data[: num_blocks * 16]

        ct = key.encrypt(data, mechanism=Mechanism.AES_ECB)
        pt = key.decrypt(ct, mechanism=Mechanism.AES_ECB)
        assert pt == data

    @pytest.mark.parametrize("size", [16, 256, 4096, 65536])
    def test_aes_ecb_crossverify_large(self, p11_session: Any, size: int) -> None:
        """Large AES-ECB encrypt cross-verified against cryptography."""
        key_bytes = bytes(range(32))
        data = b"\xab" * size

        p11_key = import_aes_key(p11_session, key_bytes)
        ct_p11 = p11_key.encrypt(data, mechanism=Mechanism.AES_ECB)

        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
        enc = cipher.encryptor()
        ct_crypto = enc.update(data) + enc.finalize()

        assert ct_p11 == ct_crypto

    def test_cbc_multiblock_roundtrip(self, p11_session: Any) -> None:
        """AES-CBC with 4KB data -- exercises Update path."""
        key = p11_session.generate_key(KeyType.AES, 256)
        iv = p11_session.generate_random(128)  # 16 bytes
        data = b"\x42" * 4096

        ct = key.encrypt(data, mechanism=Mechanism.AES_CBC, mechanism_param=iv)
        pt = key.decrypt(ct, mechanism=Mechanism.AES_CBC, mechanism_param=iv)
        assert pt == data


class TestMultipartDigest:
    """Verify digest correctness for large data (triggers C_DigestUpdate)."""

    @pytest.mark.parametrize("size", [0, 1, 64, 1024, 65536, 1048576])
    def test_sha256_large_data_crossverify(self, p11_session: Any, size: int) -> None:
        """SHA-256 of various sizes matches hashlib."""
        data = b"\xcd" * size
        p11_digest = p11_session.digest(data, mechanism=Mechanism.SHA256)
        expected = hashlib.sha256(data).digest()
        assert p11_digest == expected

    def test_sha512_1mb_crossverify(self, p11_session: Any) -> None:
        """SHA-512 of 1MB data matches hashlib."""
        data = b"\xef" * (1024 * 1024)
        p11_digest = p11_session.digest(data, mechanism=Mechanism.SHA512)
        expected = hashlib.sha512(data).digest()
        assert p11_digest == expected


class TestMultipartSign:
    """Verify sign correctness for large data (triggers C_SignUpdate)."""

    def test_rsa_sign_large_data(self, p11_session: Any) -> None:
        """RSA sign 10KB data -- hash computed internally via Update."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"\x99" * 10240

        sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        assert len(sig) == 256
        assert pub.verify(data, sig, mechanism=Mechanism.SHA256_RSA_PKCS)

    def test_hmac_large_data_crossverify(self, p11_session: Any) -> None:
        """HMAC-SHA256 of 64KB data cross-verified against hmac module."""
        import hmac as hmac_mod

        key_bytes = bytes(range(32))
        data = b"\x77" * 65536

        p11_key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.SHA256_HMAC,
                Attribute.VALUE: key_bytes,
                Attribute.SIGN: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )
        p11_mac = p11_key.sign(data, mechanism=Mechanism.SHA256_HMAC)
        expected = hmac_mod.new(key_bytes, data, hashlib.sha256).digest()
        assert p11_mac == expected
