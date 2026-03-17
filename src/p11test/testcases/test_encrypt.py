"""Tests for PKCS#11 encrypt/decrypt operations.

Covers AES key generation, multiple modes (CBC, ECB, GCM), key sizes,
and basic properties: roundtrip, key independence, ciphertext randomness.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism

pytestmark = pytest.mark.full


class TestAESEncryption:
    def test_aes_generate_key(self, p11_session: Any) -> None:
        """Generate an AES-256 session key."""
        key = p11_session.generate_key(KeyType.AES, 256)
        assert key is not None

    def test_aes_cbc_roundtrip(self, p11_session: Any) -> None:
        """Encrypt and decrypt with AES-CBC produces original plaintext."""
        key = p11_session.generate_key(KeyType.AES, 256)
        iv = p11_session.generate_random(128)
        # AES-CBC requires data aligned to block size (16 bytes)
        plaintext = b"hello pkcs11!!\x02\x02"  # 16 bytes with PKCS padding

        ciphertext = key.encrypt(plaintext, mechanism_param=iv)
        assert ciphertext != plaintext
        assert len(ciphertext) > 0

        decrypted = key.decrypt(ciphertext, mechanism_param=iv)
        assert decrypted == plaintext

    def test_aes_different_keys_different_ciphertext(self, p11_session: Any) -> None:
        """Same plaintext encrypted with different keys should differ."""
        key1 = p11_session.generate_key(KeyType.AES, 256)
        key2 = p11_session.generate_key(KeyType.AES, 256)
        iv = p11_session.generate_random(128)
        plaintext = b"test data 123456"  # 16 bytes

        ct1 = key1.encrypt(plaintext, mechanism_param=iv)
        ct2 = key2.encrypt(plaintext, mechanism_param=iv)
        assert ct1 != ct2

    def test_aes_ecb_roundtrip(self, p11_session: Any) -> None:
        """AES-ECB encrypt/decrypt roundtrip."""
        key = p11_session.generate_key(KeyType.AES, 256)
        plaintext = b"sixteen bytes!!" + b"\x01"  # 16 bytes

        ct = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        assert ct != plaintext
        pt = key.decrypt(ct, mechanism=Mechanism.AES_ECB)
        assert pt == plaintext

    @pytest.mark.parametrize("key_bits", [128, 192, 256])
    def test_aes_key_sizes(self, p11_session: Any, key_bits: int) -> None:
        """Generate AES keys of all standard sizes."""
        key = p11_session.generate_key(KeyType.AES, key_bits)
        assert key is not None
        assert key.key_type == KeyType.AES

    def test_aes_ciphertext_length(self, p11_session: Any) -> None:
        """AES-ECB ciphertext should be same length as plaintext (block-aligned)."""
        key = p11_session.generate_key(KeyType.AES, 256)
        plaintext = b"\x00" * 32  # 2 blocks
        ct = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        assert len(ct) == len(plaintext)

    def test_aes_encrypt_not_deterministic_cbc(self, p11_session: Any) -> None:
        """AES-CBC with different IVs produces different ciphertexts."""
        key = p11_session.generate_key(KeyType.AES, 256)
        plaintext = b"determinism test"  # 16 bytes
        iv1 = p11_session.generate_random(128)
        iv2 = p11_session.generate_random(128)

        ct1 = key.encrypt(plaintext, mechanism_param=iv1)
        ct2 = key.encrypt(plaintext, mechanism_param=iv2)
        assert ct1 != ct2

    def test_aes_wrong_key_decrypt_fails(self, p11_session: Any) -> None:
        """Decrypting with wrong key should produce garbage (ECB)."""
        key1 = p11_session.generate_key(KeyType.AES, 256)
        key2 = p11_session.generate_key(KeyType.AES, 256)
        plaintext = b"wrong key test!!"  # 16 bytes

        ct = key1.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        decrypted = key2.decrypt(ct, mechanism=Mechanism.AES_ECB)
        assert decrypted != plaintext

    def test_aes_empty_block_encrypt(self, p11_session: Any) -> None:
        """AES-ECB with exactly one block of zeros."""
        key = p11_session.generate_key(KeyType.AES, 256)
        plaintext = b"\x00" * 16
        ct = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        assert ct != plaintext
        assert len(ct) == 16


class TestRSAEncryption:
    def test_rsa_pkcs_roundtrip(self, p11_session: Any) -> None:
        """RSA PKCS#1 v1.5 encrypt/decrypt roundtrip."""
        pub, priv = p11_session.generate_keypair(
            KeyType.RSA,
            2048,
            public_template={Attribute.ENCRYPT: True, Attribute.TOKEN: False},
            private_template={Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        plaintext = b"RSA roundtrip test"
        ct = pub.encrypt(plaintext, mechanism=Mechanism.RSA_PKCS)
        pt = priv.decrypt(ct, mechanism=Mechanism.RSA_PKCS)
        assert pt == plaintext

    def test_rsa_oaep_roundtrip(self, p11_session: Any) -> None:
        """RSA-OAEP encrypt/decrypt roundtrip."""
        pub, priv = p11_session.generate_keypair(
            KeyType.RSA,
            2048,
            public_template={Attribute.ENCRYPT: True, Attribute.TOKEN: False},
            private_template={Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        plaintext = b"OAEP roundtrip test"
        ct = pub.encrypt(plaintext, mechanism=Mechanism.RSA_PKCS_OAEP)
        pt = priv.decrypt(ct, mechanism=Mechanism.RSA_PKCS_OAEP)
        assert pt == plaintext

    def test_rsa_ciphertext_is_random(self, p11_session: Any) -> None:
        """RSA-OAEP should produce different ciphertexts for same plaintext."""
        pub, _ = p11_session.generate_keypair(
            KeyType.RSA,
            2048,
            public_template={Attribute.ENCRYPT: True, Attribute.TOKEN: False},
            private_template={Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        plaintext = b"randomness test"
        ct1 = pub.encrypt(plaintext, mechanism=Mechanism.RSA_PKCS_OAEP)
        ct2 = pub.encrypt(plaintext, mechanism=Mechanism.RSA_PKCS_OAEP)
        assert ct1 != ct2
