"""Tests for PKCS#11 encrypt/decrypt operations."""

from __future__ import annotations

from typing import Any

from pkcs11 import KeyType


class TestAESEncryption:
    def test_aes_generate_key(self, p11_session: Any) -> None:
        """Generate an AES-256 session key."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
        )
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
