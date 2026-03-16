"""Tests for multi-part (streaming/chunked) PKCS#11 operations."""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import KeyType, Mechanism

pytestmark = pytest.mark.multipart


class TestMultiPartDigest:
    def test_sha256_consistency(self, p11_session: Any) -> None:
        """SHA-256 of same data always produces same result."""
        data = b"A" * 100 + b"B" * 100
        d1 = p11_session.digest(data, mechanism=Mechanism.SHA256)
        d2 = p11_session.digest(data, mechanism=Mechanism.SHA256)
        assert d1 == d2

    def test_sha256_different_data_different_digest(self, p11_session: Any) -> None:
        """Different data produces different SHA-256."""
        d1 = p11_session.digest(b"data one", mechanism=Mechanism.SHA256)
        d2 = p11_session.digest(b"data two", mechanism=Mechanism.SHA256)
        assert d1 != d2

    def test_sha512_output_size(self, p11_session: Any) -> None:
        """SHA-512 of large data produces 64-byte output."""
        data = b"test data " * 1000
        result = p11_session.digest(data, mechanism=Mechanism.SHA512)
        assert len(result) == 64


class TestMultiPartEncrypt:
    def test_encrypt_16kb(self, p11_session: Any) -> None:
        """Encrypt 16KB of data (multiple AES blocks)."""
        key = p11_session.generate_key(KeyType.AES, 256)
        plaintext = b"X" * (1024 * 16)
        ct = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        pt = key.decrypt(ct, mechanism=Mechanism.AES_ECB)
        assert pt == plaintext

    def test_encrypt_various_block_sizes(self, p11_session: Any) -> None:
        """Encrypt at different sizes that are multiples of block size."""
        key = p11_session.generate_key(KeyType.AES, 256)
        for num_blocks in [1, 2, 4, 8, 16, 64]:
            plaintext = bytes(range(256))[:16] * num_blocks
            ct = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
            pt = key.decrypt(ct, mechanism=Mechanism.AES_ECB)
            assert pt == plaintext

    def test_encrypt_same_key_deterministic(self, p11_session: Any) -> None:
        """AES-ECB with same key and plaintext produces same ciphertext."""
        key = p11_session.generate_key(KeyType.AES, 256)
        plaintext = b"deterministic!!!"
        ct1 = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        ct2 = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        assert ct1 == ct2


class TestMultiPartSign:
    def test_rsa_sign_10kb(self, p11_session: Any) -> None:
        """Sign a 10KB payload with RSA."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"Y" * 10000
        sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        assert len(sig) == 256
        assert pub.verify(data, sig, mechanism=Mechanism.SHA256_RSA_PKCS) is True

    def test_rsa_sign_1byte(self, p11_session: Any) -> None:
        """Sign minimal 1-byte payload."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"X"
        sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        assert pub.verify(data, sig, mechanism=Mechanism.SHA256_RSA_PKCS) is True

    def test_rsa_sign_empty(self, p11_session: Any) -> None:
        """Sign empty payload."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b""
        sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        assert pub.verify(data, sig, mechanism=Mechanism.SHA256_RSA_PKCS) is True
