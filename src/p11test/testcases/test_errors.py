"""Tests for PKCS#11 error handling and edge cases."""

from __future__ import annotations

from typing import Any

import pkcs11
from pkcs11 import KeyType, Mechanism


class TestInvalidOperations:
    def test_invalid_mechanism_param(self, p11_session: Any) -> None:
        """Using wrong mechanism parameters should raise or produce garbage.

        Some modules (NSS) accept short IVs without error — this is
        module-specific behavior, not a test failure.
        """
        key = p11_session.generate_key(KeyType.AES, 256)
        try:
            ct = key.encrypt(b"0123456789abcdef", mechanism_param=b"short")
            # If no error, the module accepted it (NSS does this)
            # The result is likely wrong but the module didn't crash
            assert isinstance(ct, bytes)
        except pkcs11.exceptions.PKCS11Error:
            pass  # Expected — module rejected invalid params

    def test_generate_key_invalid_size(self, p11_session: Any) -> None:
        """Requesting unsupported key size should fail or produce unusable key."""
        try:
            key = p11_session.generate_key(KeyType.AES, 13)
            # Some modules accept invalid sizes — this is a module behavior finding
            # The key should at least be destroyable
            key.destroy()
        except pkcs11.exceptions.PKCS11Error:
            pass  # Expected: module rejected invalid size


class TestEmptyInputs:
    def test_encrypt_empty_data(self, p11_session: Any) -> None:
        """Encrypting empty data — behavior is implementation-defined."""
        key = p11_session.generate_key(KeyType.AES, 256)
        iv = p11_session.generate_random(128)
        try:
            ct = key.encrypt(b"", mechanism_param=iv)
            assert isinstance(ct, bytes)
        except pkcs11.exceptions.PKCS11Error:
            pass  # Also acceptable


class TestSessionEdgeCases:
    def test_bulk_key_generation(self, p11_session: Any) -> None:
        """Generate many keys in sequence without issues."""
        keys = []
        for i in range(10):
            key = p11_session.generate_key(KeyType.AES, 256, label=f"bulk-{i}")
            keys.append(key)
        assert len(keys) == 10

    def test_large_random_generation(self, p11_session: Any) -> None:
        """Generate a large random buffer (1024 bytes)."""
        data = p11_session.generate_random(8192)  # 8192 bits = 1024 bytes
        assert len(data) == 1024

    def test_small_random_generation(self, p11_session: Any) -> None:
        """Generate minimal random (1 byte)."""
        data = p11_session.generate_random(8)  # 8 bits = 1 byte
        assert len(data) == 1

    def test_sign_verify_large_data(self, p11_session: Any) -> None:
        """Sign and verify a larger data payload."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"x" * 10000
        sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        assert pub.verify(data, sig, mechanism=Mechanism.SHA256_RSA_PKCS) is True
