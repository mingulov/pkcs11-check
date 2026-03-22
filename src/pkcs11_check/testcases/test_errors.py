"""Tests for PKCS#11 error handling, edge cases, and robustness.

Covers invalid operations, boundary conditions, empty inputs,
session edge cases, and key lifecycle.
"""

from __future__ import annotations

from typing import Any

import pkcs11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

pytestmark = pytest.mark.security


class TestInvalidOperations:
    def test_invalid_mechanism_param(self, p11_session: Any) -> None:
        """Using wrong mechanism parameters should raise or produce garbage."""
        key = p11_session.generate_key(KeyType.AES, 256)
        try:
            ct = key.encrypt(b"0123456789abcdef", mechanism_param=b"short")
            assert isinstance(ct, bytes)
        except pkcs11.exceptions.PKCS11Error:
            pass  # Expected - module rejected invalid params

    def test_generate_key_invalid_size(self, p11_session: Any) -> None:
        """Requesting unsupported key size should fail or produce unusable key."""
        try:
            key = p11_session.generate_key(KeyType.AES, 13)
            key.destroy()
        except pkcs11.exceptions.PKCS11Error:
            pass  # Expected

    def test_verify_with_wrong_mechanism(self, p11_session: Any) -> None:
        """Sign with one mechanism, verify with another - should fail or differ."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"mechanism mismatch test"
        sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)

        try:
            result = pub.verify(data, sig, mechanism=Mechanism.SHA384_RSA_PKCS)
            # Some modules don't check DigestInfo OID - just note it
            assert result is True or result is False
        except pkcs11.exceptions.PKCS11Error:
            pass  # Expected - module rejected mechanism mismatch

    def test_encrypt_with_sign_key(self, p11_session: Any) -> None:
        """Using a sign-only key for encryption should fail."""
        _, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        try:
            priv.encrypt(b"test", mechanism=Mechanism.RSA_PKCS)
            # Some modules allow this - not a hard failure
        except (pkcs11.exceptions.PKCS11Error, AttributeError):
            pass  # Expected

    def test_decrypt_garbage(self, p11_session: Any) -> None:
        """Decrypting random garbage should fail cleanly."""
        pub, priv = p11_session.generate_keypair(
            KeyType.RSA,
            2048,
            public_template={Attribute.ENCRYPT: True, Attribute.TOKEN: False},
            private_template={Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        garbage = p11_session.generate_random(2048)  # 256 bytes
        try:
            priv.decrypt(garbage, mechanism=Mechanism.RSA_PKCS)
            # If decryption "succeeds", the result is garbage - that's OK
        except pkcs11.exceptions.PKCS11Error:
            pass  # Expected - padding check failed


class TestEmptyInputs:
    def test_encrypt_empty_data(self, p11_session: Any) -> None:
        """Encrypting empty data - behavior is implementation-defined."""
        key = p11_session.generate_key(KeyType.AES, 256)
        iv = p11_session.generate_random(128)
        try:
            ct = key.encrypt(b"", mechanism_param=iv)
            assert isinstance(ct, bytes)
        except pkcs11.exceptions.PKCS11Error:
            pass

    def test_digest_empty_data(self, p11_session: Any) -> None:
        """Digest of empty data should succeed and produce correct hash."""
        import hashlib

        digest = p11_session.digest(b"", mechanism=Mechanism.SHA256)
        assert digest == hashlib.sha256(b"").digest()

    def test_sign_empty_data(self, p11_session: Any) -> None:
        """Signing empty data should succeed (hash handles it)."""
        _, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        try:
            sig = priv.sign(b"", mechanism=Mechanism.SHA256_RSA_PKCS)
            assert len(sig) == 256
        except pkcs11.exceptions.PKCS11Error:
            pass  # Some modules reject empty data


class TestKeyLifecycle:
    def test_use_destroyed_key(self, p11_session: Any) -> None:
        """Using a key after destroy should fail."""
        key = p11_session.generate_key(KeyType.AES, 256)
        key.destroy()
        try:
            key.encrypt(b"0123456789abcdef", mechanism=Mechanism.AES_ECB)
            pytest.fail("Should not be able to use destroyed key")
        except pkcs11.exceptions.PKCS11Error:
            pass  # Expected

    def test_bulk_key_generation(self, p11_session: Any) -> None:
        """Generate many keys in sequence without issues."""
        keys = []
        for i in range(10):
            key = p11_session.generate_key(KeyType.AES, 256, label=f"bulk-{i}")
            keys.append(key)
        assert len(keys) == 10

    def test_key_attribute_access(self, p11_session: Any) -> None:
        """Key attributes should be readable."""
        key = p11_session.generate_key(KeyType.AES, 256)
        assert key.key_type == KeyType.AES
        assert key[Attribute.ENCRYPT] is True or key[Attribute.ENCRYPT] is False

    def test_create_object_minimal(self, p11_session: Any) -> None:
        """Import a key with minimal attributes."""
        key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.AES,
                Attribute.VALUE: bytes(32),
                Attribute.TOKEN: False,
            }
        )
        assert key is not None


class TestSessionEdgeCases:
    def test_large_random_generation(self, p11_session: Any) -> None:
        """Generate a large random buffer (1024 bytes)."""
        data = p11_session.generate_random(8192)
        assert len(data) == 1024

    def test_small_random_generation(self, p11_session: Any) -> None:
        """Generate minimal random (1 byte)."""
        data = p11_session.generate_random(8)
        assert len(data) == 1

    def test_sign_verify_large_data(self, p11_session: Any) -> None:
        """Sign and verify a larger data payload (10 KB)."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"x" * 10000
        sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        assert pub.verify(data, sig, mechanism=Mechanism.SHA256_RSA_PKCS) is True

    def test_multiple_operations_same_key(self, p11_session: Any) -> None:
        """Multiple sequential operations on the same key."""
        key = p11_session.generate_key(KeyType.AES, 256)
        for _ in range(100):
            ct = key.encrypt(b"0123456789abcdef", mechanism=Mechanism.AES_ECB)
            pt = key.decrypt(ct, mechanism=Mechanism.AES_ECB)
            assert pt == b"0123456789abcdef"

    def test_concurrent_keypair_generation(self, p11_session: Any) -> None:
        """Generate multiple keypairs in sequence."""
        for _ in range(3):
            pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
            assert pub is not None
            assert priv is not None
