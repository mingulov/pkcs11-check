"""Buffer management tests -- output sizing, boundary conditions.

Tests that operations handle various data sizes correctly, including
empty data, single-byte, block boundaries, and large payloads.
Based on OASIS PKCS#11 conventions for function output.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

pytestmark = pytest.mark.boundary


class TestEncryptBufferSizes:
    """Test encryption with various input sizes."""

    def test_single_block(self, p11_session: Any) -> None:
        """Encrypt exactly one AES block (16 bytes)."""
        key = p11_session.generate_key(KeyType.AES, 256)
        pt = b"X" * 16
        ct = key.encrypt(pt, mechanism=Mechanism.AES_ECB)
        assert len(ct) == 16
        assert key.decrypt(ct, mechanism=Mechanism.AES_ECB) == pt

    def test_two_blocks(self, p11_session: Any) -> None:
        """Encrypt exactly two blocks."""
        key = p11_session.generate_key(KeyType.AES, 256)
        pt = b"Y" * 32
        ct = key.encrypt(pt, mechanism=Mechanism.AES_ECB)
        assert len(ct) == 32
        assert key.decrypt(ct, mechanism=Mechanism.AES_ECB) == pt

    def test_100_blocks(self, p11_session: Any) -> None:
        """Encrypt 100 blocks (1600 bytes)."""
        key = p11_session.generate_key(KeyType.AES, 256)
        pt = b"Z" * 1600
        ct = key.encrypt(pt, mechanism=Mechanism.AES_ECB)
        assert len(ct) == 1600
        assert key.decrypt(ct, mechanism=Mechanism.AES_ECB) == pt

    def test_64kb(self, p11_session: Any) -> None:
        """Encrypt 64KB payload."""
        key = p11_session.generate_key(KeyType.AES, 256)
        pt = bytes(range(256)) * 256  # 64KB, block-aligned
        ct = key.encrypt(pt, mechanism=Mechanism.AES_ECB)
        assert len(ct) == 65536
        assert key.decrypt(ct, mechanism=Mechanism.AES_ECB) == pt

    def test_1mb(self, p11_session: Any) -> None:
        """Encrypt 1MB payload -- tests streaming/chunking."""
        key = p11_session.generate_key(KeyType.AES, 256)
        pt = b"\xAB" * (1024 * 1024)  # 1MB
        ct = key.encrypt(pt, mechanism=Mechanism.AES_ECB)
        assert len(ct) == 1024 * 1024
        assert key.decrypt(ct, mechanism=Mechanism.AES_ECB) == pt


class TestDigestBufferSizes:
    """Test digest with various input sizes."""

    def test_empty_input(self, p11_session: Any) -> None:
        """SHA-256 of empty data."""
        digest = p11_session.digest(b"", mechanism=Mechanism.SHA256)
        assert len(digest) == 32

    def test_single_byte(self, p11_session: Any) -> None:
        """SHA-256 of single byte."""
        digest = p11_session.digest(b"\x00", mechanism=Mechanism.SHA256)
        assert len(digest) == 32

    def test_exactly_block_size(self, p11_session: Any) -> None:
        """SHA-256 of exactly one SHA-256 block (64 bytes)."""
        digest = p11_session.digest(b"A" * 64, mechanism=Mechanism.SHA256)
        assert len(digest) == 32

    def test_block_boundary_minus_one(self, p11_session: Any) -> None:
        """SHA-256 of 63 bytes (one less than block size)."""
        digest = p11_session.digest(b"B" * 63, mechanism=Mechanism.SHA256)
        assert len(digest) == 32

    def test_block_boundary_plus_one(self, p11_session: Any) -> None:
        """SHA-256 of 65 bytes (one more than block size)."""
        digest = p11_session.digest(b"C" * 65, mechanism=Mechanism.SHA256)
        assert len(digest) == 32

    def test_large_input(self, p11_session: Any) -> None:
        """SHA-256 of 1MB input."""
        data = b"D" * (1024 * 1024)
        digest = p11_session.digest(data, mechanism=Mechanism.SHA256)
        assert len(digest) == 32


class TestSignBufferSizes:
    """Test signing with various data sizes."""

    def test_sign_empty(self, p11_session: Any) -> None:
        """RSA sign of empty data."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        sig = priv.sign(b"", mechanism=Mechanism.SHA256_RSA_PKCS)
        assert len(sig) == 256
        assert pub.verify(b"", sig, mechanism=Mechanism.SHA256_RSA_PKCS)

    def test_sign_single_byte(self, p11_session: Any) -> None:
        """RSA sign of single byte."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        sig = priv.sign(b"X", mechanism=Mechanism.SHA256_RSA_PKCS)
        assert pub.verify(b"X", sig, mechanism=Mechanism.SHA256_RSA_PKCS)

    def test_sign_100kb(self, p11_session: Any) -> None:
        """RSA sign of 100KB payload."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"E" * 100_000
        sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        assert pub.verify(data, sig, mechanism=Mechanism.SHA256_RSA_PKCS)


class TestKeyImportBufferSizes:
    """Test key import with various key sizes."""

    def test_aes_128(self, p11_session: Any) -> None:
        key = p11_session.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.AES,
            Attribute.VALUE: bytes(16),
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
        })
        assert key[Attribute.VALUE] == bytes(16)

    def test_aes_192(self, p11_session: Any) -> None:
        key = p11_session.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.AES,
            Attribute.VALUE: bytes(24),
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
        })
        assert key[Attribute.VALUE] == bytes(24)

    def test_aes_256(self, p11_session: Any) -> None:
        key = p11_session.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.AES,
            Attribute.VALUE: bytes(32),
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
        })
        assert key[Attribute.VALUE] == bytes(32)


class TestRandomBufferSizes:
    """Test C_GenerateRandom with various sizes."""

    def test_1_byte(self, p11_session: Any) -> None:
        assert len(p11_session.generate_random(8)) == 1

    def test_16_bytes(self, p11_session: Any) -> None:
        assert len(p11_session.generate_random(128)) == 16

    def test_256_bytes(self, p11_session: Any) -> None:
        assert len(p11_session.generate_random(2048)) == 256

    def test_4096_bytes(self, p11_session: Any) -> None:
        assert len(p11_session.generate_random(32768)) == 4096
