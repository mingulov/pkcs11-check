"""Buffer management tests - output sizing, boundary conditions.

Tests that operations handle various data sizes correctly, including
empty data, single-byte, block boundaries, and large payloads.
Based on OASIS PKCS#11 conventions for function output.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    digest_single,
    encrypt_single,
    gen_aes_key,
    gen_rsa_keypair,
    generate_random,
    import_secret_key,
    read_attributes,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_VALUE,
    CKA_VERIFY,
    CKK_AES,
    CKM_AES_ECB,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
)

pytestmark = pytest.mark.boundary


class TestEncryptBufferSizes:
    """Test encryption with various input sizes."""

    def test_single_block(self, p11_raw_session: Any) -> None:
        """Encrypt exactly one AES block (16 bytes)."""
        rs = p11_raw_session
        enc_attrs = {int(CKA_ENCRYPT): True, int(CKA_DECRYPT): True}
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs=enc_attrs)
        try:
            pt = b"X" * 16
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, pt)
            assert len(ct) == 16
            dt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
            assert dt == pt
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_two_blocks(self, p11_raw_session: Any) -> None:
        """Encrypt exactly two blocks."""
        rs = p11_raw_session
        enc_attrs = {int(CKA_ENCRYPT): True, int(CKA_DECRYPT): True}
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs=enc_attrs)
        try:
            pt = b"Y" * 32
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, pt)
            assert len(ct) == 32
            dt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
            assert dt == pt
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_100_blocks(self, p11_raw_session: Any) -> None:
        """Encrypt 100 blocks (1600 bytes)."""
        rs = p11_raw_session
        enc_attrs = {int(CKA_ENCRYPT): True, int(CKA_DECRYPT): True}
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs=enc_attrs)
        try:
            pt = b"Z" * 1600
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, pt)
            assert len(ct) == 1600
            dt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
            assert dt == pt
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_64kb(self, p11_raw_session: Any) -> None:
        """Encrypt 64KB payload."""
        rs = p11_raw_session
        enc_attrs = {int(CKA_ENCRYPT): True, int(CKA_DECRYPT): True}
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs=enc_attrs)
        try:
            pt = bytes(range(256)) * 256  # 64KB, block-aligned
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, pt)
            assert len(ct) == 65536
            dt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
            assert dt == pt
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_1mb(self, p11_raw_session: Any) -> None:
        """Encrypt 1MB payload - tests streaming/chunking."""
        rs = p11_raw_session
        enc_attrs = {int(CKA_ENCRYPT): True, int(CKA_DECRYPT): True}
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs=enc_attrs)
        try:
            pt = b"\xAB" * (1024 * 1024)  # 1MB
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, pt)
            assert len(ct) == 1024 * 1024
            dt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
            assert dt == pt
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestDigestBufferSizes:
    """Test digest with various input sizes."""

    def test_empty_input(self, p11_raw_session: Any) -> None:
        """SHA-256 of empty data."""
        rs = p11_raw_session
        digest = digest_single(rs.raw, rs.sh, CKM_SHA256, b"")
        assert len(digest) == 32

    def test_single_byte(self, p11_raw_session: Any) -> None:
        """SHA-256 of single byte."""
        rs = p11_raw_session
        digest = digest_single(rs.raw, rs.sh, CKM_SHA256, b"\x00")
        assert len(digest) == 32

    def test_exactly_block_size(self, p11_raw_session: Any) -> None:
        """SHA-256 of exactly one SHA-256 block (64 bytes)."""
        rs = p11_raw_session
        digest = digest_single(rs.raw, rs.sh, CKM_SHA256, b"A" * 64)
        assert len(digest) == 32

    def test_block_boundary_minus_one(self, p11_raw_session: Any) -> None:
        """SHA-256 of 63 bytes (one less than block size)."""
        rs = p11_raw_session
        digest = digest_single(rs.raw, rs.sh, CKM_SHA256, b"B" * 63)
        assert len(digest) == 32

    def test_block_boundary_plus_one(self, p11_raw_session: Any) -> None:
        """SHA-256 of 65 bytes (one more than block size)."""
        rs = p11_raw_session
        digest = digest_single(rs.raw, rs.sh, CKM_SHA256, b"C" * 65)
        assert len(digest) == 32

    def test_large_input(self, p11_raw_session: Any) -> None:
        """SHA-256 of 1MB input."""
        rs = p11_raw_session
        data = b"D" * (1024 * 1024)
        digest = digest_single(rs.raw, rs.sh, CKM_SHA256, data)
        assert len(digest) == 32


class TestSignBufferSizes:
    """Test signing with various data sizes."""

    def test_sign_empty(self, p11_raw_session: Any) -> None:
        """RSA sign of empty data."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(
            rs.raw, rs.sh, 2048,
            public_attrs={int(CKA_VERIFY): True},
            private_attrs={int(CKA_SIGN): True},
        )
        try:
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, b"")
            assert len(sig) == 256
            verify_single(rs.raw, rs.sh, pub, CKM_SHA256_RSA_PKCS, b"", sig)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_sign_single_byte(self, p11_raw_session: Any) -> None:
        """RSA sign of single byte."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(
            rs.raw, rs.sh, 2048,
            public_attrs={int(CKA_VERIFY): True},
            private_attrs={int(CKA_SIGN): True},
        )
        try:
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, b"X")
            verify_single(rs.raw, rs.sh, pub, CKM_SHA256_RSA_PKCS, b"X", sig)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_sign_100kb(self, p11_raw_session: Any) -> None:
        """RSA sign of 100KB payload."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(
            rs.raw, rs.sh, 2048,
            public_attrs={int(CKA_VERIFY): True},
            private_attrs={int(CKA_SIGN): True},
        )
        try:
            data = b"E" * 100_000
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)
            verify_single(rs.raw, rs.sh, pub, CKM_SHA256_RSA_PKCS, data, sig)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestKeyImportBufferSizes:
    """Test key import with various key sizes."""

    def test_aes_128(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        key = import_secret_key(
            rs.raw, rs.sh, CKK_AES, bytes(16),
            attrs={int(CKA_SENSITIVE): False, int(CKA_EXTRACTABLE): True},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [int(CKA_VALUE)])
            assert attrs[int(CKA_VALUE)] == bytes(16)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_aes_192(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        key = import_secret_key(
            rs.raw, rs.sh, CKK_AES, bytes(24),
            attrs={int(CKA_SENSITIVE): False, int(CKA_EXTRACTABLE): True},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [int(CKA_VALUE)])
            assert attrs[int(CKA_VALUE)] == bytes(24)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_aes_256(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        key = import_secret_key(
            rs.raw, rs.sh, CKK_AES, bytes(32),
            attrs={int(CKA_SENSITIVE): False, int(CKA_EXTRACTABLE): True},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [int(CKA_VALUE)])
            assert attrs[int(CKA_VALUE)] == bytes(32)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestRandomBufferSizes:
    """Test C_GenerateRandom with various sizes."""

    def test_1_byte(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        assert len(generate_random(rs.raw, rs.sh, 1)) == 1

    def test_16_bytes(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        assert len(generate_random(rs.raw, rs.sh, 16)) == 16

    def test_256_bytes(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        assert len(generate_random(rs.raw, rs.sh, 256)) == 256

    def test_4096_bytes(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        assert len(generate_random(rs.raw, rs.sh, 4096)) == 4096
