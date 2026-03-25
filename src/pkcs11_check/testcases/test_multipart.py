"""Tests for multi-part (streaming/chunked) PKCS#11 operations."""

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
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKM_AES_ECB,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA512,
)

pytestmark = pytest.mark.multipart


class TestMultiPartDigest:
    def test_sha256_consistency(self, p11_raw_session: Any) -> None:
        """SHA-256 of same data always produces same result."""
        rs = p11_raw_session
        data = b"A" * 100 + b"B" * 100
        d1 = digest_single(rs.raw, rs.sh, CKM_SHA256, data)
        d2 = digest_single(rs.raw, rs.sh, CKM_SHA256, data)
        assert d1 == d2

    def test_sha256_different_data_different_digest(self, p11_raw_session: Any) -> None:
        """Different data produces different SHA-256."""
        rs = p11_raw_session
        d1 = digest_single(rs.raw, rs.sh, CKM_SHA256, b"data one")
        d2 = digest_single(rs.raw, rs.sh, CKM_SHA256, b"data two")
        assert d1 != d2

    def test_sha512_output_size(self, p11_raw_session: Any) -> None:
        """SHA-512 of large data produces 64-byte output."""
        rs = p11_raw_session
        data = b"test data " * 1000
        result = digest_single(rs.raw, rs.sh, CKM_SHA512, data)
        assert len(result) == 64


class TestMultiPartEncrypt:
    def test_encrypt_16kb(self, p11_raw_session: Any) -> None:
        """Encrypt 16KB of data (multiple AES blocks)."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        plaintext = b"X" * (1024 * 16)
        try:
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, plaintext)
            pt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_encrypt_various_block_sizes(self, p11_raw_session: Any) -> None:
        """Encrypt at different sizes that are multiples of block size."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            for num_blocks in [1, 2, 4, 8, 16, 64]:
                plaintext = bytes(range(256))[:16] * num_blocks
                ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, plaintext)
                pt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
                assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_encrypt_same_key_deterministic(self, p11_raw_session: Any) -> None:
        """AES-ECB with same key and plaintext produces same ciphertext."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        plaintext = b"deterministic!!!"
        try:
            ct1 = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, plaintext)
            ct2 = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, plaintext)
            assert ct1 == ct2
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestMultiPartSign:
    def test_rsa_sign_10kb(self, p11_raw_session: Any) -> None:
        """Sign a 10KB payload with RSA."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        data = b"Y" * 10000
        try:
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)
            assert len(sig) == 256
            assert verify_single(rs.raw, rs.sh, pub, CKM_SHA256_RSA_PKCS, data, sig) is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_sign_1byte(self, p11_raw_session: Any) -> None:
        """Sign minimal 1-byte payload."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        data = b"X"
        try:
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)
            assert verify_single(rs.raw, rs.sh, pub, CKM_SHA256_RSA_PKCS, data, sig) is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_sign_empty(self, p11_raw_session: Any) -> None:
        """Sign empty payload."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        data = b""
        try:
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)
            assert verify_single(rs.raw, rs.sh, pub, CKM_SHA256_RSA_PKCS, data, sig) is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
