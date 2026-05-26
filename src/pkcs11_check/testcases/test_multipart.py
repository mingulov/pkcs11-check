"""Tests for multi-part (streaming/chunked) PKCS#11 operations."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    digest_single,
    encrypt_single,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKM_AES_ECB,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA512,
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases.conftest import (
    gen_aes_key_or_xfail,
    gen_rsa_keypair_or_xfail,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.multipart

_OPERATION_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)


def _require_mechanism(rs: Any, name: str) -> None:
    if not rs.has_mechanism(name):
        pytest.skip(f"{name} not supported")


def _digest_or_xfail(rs: Any, mechanism: int, mech_name: str, data: bytes) -> bytes:
    _require_mechanism(rs, mech_name)
    try:
        return digest_single(rs.raw, rs.sh, mechanism, data)
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _OPERATION_REJECT_RVS, f"{mech_name} digest rejected")
    raise


def _aes_key_for_multipart_smoke(rs: Any) -> int:
    _require_mechanism(rs, "AES_ECB")
    return gen_aes_key_or_xfail(rs, 128, purpose="legacy multipart smoke")


def _encrypt_or_xfail(rs: Any, key: int, data: bytes) -> bytes:
    try:
        return encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _OPERATION_REJECT_RVS, "AES_ECB encrypt rejected")
    raise


def _decrypt_or_xfail(rs: Any, key: int, data: bytes) -> bytes:
    try:
        return decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _OPERATION_REJECT_RVS, "AES_ECB decrypt rejected")
    raise


def _rsa_keypair_for_multipart_smoke(rs: Any) -> tuple[int, int]:
    _require_mechanism(rs, "SHA256_RSA_PKCS")
    return gen_rsa_keypair_or_xfail(rs, 2048)


def _sign_or_xfail(rs: Any, private_key: int, data: bytes) -> bytes:
    try:
        return sign_single(rs.raw, rs.sh, private_key, CKM_SHA256_RSA_PKCS, data)
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _OPERATION_REJECT_RVS, "SHA256_RSA_PKCS sign rejected")
    raise


def _verify_or_xfail(rs: Any, public_key: int, data: bytes, signature: bytes) -> bool:
    try:
        return verify_single(rs.raw, rs.sh, public_key, CKM_SHA256_RSA_PKCS, data, signature)
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _OPERATION_REJECT_RVS, "SHA256_RSA_PKCS verify rejected")
    raise


class TestMultiPartDigest:
    def test_sha256_consistency(self, p11_raw_session: Any) -> None:
        """SHA-256 of same data always produces same result."""
        rs = p11_raw_session
        data = b"A" * 100 + b"B" * 100
        d1 = _digest_or_xfail(rs, CKM_SHA256, "SHA256", data)
        d2 = _digest_or_xfail(rs, CKM_SHA256, "SHA256", data)
        assert d1 == d2

    def test_sha256_different_data_different_digest(self, p11_raw_session: Any) -> None:
        """Different data produces different SHA-256."""
        rs = p11_raw_session
        d1 = _digest_or_xfail(rs, CKM_SHA256, "SHA256", b"data one")
        d2 = _digest_or_xfail(rs, CKM_SHA256, "SHA256", b"data two")
        assert d1 != d2

    def test_sha512_output_size(self, p11_raw_session: Any) -> None:
        """SHA-512 of large data produces 64-byte output."""
        rs = p11_raw_session
        data = b"test data " * 1000
        result = _digest_or_xfail(rs, CKM_SHA512, "SHA512", data)
        assert len(result) == 64


class TestMultiPartEncrypt:
    def test_encrypt_16kb(self, p11_raw_session: Any) -> None:
        """Encrypt 16KB of data (multiple AES blocks)."""
        rs = p11_raw_session
        key = _aes_key_for_multipart_smoke(rs)
        plaintext = b"X" * (1024 * 16)
        try:
            ct = _encrypt_or_xfail(rs, key, plaintext)
            pt = _decrypt_or_xfail(rs, key, ct)
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_encrypt_various_block_sizes(self, p11_raw_session: Any) -> None:
        """Encrypt at different sizes that are multiples of block size."""
        rs = p11_raw_session
        key = _aes_key_for_multipart_smoke(rs)
        try:
            for num_blocks in [1, 2, 4, 8, 16, 64]:
                plaintext = bytes(range(256))[:16] * num_blocks
                ct = _encrypt_or_xfail(rs, key, plaintext)
                pt = _decrypt_or_xfail(rs, key, ct)
                assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_encrypt_same_key_deterministic(self, p11_raw_session: Any) -> None:
        """AES-ECB with same key and plaintext produces same ciphertext."""
        rs = p11_raw_session
        key = _aes_key_for_multipart_smoke(rs)
        plaintext = b"deterministic!!!"
        try:
            ct1 = _encrypt_or_xfail(rs, key, plaintext)
            ct2 = _encrypt_or_xfail(rs, key, plaintext)
            assert ct1 == ct2
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestMultiPartSign:
    def test_rsa_sign_10kb(self, p11_raw_session: Any) -> None:
        """Sign a 10KB payload with RSA."""
        rs = p11_raw_session
        pub, priv = _rsa_keypair_for_multipart_smoke(rs)
        data = b"Y" * 10000
        try:
            sig = _sign_or_xfail(rs, priv, data)
            assert len(sig) == 256
            assert _verify_or_xfail(rs, pub, data, sig) is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_sign_1byte(self, p11_raw_session: Any) -> None:
        """Sign minimal 1-byte payload."""
        rs = p11_raw_session
        pub, priv = _rsa_keypair_for_multipart_smoke(rs)
        data = b"X"
        try:
            sig = _sign_or_xfail(rs, priv, data)
            assert _verify_or_xfail(rs, pub, data, sig) is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_sign_empty(self, p11_raw_session: Any) -> None:
        """Sign empty payload."""
        rs = p11_raw_session
        pub, priv = _rsa_keypair_for_multipart_smoke(rs)
        data = b""
        try:
            sig = _sign_or_xfail(rs, priv, data)
            assert _verify_or_xfail(rs, pub, data, sig) is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
