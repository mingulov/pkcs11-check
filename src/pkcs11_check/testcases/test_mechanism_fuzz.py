"""Mechanism parameter fuzzing tests.

Passes random/invalid bytes as mechanism_param to various operations.
The module must not crash (segfault) — it should return an error code.
These tests verify robustness against malformed parameters.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.exceptions import PKCS11Error

pytestmark = pytest.mark.security


class TestAESParameterFuzz:
    """Fuzz AES mechanism parameters."""

    @pytest.mark.parametrize(
        "bad_param",
        [
            b"",
            b"\x00",
            b"\xff" * 8,
            b"\xff" * 15,  # Wrong IV length (not 16)
            b"\xff" * 17,  # Wrong IV length
            b"\xff" * 256,  # Way too long
            os.urandom(7),  # Random short
        ],
        ids=["empty", "one-byte", "8-bytes", "15-bytes", "17-bytes", "256-bytes", "random-7"],
    )
    def test_aes_cbc_bad_iv(self, p11_session: Any, bad_param: bytes) -> None:
        """AES-CBC with wrong-sized IV must fail, not crash."""
        key = p11_session.generate_key(KeyType.AES, 256)
        data = b"\x00" * 16

        with pytest.raises((PKCS11Error, ValueError)):
            key.encrypt(data, mechanism=Mechanism.AES_CBC, mechanism_param=bad_param)

    def test_aes_ecb_with_param_should_fail_or_ignore(self, p11_session: Any) -> None:
        """AES-ECB doesn't take a parameter — passing one should fail or be ignored."""
        key = p11_session.generate_key(KeyType.AES, 256)
        data = b"\x00" * 16
        try:
            ct = key.encrypt(data, mechanism=Mechanism.AES_ECB, mechanism_param=b"\xff" * 16)
            # Some modules silently ignore extra params
            assert len(ct) == 16
        except PKCS11Error:
            pass  # Correct behavior


class TestDigestParameterFuzz:
    """Fuzz digest mechanism parameters."""

    @pytest.mark.parametrize(
        "bad_param",
        [b"", b"\x00" * 32, b"\xff" * 256, os.urandom(64)],
        ids=["empty", "32-zeros", "256-ff", "random-64"],
    )
    def test_sha256_with_param(self, p11_session: Any, bad_param: bytes) -> None:
        """SHA-256 doesn't take parameters — extra params should fail or be ignored."""
        data = b"test data"
        try:
            digest = p11_session.digest(data, mechanism=Mechanism.SHA256, mechanism_param=bad_param)
            assert len(digest) == 32  # If it works, still correct output
        except (PKCS11Error, TypeError, ValueError):
            pass  # Correct to reject


class TestSignParameterFuzz:
    """Fuzz signature mechanism parameters."""

    def test_rsa_pkcs_sign_with_random_param(self, p11_session: Any) -> None:
        """RSA-PKCS sign with random mechanism_param should fail or be ignored."""
        _pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"fuzz test data"

        try:
            sig = priv.sign(
                data,
                mechanism=Mechanism.SHA256_RSA_PKCS,
                mechanism_param=os.urandom(32),
            )
            # If it succeeds, at least verify sig is the right length
            assert len(sig) == 256
        except (PKCS11Error, TypeError, ValueError):
            pass  # Correct to reject


class TestKeyGenParameterFuzz:
    """Fuzz key generation parameters."""

    @pytest.mark.parametrize(
        "bad_param",
        [b"\x00", b"\xff" * 32, os.urandom(128)],
        ids=["one-zero", "32-ff", "random-128"],
    )
    def test_aes_keygen_with_random_param(self, p11_session: Any, bad_param: bytes) -> None:
        """AES key generation with random mechanism_param should fail or be ignored."""
        try:
            key = p11_session.generate_key(
                KeyType.AES,
                256,
                mechanism_param=bad_param,
            )
            # If it works, key should still be valid
            assert key[Attribute.KEY_TYPE] == KeyType.AES
        except (PKCS11Error, TypeError, ValueError):
            pass  # Correct to reject


class TestEncryptDataFuzz:
    """Fuzz data inputs to encryption."""

    def test_encrypt_empty_data(self, p11_session: Any) -> None:
        """Encrypting empty data — module must handle gracefully."""
        key = p11_session.generate_key(KeyType.AES, 256)
        try:
            ct = key.encrypt(b"", mechanism=Mechanism.AES_ECB)
            assert ct == b""  # Some modules return empty for empty input
        except PKCS11Error:
            pass  # Also valid to reject

    def test_encrypt_non_block_aligned(self, p11_session: Any) -> None:
        """AES-ECB with non-block-aligned data must fail (no padding)."""
        key = p11_session.generate_key(KeyType.AES, 256)
        with pytest.raises(PKCS11Error):
            key.encrypt(b"\x00" * 15, mechanism=Mechanism.AES_ECB)  # 15, not 16
