"""Tests for PKCS#11 digest and hash operations.

Covers all SHA-family digests, known-answer vectors, length validation,
determinism, collision resistance properties, and large-data digests.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from pkcs11 import Mechanism

pytestmark = pytest.mark.full


class TestDigestLengths:
    """Verify correct output lengths for all hash mechanisms."""

    @pytest.mark.parametrize(
        "mechanism,expected_len",
        [
            (Mechanism.SHA_1, 20),
            (Mechanism.SHA224, 28),
            (Mechanism.SHA256, 32),
            (Mechanism.SHA384, 48),
            (Mechanism.SHA512, 64),
        ],
        ids=["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"],
    )
    def test_digest_length(self, p11_session: Any, mechanism: Mechanism, expected_len: int) -> None:
        """Each hash mechanism produces the correct output length."""
        digest = p11_session.digest(b"test data", mechanism=mechanism)
        assert len(digest) == expected_len


class TestDigestProperties:
    """Test fundamental hash function properties."""

    def test_sha256_deterministic(self, p11_session: Any) -> None:
        """Same input produces same SHA-256 digest."""
        data = b"deterministic test"
        d1 = p11_session.digest(data, mechanism=Mechanism.SHA256)
        d2 = p11_session.digest(data, mechanism=Mechanism.SHA256)
        assert d1 == d2

    def test_sha256_different_input_different_digest(self, p11_session: Any) -> None:
        """Different inputs produce different digests."""
        d1 = p11_session.digest(b"input one", mechanism=Mechanism.SHA256)
        d2 = p11_session.digest(b"input two", mechanism=Mechanism.SHA256)
        assert d1 != d2

    def test_sha256_empty_data(self, p11_session: Any) -> None:
        """Digest of empty data produces known SHA-256 hash of empty string."""
        digest = p11_session.digest(b"", mechanism=Mechanism.SHA256)
        assert digest.hex() == hashlib.sha256(b"").hexdigest()

    def test_sha1_empty_data(self, p11_session: Any) -> None:
        """SHA-1 of empty string matches known value."""
        digest = p11_session.digest(b"", mechanism=Mechanism.SHA_1)
        assert digest.hex() == hashlib.sha1(b"").hexdigest()

    def test_digest_large_data(self, p11_session: Any) -> None:
        """Digest of 1 MiB data succeeds and matches hashlib."""
        data = b"\xab" * (1024 * 1024)
        p11_digest = p11_session.digest(data, mechanism=Mechanism.SHA256)
        expected = hashlib.sha256(data).digest()
        assert p11_digest == expected


class TestDigestCrossVerify:
    """Cross-verify PKCS#11 digests against Python hashlib."""

    @pytest.mark.parametrize(
        "mechanism,hashlib_name",
        [
            (Mechanism.SHA_1, "sha1"),
            (Mechanism.SHA224, "sha224"),
            (Mechanism.SHA256, "sha256"),
            (Mechanism.SHA384, "sha384"),
            (Mechanism.SHA512, "sha512"),
        ],
        ids=["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"],
    )
    def test_cross_verify(self, p11_session: Any, mechanism: Mechanism, hashlib_name: str) -> None:
        """PKCS#11 digest matches hashlib for each algorithm."""
        data = b"cross-verification test data for digest operations"
        p11_digest = p11_session.digest(data, mechanism=mechanism)
        expected = hashlib.new(hashlib_name, data).digest()
        assert p11_digest == expected

    @pytest.mark.parametrize(
        "mechanism,hashlib_name",
        [
            (Mechanism.SHA256, "sha256"),
            (Mechanism.SHA512, "sha512"),
        ],
        ids=["SHA-256", "SHA-512"],
    )
    def test_cross_verify_binary_data(
        self, p11_session: Any, mechanism: Mechanism, hashlib_name: str
    ) -> None:
        """Digest of binary data (all byte values) matches hashlib."""
        data = bytes(range(256))
        p11_digest = p11_session.digest(data, mechanism=mechanism)
        expected = hashlib.new(hashlib_name, data).digest()
        assert p11_digest == expected
