"""Tests for PKCS#11 digest and hash operations."""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Mechanism

pytestmark = pytest.mark.full


class TestDigest:
    def test_sha256_digest(self, p11_session: Any) -> None:
        """SHA-256 digest produces 32-byte output."""
        digest = p11_session.digest(b"test data for hashing", mechanism=Mechanism.SHA256)
        assert len(digest) == 32

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

    def test_sha512_digest(self, p11_session: Any) -> None:
        """SHA-512 digest produces 64-byte output."""
        digest = p11_session.digest(b"test data", mechanism=Mechanism.SHA512)
        assert len(digest) == 64

    def test_sha1_digest(self, p11_session: Any) -> None:
        """SHA-1 digest produces 20-byte output."""
        digest = p11_session.digest(b"test data", mechanism=Mechanism.SHA_1)
        assert len(digest) == 20

    def test_sha256_empty_data(self, p11_session: Any) -> None:
        """Digest of empty data produces known SHA-256 hash."""
        digest = p11_session.digest(b"", mechanism=Mechanism.SHA256)
        assert len(digest) == 32
        assert digest.hex().startswith("e3b0c44298fc")

    def test_sha224_digest(self, p11_session: Any) -> None:
        """SHA-224 digest produces 28-byte output."""
        digest = p11_session.digest(b"test data", mechanism=Mechanism.SHA224)
        assert len(digest) == 28

    def test_sha384_digest(self, p11_session: Any) -> None:
        """SHA-384 digest produces 48-byte output."""
        digest = p11_session.digest(b"test data", mechanism=Mechanism.SHA384)
        assert len(digest) == 48
