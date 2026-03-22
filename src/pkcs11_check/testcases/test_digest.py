"""Tests for PKCS#11 digest and hash operations.

Covers all SHA-family digests, known-answer vectors, length validation,
determinism, collision resistance properties, and large-data digests.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.exceptions import FunctionNotSupported

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


class TestDigestKey:
    """Tests for C_DigestKey - digesting key material directly.

    Source: PKCS#11 v3.2 Sec.5.13.4 (C_DigestKey).

    C_DigestKey continues an ongoing digest operation by digesting the value of
    a secret key, as if that value had been passed to C_DigestUpdate.  The python-
    pkcs11 fork calls C_DigestKey internally when a Key object is passed to
    session.digest().
    """

    def test_digest_key_matches_hashlib(self, p11_session: Any) -> None:
        """DigestKey of extractable AES-128 key matches hashlib digest of key bytes."""
        key = p11_session.generate_key(
            KeyType.AES,
            128,
            template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True},
        )
        try:
            p11_digest = p11_session.digest(key, mechanism=Mechanism.SHA256)
        except FunctionNotSupported:
            pytest.skip("C_DigestKey not supported by this module")
        key_bytes = key[Attribute.VALUE]
        ref_digest = hashlib.sha256(key_bytes).digest()
        assert p11_digest == ref_digest

    def test_digest_key_with_data(self, p11_session: Any) -> None:
        """DigestKey mixed with data: SHA-256(data_prefix + key_bytes)."""
        key = p11_session.generate_key(
            KeyType.AES,
            128,
            template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True},
        )
        data_prefix = b"prefix-data-for-digest"
        try:
            p11_digest = p11_session.digest(iter([data_prefix, key]), mechanism=Mechanism.SHA256)
        except FunctionNotSupported:
            pytest.skip("C_DigestKey not supported by this module")
        key_bytes = key[Attribute.VALUE]
        ref_digest = hashlib.sha256(data_prefix + key_bytes).digest()
        assert p11_digest == ref_digest

    def test_digest_key_256bit(self, p11_session: Any) -> None:
        """DigestKey works with AES-256 key."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True},
        )
        try:
            p11_digest = p11_session.digest(key, mechanism=Mechanism.SHA256)
        except FunctionNotSupported:
            pytest.skip("C_DigestKey not supported by this module")
        ref_digest = hashlib.sha256(key[Attribute.VALUE]).digest()
        assert p11_digest == ref_digest
