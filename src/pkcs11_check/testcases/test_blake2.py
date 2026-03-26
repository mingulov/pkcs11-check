"""BLAKE2B digest tests - BLAKE2B-160/256/384/512.

Tests PKCS#11 v3.0 BLAKE2B digest mechanisms (unkeyed variant).
Cross-verifies against Python hashlib.blake2b with matching digest_size.

PKCS#11 reference: v3.0 Sec.2.42 (BLAKE2b Message Digesting).
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from pkcs11_check.raw.recipes import digest_single
from pkcs11_check.raw.types_std import (
    CKM_BLAKE2B_160,
    CKM_BLAKE2B_256,
    CKM_BLAKE2B_384,
    CKM_BLAKE2B_512,
)

pytestmark = pytest.mark.full

_BLAKE2_MECHS = {
    "BLAKE2B_160": (CKM_BLAKE2B_160, 20),
    "BLAKE2B_256": (CKM_BLAKE2B_256, 32),
    "BLAKE2B_384": (CKM_BLAKE2B_384, 48),
    "BLAKE2B_512": (CKM_BLAKE2B_512, 64),
}


class TestBlake2bDigestLength:
    """Verify correct output lengths for all BLAKE2B digest mechanisms."""

    @pytest.mark.parametrize(
        "mech_name_str,mechanism,expected_len",
        [
            ("BLAKE2B_160", CKM_BLAKE2B_160, 20),
            ("BLAKE2B_256", CKM_BLAKE2B_256, 32),
            ("BLAKE2B_384", CKM_BLAKE2B_384, 48),
            ("BLAKE2B_512", CKM_BLAKE2B_512, 64),
        ],
        ids=["BLAKE2B-160", "BLAKE2B-256", "BLAKE2B-384", "BLAKE2B-512"],
    )
    def test_digest_length(
        self,
        p11_raw_session: Any,
        mech_name_str: str,
        mechanism: Any,
        expected_len: int,
    ) -> None:
        """Each BLAKE2B mechanism produces the correct output length."""
        rs = p11_raw_session
        if not rs.has_mechanism(mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")
        digest = digest_single(rs.raw, rs.sh, mechanism, b"test data")
        assert len(digest) == expected_len


class TestBlake2bCrossVerify:
    """Cross-verify PKCS#11 BLAKE2B digests against Python hashlib.

    PKCS#11 BLAKE2B mechanisms use the unkeyed variant - no key material.
    hashlib.blake2b(data, digest_size=N) with no key matches this exactly.
    """

    @pytest.mark.parametrize(
        "mech_name_str,mechanism,digest_size",
        [
            ("BLAKE2B_160", CKM_BLAKE2B_160, 20),
            ("BLAKE2B_256", CKM_BLAKE2B_256, 32),
            ("BLAKE2B_384", CKM_BLAKE2B_384, 48),
            ("BLAKE2B_512", CKM_BLAKE2B_512, 64),
        ],
        ids=["BLAKE2B-160", "BLAKE2B-256", "BLAKE2B-384", "BLAKE2B-512"],
    )
    def test_cross_verify(
        self,
        p11_raw_session: Any,
        mech_name_str: str,
        mechanism: Any,
        digest_size: int,
    ) -> None:
        """PKCS#11 BLAKE2B digest matches hashlib for each output size."""
        rs = p11_raw_session
        if not rs.has_mechanism(mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")
        data = b"BLAKE2B cross-verification test data"
        p11_digest = digest_single(rs.raw, rs.sh, mechanism, data)
        py_digest = hashlib.blake2b(data, digest_size=digest_size).digest()
        assert p11_digest == py_digest

    @pytest.mark.parametrize(
        "mech_name_str,mechanism,digest_size",
        [
            ("BLAKE2B_256", CKM_BLAKE2B_256, 32),
            ("BLAKE2B_512", CKM_BLAKE2B_512, 64),
        ],
        ids=["BLAKE2B-256", "BLAKE2B-512"],
    )
    def test_cross_verify_binary_data(
        self,
        p11_raw_session: Any,
        mech_name_str: str,
        mechanism: Any,
        digest_size: int,
    ) -> None:
        """Digest of all 256 byte values matches hashlib."""
        rs = p11_raw_session
        if not rs.has_mechanism(mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")
        data = bytes(range(256))
        p11_digest = digest_single(rs.raw, rs.sh, mechanism, data)
        py_digest = hashlib.blake2b(data, digest_size=digest_size).digest()
        assert p11_digest == py_digest


class TestBlake2bProperties:
    """Test fundamental hash function properties using BLAKE2B-256 as representative."""

    def test_deterministic(self, p11_raw_session: Any) -> None:
        """Same input produces the same BLAKE2B-256 digest."""
        rs = p11_raw_session
        if not rs.has_mechanism("BLAKE2B_256"):
            pytest.skip("CKM_BLAKE2B_256 not supported")
        data = b"deterministic test"
        d1 = digest_single(rs.raw, rs.sh, CKM_BLAKE2B_256, data)
        d2 = digest_single(rs.raw, rs.sh, CKM_BLAKE2B_256, data)
        assert d1 == d2

    def test_different_input_different_digest(self, p11_raw_session: Any) -> None:
        """Different inputs produce different BLAKE2B-256 digests."""
        rs = p11_raw_session
        if not rs.has_mechanism("BLAKE2B_256"):
            pytest.skip("CKM_BLAKE2B_256 not supported")
        d1 = digest_single(rs.raw, rs.sh, CKM_BLAKE2B_256, b"input one")
        d2 = digest_single(rs.raw, rs.sh, CKM_BLAKE2B_256, b"input two")
        assert d1 != d2

    def test_empty_data(self, p11_raw_session: Any) -> None:
        """BLAKE2B-256 digest of empty data matches hashlib."""
        rs = p11_raw_session
        if not rs.has_mechanism("BLAKE2B_256"):
            pytest.skip("CKM_BLAKE2B_256 not supported")
        digest = digest_single(rs.raw, rs.sh, CKM_BLAKE2B_256, b"")
        expected = hashlib.blake2b(b"", digest_size=32).digest()
        assert digest == expected

    def test_empty_data_blake2b_512(self, p11_raw_session: Any) -> None:
        """BLAKE2B-512 digest of empty data matches hashlib."""
        rs = p11_raw_session
        if not rs.has_mechanism("BLAKE2B_512"):
            pytest.skip("CKM_BLAKE2B_512 not supported")
        digest = digest_single(rs.raw, rs.sh, CKM_BLAKE2B_512, b"")
        expected = hashlib.blake2b(b"", digest_size=64).digest()
        assert digest == expected

    def test_large_data(self, p11_raw_session: Any) -> None:
        """BLAKE2B-256 digest of 1 MiB data matches hashlib."""
        rs = p11_raw_session
        if not rs.has_mechanism("BLAKE2B_256"):
            pytest.skip("CKM_BLAKE2B_256 not supported")
        data = b"\xab" * (1024 * 1024)
        p11_digest = digest_single(rs.raw, rs.sh, CKM_BLAKE2B_256, data)
        expected = hashlib.blake2b(data, digest_size=32).digest()
        assert p11_digest == expected
