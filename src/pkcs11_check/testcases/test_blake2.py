"""BLAKE2B digest tests - BLAKE2B-160/256/384/512.

Tests PKCS#11 v3.0 BLAKE2B digest mechanisms (unkeyed variant).
Cross-verifies against Python hashlib.blake2b with matching digest_size.

PKCS#11 reference: v3.0 Sec.2.42 (BLAKE2b Message Digesting).
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from pkcs11 import Mechanism

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.full


class TestBlake2bDigestLength:
    """Verify correct output lengths for all BLAKE2B digest mechanisms."""

    @pytest.mark.parametrize(
        "mechanism,expected_len",
        [
            (Mechanism.BLAKE2B_160, 20),
            (Mechanism.BLAKE2B_256, 32),
            (Mechanism.BLAKE2B_384, 48),
            (Mechanism.BLAKE2B_512, 64),
        ],
        ids=["BLAKE2B-160", "BLAKE2B-256", "BLAKE2B-384", "BLAKE2B-512"],
    )
    def test_digest_length(
        self, p11_session: Any, p11_module: Any, mechanism: Mechanism, expected_len: int
    ) -> None:
        """Each BLAKE2B mechanism produces the correct output length."""
        mech_name = mechanism.name
        if not has_mechanism(p11_module, mech_name):
            pytest.skip(f"CKM_{mech_name} not supported")
        digest = p11_session.digest(b"test data", mechanism=mechanism)
        assert len(digest) == expected_len


class TestBlake2bCrossVerify:
    """Cross-verify PKCS#11 BLAKE2B digests against Python hashlib.

    PKCS#11 BLAKE2B mechanisms use the unkeyed variant - no key material.
    hashlib.blake2b(data, digest_size=N) with no key matches this exactly.
    """

    @pytest.mark.parametrize(
        "mechanism,digest_size",
        [
            (Mechanism.BLAKE2B_160, 20),
            (Mechanism.BLAKE2B_256, 32),
            (Mechanism.BLAKE2B_384, 48),
            (Mechanism.BLAKE2B_512, 64),
        ],
        ids=["BLAKE2B-160", "BLAKE2B-256", "BLAKE2B-384", "BLAKE2B-512"],
    )
    def test_cross_verify(
        self, p11_session: Any, p11_module: Any, mechanism: Mechanism, digest_size: int
    ) -> None:
        """PKCS#11 BLAKE2B digest matches hashlib for each output size."""
        mech_name = mechanism.name
        if not has_mechanism(p11_module, mech_name):
            pytest.skip(f"CKM_{mech_name} not supported")
        data = b"BLAKE2B cross-verification test data"
        p11_digest = p11_session.digest(data, mechanism=mechanism)
        py_digest = hashlib.blake2b(data, digest_size=digest_size).digest()
        assert p11_digest == py_digest

    @pytest.mark.parametrize(
        "mechanism,digest_size",
        [
            (Mechanism.BLAKE2B_256, 32),
            (Mechanism.BLAKE2B_512, 64),
        ],
        ids=["BLAKE2B-256", "BLAKE2B-512"],
    )
    def test_cross_verify_binary_data(
        self, p11_session: Any, p11_module: Any, mechanism: Mechanism, digest_size: int
    ) -> None:
        """Digest of all 256 byte values matches hashlib."""
        mech_name = mechanism.name
        if not has_mechanism(p11_module, mech_name):
            pytest.skip(f"CKM_{mech_name} not supported")
        data = bytes(range(256))
        p11_digest = p11_session.digest(data, mechanism=mechanism)
        py_digest = hashlib.blake2b(data, digest_size=digest_size).digest()
        assert p11_digest == py_digest


class TestBlake2bProperties:
    """Test fundamental hash function properties using BLAKE2B-256 as representative."""

    def test_deterministic(self, p11_session: Any, p11_module: Any) -> None:
        """Same input produces the same BLAKE2B-256 digest."""
        if not has_mechanism(p11_module, "BLAKE2B_256"):
            pytest.skip("CKM_BLAKE2B_256 not supported")
        data = b"deterministic test"
        d1 = p11_session.digest(data, mechanism=Mechanism.BLAKE2B_256)
        d2 = p11_session.digest(data, mechanism=Mechanism.BLAKE2B_256)
        assert d1 == d2

    def test_different_input_different_digest(self, p11_session: Any, p11_module: Any) -> None:
        """Different inputs produce different BLAKE2B-256 digests."""
        if not has_mechanism(p11_module, "BLAKE2B_256"):
            pytest.skip("CKM_BLAKE2B_256 not supported")
        d1 = p11_session.digest(b"input one", mechanism=Mechanism.BLAKE2B_256)
        d2 = p11_session.digest(b"input two", mechanism=Mechanism.BLAKE2B_256)
        assert d1 != d2

    def test_empty_data(self, p11_session: Any, p11_module: Any) -> None:
        """BLAKE2B-256 digest of empty data matches hashlib."""
        if not has_mechanism(p11_module, "BLAKE2B_256"):
            pytest.skip("CKM_BLAKE2B_256 not supported")
        digest = p11_session.digest(b"", mechanism=Mechanism.BLAKE2B_256)
        expected = hashlib.blake2b(b"", digest_size=32).digest()
        assert digest == expected

    def test_empty_data_blake2b_512(self, p11_session: Any, p11_module: Any) -> None:
        """BLAKE2B-512 digest of empty data matches hashlib."""
        if not has_mechanism(p11_module, "BLAKE2B_512"):
            pytest.skip("CKM_BLAKE2B_512 not supported")
        digest = p11_session.digest(b"", mechanism=Mechanism.BLAKE2B_512)
        expected = hashlib.blake2b(b"", digest_size=64).digest()
        assert digest == expected

    def test_large_data(self, p11_session: Any, p11_module: Any) -> None:
        """BLAKE2B-256 digest of 1 MiB data matches hashlib."""
        if not has_mechanism(p11_module, "BLAKE2B_256"):
            pytest.skip("CKM_BLAKE2B_256 not supported")
        data = b"\xab" * (1024 * 1024)
        p11_digest = p11_session.digest(data, mechanism=Mechanism.BLAKE2B_256)
        expected = hashlib.blake2b(data, digest_size=32).digest()
        assert p11_digest == expected
