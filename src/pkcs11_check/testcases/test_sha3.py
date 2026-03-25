"""SHA-3 digest tests with cross-verification against hashlib.

SHA3-224/256/384/512 from FIPS 202. Auto-skips if module doesn't support SHA-3.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from pkcs11_check.raw.recipes import digest_single
from pkcs11_check.raw.types_std import (
    CKM_SHA3_224,
    CKM_SHA3_256,
    CKM_SHA3_384,
    CKM_SHA3_512,
)

pytestmark = pytest.mark.crossverify

# NIST FIPS 202 KAT: SHA-3 of "abc" (0x616263)
_SHA3_KATS = [
    ("SHA3_256", CKM_SHA3_256, hashlib.sha3_256, 32),
    ("SHA3_384", CKM_SHA3_384, hashlib.sha3_384, 48),
    ("SHA3_512", CKM_SHA3_512, hashlib.sha3_512, 64),
    ("SHA3_224", CKM_SHA3_224, hashlib.sha3_224, 28),
]


class TestSHA3Digest:
    """SHA-3 digest tests - cross-verified against hashlib."""

    @pytest.mark.parametrize(
        "name,mechanism,hash_fn,digest_len",
        _SHA3_KATS,
        ids=[k[0] for k in _SHA3_KATS],
    )
    def test_sha3_abc(
        self,
        p11_raw_session: Any,
        name: str,
        mechanism: Any,
        hash_fn: Any,
        digest_len: int,
    ) -> None:
        """SHA-3 of 'abc' - PKCS#11 vs hashlib."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA3_256"):
            pytest.skip("SHA-3 not supported by this module")

        data = b"abc"
        p11_digest = digest_single(rs.raw, rs.sh, mechanism, data)
        py_digest = hash_fn(data).digest()

        assert len(p11_digest) == digest_len
        assert p11_digest == py_digest

    @pytest.mark.parametrize(
        "name,mechanism,hash_fn,digest_len",
        _SHA3_KATS,
        ids=[k[0] for k in _SHA3_KATS],
    )
    def test_sha3_empty(
        self,
        p11_raw_session: Any,
        name: str,
        mechanism: Any,
        hash_fn: Any,
        digest_len: int,
    ) -> None:
        """SHA-3 of empty data."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA3_256"):
            pytest.skip("SHA-3 not supported by this module")

        p11_digest = digest_single(rs.raw, rs.sh, mechanism, b"")
        py_digest = hash_fn(b"").digest()

        assert len(p11_digest) == digest_len
        assert p11_digest == py_digest

    @pytest.mark.parametrize(
        "name,mechanism,hash_fn,digest_len",
        _SHA3_KATS,
        ids=[k[0] for k in _SHA3_KATS],
    )
    def test_sha3_large(
        self,
        p11_raw_session: Any,
        name: str,
        mechanism: Any,
        hash_fn: Any,
        digest_len: int,
    ) -> None:
        """SHA-3 of 10KB data."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA3_256"):
            pytest.skip("SHA-3 not supported by this module")

        data = b"X" * 10240
        p11_digest = digest_single(rs.raw, rs.sh, mechanism, data)
        py_digest = hash_fn(data).digest()

        assert p11_digest == py_digest
