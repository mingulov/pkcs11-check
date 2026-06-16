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
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
)
from pkcs11_check.testcases.conftest import assert_correct, xfail_if_known_ckr

# Clean codes meaning the advertised SHA-3 mechanism is not operational for
# standalone C_Digest -> xfail (advertised-but-not-operational). CKR_ARGUMENTS_BAD
# is excluded: an ARGUMENTS_BAD reject of an empty-message digest is a real
# PROVIDER_BUG (empty digest is well-defined) and must stay a hard fail, as must a
# wrong digest value (the assert_correct comparison).
_DIGEST_OP_REJECT_RVS = (
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
)


def _digest_or_xfail(rs: Any, mechanism: Any, data: bytes, label: str) -> bytes:
    """Produce a SHA-3 digest; xfail on a clean not-operational reject."""
    try:
        return digest_single(rs.raw, rs.sh, mechanism, data)
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _DIGEST_OP_REJECT_RVS, f"{label}: digest not operational")
        raise


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
        p11_digest = _digest_or_xfail(rs, mechanism, data, name)
        py_digest = hash_fn(data).digest()

        assert len(p11_digest) == digest_len
        assert_correct(
            actual=p11_digest,
            expected=py_digest,
            label=f"{name}:C_Digest KAT (abc)",
            operation="C_Digest",
            mechanism=name,
        )

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

        p11_digest = _digest_or_xfail(rs, mechanism, b"", name)
        py_digest = hash_fn(b"").digest()

        assert len(p11_digest) == digest_len
        assert_correct(
            actual=p11_digest,
            expected=py_digest,
            label=f"{name}:C_Digest KAT (empty)",
            operation="C_Digest",
            mechanism=name,
        )

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
        p11_digest = _digest_or_xfail(rs, mechanism, data, name)
        py_digest = hash_fn(data).digest()

        assert_correct(
            actual=p11_digest,
            expected=py_digest,
            label=f"{name}:C_Digest KAT (10KB)",
            operation="C_Digest",
            mechanism=name,
        )
