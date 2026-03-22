"""SHA-3 digest tests with cross-verification against hashlib.

SHA3-224/256/384/512 from FIPS 202. Auto-skips if module doesn't support SHA-3.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from pkcs11 import Mechanism

from pkcs11_check.testcases.conftest import mech_name

pytestmark = pytest.mark.crossverify

# NIST FIPS 202 KAT: SHA-3 of "abc" (0x616263)
_SHA3_KATS = [
    ("SHA3_256", Mechanism.SHA3_256, hashlib.sha3_256, 32),
    ("SHA3_384", Mechanism.SHA3_384, hashlib.sha3_384, 48),
    ("SHA3_512", Mechanism.SHA3_512, hashlib.sha3_512, 64),
    ("SHA3_224", Mechanism.SHA3_224, hashlib.sha3_224, 28),
]


def _has_sha3(p11_module: Any) -> bool:
    slot = p11_module.get_slots(token_present=True)[0]
    names = {mech_name(m) for m in slot.get_mechanisms()}
    return "SHA3_256" in names


class TestSHA3Digest:
    """SHA-3 digest tests - cross-verified against hashlib."""

    @pytest.mark.parametrize(
        "name,mechanism,hash_fn,digest_len",
        _SHA3_KATS,
        ids=[k[0] for k in _SHA3_KATS],
    )
    def test_sha3_abc(
        self,
        p11_session: Any,
        p11_module: Any,
        name: str,
        mechanism: Any,
        hash_fn: Any,
        digest_len: int,
    ) -> None:
        """SHA-3 of 'abc' - PKCS#11 vs hashlib."""
        if not _has_sha3(p11_module):
            pytest.skip("SHA-3 not supported by this module")

        data = b"abc"
        p11_digest = p11_session.digest(data, mechanism=mechanism)
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
        p11_session: Any,
        p11_module: Any,
        name: str,
        mechanism: Any,
        hash_fn: Any,
        digest_len: int,
    ) -> None:
        """SHA-3 of empty data."""
        if not _has_sha3(p11_module):
            pytest.skip("SHA-3 not supported by this module")

        p11_digest = p11_session.digest(b"", mechanism=mechanism)
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
        p11_session: Any,
        p11_module: Any,
        name: str,
        mechanism: Any,
        hash_fn: Any,
        digest_len: int,
    ) -> None:
        """SHA-3 of 10KB data."""
        if not _has_sha3(p11_module):
            pytest.skip("SHA-3 not supported by this module")

        data = b"X" * 10240
        p11_digest = p11_session.digest(data, mechanism=mechanism)
        py_digest = hash_fn(data).digest()

        assert p11_digest == py_digest
