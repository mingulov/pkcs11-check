"""Mechanism-driven digest tests.

Parametrized by mech_digest_entry -- tests every digest mechanism advertised by
the module that also has a registry config.

Tests:
- test_known_empty: digest of empty input matches Python hashlib (for SHA family)
  or just verifies a non-empty output for other algorithms
- test_length: output length matches expected size for the algorithm
- test_deterministic: same input produces identical digest in two calls

XOF mechanisms (SHAKE-128/256) that require C_DigestXof* are skipped here --
they use a different API not covered by digest_single.
Mechanisms with param_required=True and no factory (SHA-512/t) are skipped.
"""

from __future__ import annotations

import hashlib

import pytest

from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.recipes import digest_single
from pkcs11_check.raw.types_std import (
    CKM,
    CKM_BLAKE2B_160,
    CKM_BLAKE2B_256,
    CKM_BLAKE2B_384,
    CKM_BLAKE2B_512,
    CKM_RIPEMD128,
    CKM_RIPEMD160,
    CKM_SHA3_224,
    CKM_SHA3_256,
    CKM_SHA3_384,
    CKM_SHA3_512,
    CKM_SHA224,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512,
    CKM_SHA512_224,
    CKM_SHA512_256,
    CKM_SHA_1,
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases.conftest import xfail_if_known_ckr
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import MechConfig

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.digest]

# Known CKM IDs for SHAKE (XOF -- different API, not tested here)
_SHAKE_128_ID = 0x00000418  # TODO: not in vendored v3.2 header; future spec
_SHAKE_256_ID = 0x00000419  # TODO: not in vendored v3.2 header; future spec

# Map CKM mech_id -> expected output length in bytes (None = unknown/variable)
_KNOWN_OUTPUT_LENGTHS: dict[int, int] = {
    int(CKM_SHA_1): 20,
    int(CKM_SHA224): 28,
    int(CKM_SHA256): 32,
    int(CKM_SHA384): 48,
    int(CKM_SHA512): 64,
    int(CKM_SHA512_224): 28,
    int(CKM_SHA512_256): 32,
    int(CKM_SHA3_224): 28,
    int(CKM_SHA3_256): 32,
    int(CKM_SHA3_384): 48,
    int(CKM_SHA3_512): 64,
    int(CKM_RIPEMD128): 16,
    int(CKM_RIPEMD160): 20,
    int(CKM_BLAKE2B_160): 20,
    int(CKM_BLAKE2B_256): 32,
    int(CKM_BLAKE2B_384): 48,
    int(CKM_BLAKE2B_512): 64,
}

# Map CKM mech_id -> hashlib algorithm name (for known-answer verification via Python)
_HASHLIB_BY_MECH: dict[int, str] = {
    int(CKM_SHA_1): "sha1",
    int(CKM_SHA224): "sha224",
    int(CKM_SHA256): "sha256",
    int(CKM_SHA384): "sha384",
    int(CKM_SHA512): "sha512",
    int(CKM_SHA3_224): "sha3_224",
    int(CKM_SHA3_256): "sha3_256",
    int(CKM_SHA3_384): "sha3_384",
    int(CKM_SHA3_512): "sha3_512",
}

_DIGEST_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)


def _digest_or_xfail(rs: RawSession, entry: MechEntry, data: bytes) -> bytes:
    try:
        return digest_single(rs.raw, rs.sh, CKM(entry.mech_id), data)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            _DIGEST_RUNTIME_REJECT_RVS,
            f"{entry.mech_name} advertised but digest is not operational",
        )
    raise


def _check_not_xof(entry: MechEntry) -> None:
    """Skip XOF mechanisms that require C_DigestXof* (SHAKE-128/256)."""
    if entry.mech_id in (_SHAKE_128_ID, _SHAKE_256_ID):
        pytest.skip(
            f"{entry.mech_name}: XOF mechanism requires C_DigestXof* (v3.1), not tested here"
        )


def _check_not_parameterised(entry: MechEntry, config: MechConfig) -> None:
    """Skip mechanisms that require parameters we can't build generically (e.g. SHA-512/t)."""
    if config.param_required and config.param_recipe.style == "none":
        pytest.skip(
            f"{entry.mech_name}: param_required=True but recipe style 'none' -- "
            "cannot create test params generically"
        )


class TestMechDigest:
    """Digest tests for every advertised digest mechanism with a registry config."""

    def test_known_empty(
        self, p11_module_session: RawSession, mech_digest_entry: MechEntry
    ) -> None:
        """Digest of empty input: verify against hashlib for known algorithms,
        or just check output is non-empty for others."""
        rs = p11_module_session
        entry = mech_digest_entry
        config = entry.config
        if config is None:
            pytest.skip(f"{entry.mech_name}: no registry config")

        _check_not_xof(entry)
        _check_not_parameterised(entry, config)

        digest = _digest_or_xfail(rs, entry, b"")

        hashlib_name = _HASHLIB_BY_MECH.get(entry.mech_id)
        if hashlib_name is not None:
            try:
                expected = hashlib.new(hashlib_name, b"").digest()
                assert digest == expected, (
                    f"{entry.mech_name}: empty-input digest mismatch. "
                    f"Got {digest.hex()!r}, expected {expected.hex()!r}"
                )
            except ValueError:
                # hashlib doesn't know this algorithm -- just check non-empty
                assert len(digest) > 0, f"{entry.mech_name}: empty digest output"
        else:
            assert len(digest) > 0, f"{entry.mech_name}: empty digest output is zero bytes"

    def test_length(self, p11_module_session: RawSession, mech_digest_entry: MechEntry) -> None:
        """Output length matches expected for the algorithm."""
        rs = p11_module_session
        entry = mech_digest_entry
        config = entry.config
        if config is None:
            pytest.skip(f"{entry.mech_name}: no registry config")

        _check_not_xof(entry)
        _check_not_parameterised(entry, config)

        data = b"length check input data for pkcs11"
        digest = _digest_or_xfail(rs, entry, data)

        expected_len = _KNOWN_OUTPUT_LENGTHS.get(entry.mech_id)
        if expected_len is not None:
            assert len(digest) == expected_len, (
                f"{entry.mech_name}: output length {len(digest)} != expected {expected_len}"
            )
        else:
            # Unknown algorithm -- just verify output is non-empty
            assert len(digest) > 0, f"{entry.mech_name}: digest output is zero bytes"

    def test_deterministic(
        self, p11_module_session: RawSession, mech_digest_entry: MechEntry
    ) -> None:
        """Same input produces same digest in two consecutive calls."""
        rs = p11_module_session
        entry = mech_digest_entry
        config = entry.config
        if config is None:
            pytest.skip(f"{entry.mech_name}: no registry config")

        _check_not_xof(entry)
        _check_not_parameterised(entry, config)

        data = b"deterministic digest test input"
        d1 = _digest_or_xfail(rs, entry, data)
        d2 = _digest_or_xfail(rs, entry, data)
        assert d1 == d2, (
            f"{entry.mech_name}: two digests of same input differ: {d1.hex()!r} vs {d2.hex()!r}"
        )


class TestMechDigestKAT:
    """Known-answer digest tests from pre-generated vectors."""

    def test_kat_vector(self, p11_module_session: RawSession, mech_digest_entry: MechEntry) -> None:
        """Digest known inputs -- verify output matches pre-computed vectors."""
        rs = p11_module_session
        entry = mech_digest_entry
        config = entry.config
        if config is None or not config.vector_file:
            pytest.skip("No KAT vectors for this mechanism")

        from pkcs11_check.testcases.mechanism_vectors import load_positive_vectors

        vectors = load_positive_vectors(config.vector_file)
        if not vectors:
            pytest.skip(f"No positive vectors in {config.vector_file}")

        _check_not_xof(entry)
        _check_not_parameterised(entry, config)

        for vec in vectors:
            # SHA vector files may contain multiple mechanisms; filter to this one
            vec_mech = vec.get("mechanism_name")
            if vec_mech and vec_mech != f"CKM_{entry.mech_name}" and vec_mech != entry.mech_name:
                continue
            digest = _digest_or_xfail(rs, entry, bytes.fromhex(vec["input_hex"]))
            expected = bytes.fromhex(vec["digest_hex"])
            assert digest == expected, (
                f"KAT digest mismatch for {vec.get('id', '?')}: "
                f"got {digest.hex()!r}, expected {expected.hex()!r}"
            )
