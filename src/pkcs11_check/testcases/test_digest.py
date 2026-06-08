"""Tests for PKCS#11 digest and hash operations.

Covers all SHA-family digests, known-answer vectors, length validation,
determinism, collision resistance properties, and large-data digests.
"""

from __future__ import annotations

import ctypes
import hashlib
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.metadata_std import MECHANISM_NAMES
from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    digest_single,
    digest_single_with_key,
    gen_aes_key,
    import_secret_key,
    read_attributes,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKA_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_VALUE,
    CKK_AES,
    CKM_SHA224,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512,
    CKM_SHA_1,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_INDIGESTIBLE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    is_known_error,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.full

_DIGEST_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)

_DIGEST_KEY_PROTECTED_REJECT_RVS = (
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_INDIGESTIBLE,
)


def _mechanism_name(mechanism: Any) -> str:
    name = MECHANISM_NAMES.get(int(mechanism), f"0x{int(mechanism):x}")
    return name[4:] if name.startswith("CKM_") else name


def _require_digest_mechanism(rs: Any, mechanism: Any) -> str:
    name = _mechanism_name(mechanism)
    if not rs.has_mechanism(name):
        pytest.skip(f"{name} not supported")
    return name


def _digest_or_xfail(rs: Any, mechanism: Any, data: bytes) -> bytes:
    name = _require_digest_mechanism(rs, mechanism)
    try:
        return digest_single(rs.raw, rs.sh, mechanism, data)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            _DIGEST_RUNTIME_REJECT_RVS,
            f"{name} advertised but digest is not operational",
        )
    raise


def _gen_extractable_aes_key_or_xfail(rs: Any, bits: int) -> int:
    if not rs.has_mechanism("AES_KEY_GEN"):
        pytest.skip("AES_KEY_GEN not supported")
    try:
        return gen_aes_key(
            rs.raw,
            rs.sh,
            bits,
            attrs={CKA_SENSITIVE: False, CKA_EXTRACTABLE: True},
        )
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            AES_KEYGEN_RUNTIME_REJECT_RVS,
            f"AES_KEY_GEN advertised but AES-{bits} setup for C_DigestKey is not operational",
        )
    raise


def _digest_key_or_skip_or_xfail(rs: Any, key: int) -> bytes:
    _require_digest_mechanism(rs, CKM_SHA256)
    try:
        return digest_single_with_key(rs.raw, rs.sh, CKM_SHA256, key)
    except AssertionError as exc:
        if is_known_error(exc, (CKR_FUNCTION_NOT_SUPPORTED,)):
            pytest.skip("C_DigestKey not supported by this module")
        xfail_if_known_ckr(
            exc,
            _DIGEST_RUNTIME_REJECT_RVS,
            "SHA256 advertised but C_DigestKey is not operational",
        )
    raise


def _expect_digest_rv_or_xfail(rv: Any, context: str) -> None:
    try:
        expect_rv(rv, CKR_OK)
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _DIGEST_RUNTIME_REJECT_RVS, context)


class TestDigestLengths:
    """Verify correct output lengths for all hash mechanisms."""

    @pytest.mark.parametrize(
        "mechanism,expected_len",
        [
            (CKM_SHA_1, 20),
            (CKM_SHA224, 28),
            (CKM_SHA256, 32),
            (CKM_SHA384, 48),
            (CKM_SHA512, 64),
        ],
        ids=["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"],
    )
    def test_digest_length(self, p11_raw_session: Any, mechanism: Any, expected_len: int) -> None:
        """Each hash mechanism produces the correct output length."""
        rs = p11_raw_session
        digest = _digest_or_xfail(rs, mechanism, b"test data")
        assert len(digest) == expected_len


class TestDigestProperties:
    """Test fundamental hash function properties."""

    def test_sha256_deterministic(self, p11_raw_session: Any) -> None:
        """Same input produces same SHA-256 digest."""
        rs = p11_raw_session
        data = b"deterministic test"
        d1 = _digest_or_xfail(rs, CKM_SHA256, data)
        d2 = _digest_or_xfail(rs, CKM_SHA256, data)
        assert d1 == d2

    def test_sha256_different_input_different_digest(self, p11_raw_session: Any) -> None:
        """Different inputs produce different digests."""
        rs = p11_raw_session
        d1 = _digest_or_xfail(rs, CKM_SHA256, b"input one")
        d2 = _digest_or_xfail(rs, CKM_SHA256, b"input two")
        assert d1 != d2

    def test_sha256_empty_data(self, p11_raw_session: Any) -> None:
        """Digest of empty data produces known SHA-256 hash of empty string."""
        rs = p11_raw_session
        digest = _digest_or_xfail(rs, CKM_SHA256, b"")
        assert digest.hex() == hashlib.sha256(b"").hexdigest()

    def test_sha1_empty_data(self, p11_raw_session: Any) -> None:
        """SHA-1 of empty string matches known value."""
        rs = p11_raw_session
        digest = _digest_or_xfail(rs, CKM_SHA_1, b"")
        assert digest.hex() == hashlib.sha1(b"", usedforsecurity=False).hexdigest()

    def test_digest_large_data(self, p11_raw_session: Any) -> None:
        """Digest of 1 MiB data succeeds and matches hashlib."""
        rs = p11_raw_session
        data = b"\xab" * (1024 * 1024)
        p11_digest = _digest_or_xfail(rs, CKM_SHA256, data)
        expected = hashlib.sha256(data).digest()
        assert p11_digest == expected


class TestDigestCrossVerify:
    """Cross-verify PKCS#11 digests against Python hashlib."""

    @pytest.mark.parametrize(
        "mechanism,hashlib_name",
        [
            (CKM_SHA_1, "sha1"),
            (CKM_SHA224, "sha224"),
            (CKM_SHA256, "sha256"),
            (CKM_SHA384, "sha384"),
            (CKM_SHA512, "sha512"),
        ],
        ids=["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"],
    )
    def test_cross_verify(self, p11_raw_session: Any, mechanism: Any, hashlib_name: str) -> None:
        """PKCS#11 digest matches hashlib for each algorithm."""
        rs = p11_raw_session
        data = b"cross-verification test data for digest operations"
        p11_digest = _digest_or_xfail(rs, mechanism, data)
        expected = hashlib.new(hashlib_name, data).digest()
        assert p11_digest == expected

    @pytest.mark.parametrize(
        "mechanism,hashlib_name",
        [
            (CKM_SHA256, "sha256"),
            (CKM_SHA512, "sha512"),
        ],
        ids=["SHA-256", "SHA-512"],
    )
    def test_cross_verify_binary_data(
        self, p11_raw_session: Any, mechanism: Any, hashlib_name: str
    ) -> None:
        """Digest of binary data (all byte values) matches hashlib."""
        rs = p11_raw_session
        data = bytes(range(256))
        p11_digest = _digest_or_xfail(rs, mechanism, data)
        expected = hashlib.new(hashlib_name, data).digest()
        assert p11_digest == expected


class TestDigestKey:
    """Tests for C_DigestKey - digesting key material directly.

    Source: PKCS#11 v3.2 Sec.5.13.4 (C_DigestKey).

    C_DigestKey continues an ongoing digest operation by digesting the value of
    a secret key, as if that value had been passed to C_DigestUpdate.  Uses raw
    C_DigestInit / C_DigestKey / C_DigestFinal calls since there is no single
    recipe for this multi-step pattern.
    """

    def test_digest_key_matches_hashlib(self, p11_raw_session: Any) -> None:
        """DigestKey of extractable AES-128 key matches hashlib digest of key bytes."""
        rs = p11_raw_session
        _require_digest_mechanism(rs, CKM_SHA256)
        key = _gen_extractable_aes_key_or_xfail(rs, 128)
        try:
            p11_digest = _digest_key_or_skip_or_xfail(rs, key)
            # Compare with hashlib
            key_bytes = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])[CKA_VALUE]
            assert isinstance(key_bytes, bytes)
            ref_digest = hashlib.sha256(key_bytes).digest()
            assert p11_digest == ref_digest
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_digest_key_with_data(self, p11_raw_session: Any) -> None:
        """DigestKey mixed with data: SHA-256(data_prefix + key_bytes)."""
        rs = p11_raw_session
        _require_digest_mechanism(rs, CKM_SHA256)
        key = _gen_extractable_aes_key_or_xfail(rs, 128)
        data_prefix = b"prefix-data-for-digest"
        try:
            # C_DigestInit
            mech = mech_simple(CKM_SHA256)
            rv = rs.raw.C_DigestInit(rs.sh, mech.byref())
            _expect_digest_rv_or_xfail(rv, "SHA256 advertised but C_DigestInit failed")
            # C_DigestUpdate with data prefix
            in_buf = (ctypes.c_ubyte * len(data_prefix))(*data_prefix)
            rv = rs.raw.C_DigestUpdate(rs.sh, in_buf, len(data_prefix))
            _expect_digest_rv_or_xfail(rv, "SHA256 advertised but C_DigestUpdate failed")
            # C_DigestKey
            rv = rs.raw.C_DigestKey(rs.sh, key)
            if rv == CKR_FUNCTION_NOT_SUPPORTED:
                pytest.skip("C_DigestKey not supported by this module")
            _expect_digest_rv_or_xfail(rv, "SHA256 advertised but C_DigestKey failed")
            # C_DigestFinal (two-call pattern)
            out_len = CK_ULONG(0)
            rv = rs.raw.C_DigestFinal(rs.sh, None, byref(out_len))
            _expect_digest_rv_or_xfail(rv, "SHA256 advertised but C_DigestFinal length failed")
            out_buf = (ctypes.c_ubyte * out_len.value)()
            rv = rs.raw.C_DigestFinal(rs.sh, out_buf, byref(out_len))
            _expect_digest_rv_or_xfail(rv, "SHA256 advertised but C_DigestFinal failed")
            p11_digest = bytes(out_buf[: out_len.value])
            # Compare with hashlib
            key_bytes = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])[CKA_VALUE]
            assert isinstance(key_bytes, bytes)
            ref_digest = hashlib.sha256(data_prefix + key_bytes).digest()
            assert p11_digest == ref_digest
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_digest_key_256bit(self, p11_raw_session: Any) -> None:
        """DigestKey works with AES-256 key."""
        rs = p11_raw_session
        _require_digest_mechanism(rs, CKM_SHA256)
        key = _gen_extractable_aes_key_or_xfail(rs, 256)
        try:
            p11_digest = _digest_key_or_skip_or_xfail(rs, key)
            # Compare with hashlib
            key_bytes = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])[CKA_VALUE]
            assert isinstance(key_bytes, bytes)
            ref_digest = hashlib.sha256(key_bytes).digest()
            assert p11_digest == ref_digest
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_digest_key_sensitive_non_extractable_imported_key(
        self,
        p11_raw_session: Any,
    ) -> None:
        """DigestKey may use protected key material without exposing CKA_VALUE."""
        rs = p11_raw_session
        _require_digest_mechanism(rs, CKM_SHA256)
        secret = bytes.fromhex("07192a3b4c5d6e7f8091a2b3c4d5e6f7")
        try:
            key = import_secret_key(
                rs.raw,
                rs.sh,
                CKK_AES,
                secret,
                attrs={CKA_SENSITIVE: True, CKA_EXTRACTABLE: False},
            )
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _DIGEST_RUNTIME_REJECT_RVS,
                "C_CreateObject rejected protected AES key setup for C_DigestKey",
            )
            raise

        try:
            try:
                p11_digest = digest_single_with_key(rs.raw, rs.sh, CKM_SHA256, key)
            except NotImplementedError:
                pytest.skip("C_DigestKey not supported by this module")
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    _DIGEST_KEY_PROTECTED_REJECT_RVS,
                    "SHA256 C_DigestKey rejected a protected AES key",
                )
                raise
            expected = hashlib.sha256(secret).digest()
            assert p11_digest == expected, (
                "C_DigestKey accepted a protected imported AES key but digested "
                f"{p11_digest.hex()!r}, expected {expected.hex()!r}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
