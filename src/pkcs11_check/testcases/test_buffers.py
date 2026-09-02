"""Buffer management tests - output sizing, boundary conditions.

Tests that operations handle various data sizes correctly, including
empty data, single-byte, block boundaries, and large payloads.
Based on OASIS PKCS#11 conventions for function output.
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    digest_single,
    encrypt_single,
    gen_aes_key,
    generate_random,
    import_secret_key,
    read_attributes,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_VALUE,
    CKA_VERIFY,
    CKK_AES,
    CKM_AES_ECB,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
    CKR_ARGUMENTS_BAD,
    CKR_BUFFER_TOO_SMALL,
    CKR_OK,
)
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    gen_rsa_keypair_or_xfail,
    require_operational_aes_keygen,
)

pytestmark = pytest.mark.boundary


def _gen_aes_ecb_buffer_key(rs: Any) -> int:
    if not rs.has_mechanism("AES_ECB"):
        pytest.skip("CKM_AES_ECB not supported")
    require_operational_aes_keygen(rs)
    return gen_aes_key(
        rs.raw,
        rs.sh,
        128,
        attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True},
    )


def _require_sha256(rs: Any) -> None:
    if not rs.has_mechanism("SHA256"):
        pytest.skip("CKM_SHA256 not supported")


def _gen_rsa_sign_buffer_keypair(rs: Any) -> tuple[int, int]:
    if not rs.has_mechanism("SHA256_RSA_PKCS"):
        pytest.skip("CKM_SHA256_RSA_PKCS not supported")
    if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
        pytest.skip("RSA_PKCS_KEY_PAIR_GEN not supported")
    return gen_rsa_keypair_or_xfail(
        rs,
        2048,
        public_attrs={CKA_VERIFY: True},
        private_attrs={CKA_SIGN: True},
    )


class TestEncryptBufferSizes:
    """Test encryption with various input sizes."""

    def test_single_block(self, p11_raw_session: Any) -> None:
        """Encrypt exactly one AES block (16 bytes)."""
        rs = p11_raw_session
        key = _gen_aes_ecb_buffer_key(rs)
        try:
            pt = b"X" * 16
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, pt)
            assert len(ct) == 16
            dt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
            assert dt == pt
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_two_blocks(self, p11_raw_session: Any) -> None:
        """Encrypt exactly two blocks."""
        rs = p11_raw_session
        key = _gen_aes_ecb_buffer_key(rs)
        try:
            pt = b"Y" * 32
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, pt)
            assert len(ct) == 32
            dt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
            assert dt == pt
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_100_blocks(self, p11_raw_session: Any) -> None:
        """Encrypt 100 blocks (1600 bytes)."""
        rs = p11_raw_session
        key = _gen_aes_ecb_buffer_key(rs)
        try:
            pt = b"Z" * 1600
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, pt)
            assert len(ct) == 1600
            dt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
            assert dt == pt
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_64kb(self, p11_raw_session: Any) -> None:
        """Encrypt 64KB payload."""
        rs = p11_raw_session
        key = _gen_aes_ecb_buffer_key(rs)
        try:
            pt = bytes(range(256)) * 256  # 64KB, block-aligned
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, pt)
            assert len(ct) == 65536
            dt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
            assert dt == pt
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_1mb(self, p11_raw_session: Any) -> None:
        """Encrypt 1MB payload - tests streaming/chunking."""
        rs = p11_raw_session
        key = _gen_aes_ecb_buffer_key(rs)
        try:
            pt = b"\xab" * (1024 * 1024)  # 1MB
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, pt)
            assert len(ct) == 1024 * 1024
            dt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
            assert dt == pt
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestDigestBufferSizes:
    """Test digest with various input sizes."""

    def test_empty_input(self, p11_raw_session: Any) -> None:
        """SHA-256 of empty data."""
        rs = p11_raw_session
        _require_sha256(rs)
        digest = digest_single(rs.raw, rs.sh, CKM_SHA256, b"")
        assert len(digest) == 32

    def test_single_byte(self, p11_raw_session: Any) -> None:
        """SHA-256 of single byte."""
        rs = p11_raw_session
        _require_sha256(rs)
        digest = digest_single(rs.raw, rs.sh, CKM_SHA256, b"\x00")
        assert len(digest) == 32

    def test_exactly_block_size(self, p11_raw_session: Any) -> None:
        """SHA-256 of exactly one SHA-256 block (64 bytes)."""
        rs = p11_raw_session
        _require_sha256(rs)
        digest = digest_single(rs.raw, rs.sh, CKM_SHA256, b"A" * 64)
        assert len(digest) == 32

    def test_block_boundary_minus_one(self, p11_raw_session: Any) -> None:
        """SHA-256 of 63 bytes (one less than block size)."""
        rs = p11_raw_session
        _require_sha256(rs)
        digest = digest_single(rs.raw, rs.sh, CKM_SHA256, b"B" * 63)
        assert len(digest) == 32

    def test_block_boundary_plus_one(self, p11_raw_session: Any) -> None:
        """SHA-256 of 65 bytes (one more than block size)."""
        rs = p11_raw_session
        _require_sha256(rs)
        digest = digest_single(rs.raw, rs.sh, CKM_SHA256, b"C" * 65)
        assert len(digest) == 32

    def test_large_input(self, p11_raw_session: Any) -> None:
        """SHA-256 of 1MB input."""
        rs = p11_raw_session
        _require_sha256(rs)
        data = b"D" * (1024 * 1024)
        digest = digest_single(rs.raw, rs.sh, CKM_SHA256, data)
        assert len(digest) == 32


class TestSignBufferSizes:
    """Test signing with various data sizes."""

    def test_sign_empty(self, p11_raw_session: Any) -> None:
        """RSA sign of empty data."""
        rs = p11_raw_session
        pub, priv = _gen_rsa_sign_buffer_keypair(rs)
        try:
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, b"")
            assert len(sig) == 256
            verify_single(rs.raw, rs.sh, pub, CKM_SHA256_RSA_PKCS, b"", sig)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_sign_single_byte(self, p11_raw_session: Any) -> None:
        """RSA sign of single byte."""
        rs = p11_raw_session
        pub, priv = _gen_rsa_sign_buffer_keypair(rs)
        try:
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, b"X")
            verify_single(rs.raw, rs.sh, pub, CKM_SHA256_RSA_PKCS, b"X", sig)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_sign_100kb(self, p11_raw_session: Any) -> None:
        """RSA sign of 100KB payload."""
        rs = p11_raw_session
        pub, priv = _gen_rsa_sign_buffer_keypair(rs)
        try:
            data = b"E" * 100_000
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)
            verify_single(rs.raw, rs.sh, pub, CKM_SHA256_RSA_PKCS, data, sig)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestKeyImportBufferSizes:
    """Test key import with various key sizes."""

    def test_aes_128(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            bytes(16),
            attrs={CKA_SENSITIVE: False, CKA_EXTRACTABLE: True},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])
            assert attrs[CKA_VALUE] == bytes(16)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_aes_192(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            bytes(24),
            attrs={CKA_SENSITIVE: False, CKA_EXTRACTABLE: True},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])
            assert attrs[CKA_VALUE] == bytes(24)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_aes_256(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            bytes(32),
            attrs={CKA_SENSITIVE: False, CKA_EXTRACTABLE: True},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])
            assert attrs[CKA_VALUE] == bytes(32)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestRandomBufferSizes:
    """Test C_GenerateRandom with various sizes."""

    def test_1_byte(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        assert len(generate_random(rs.raw, rs.sh, 1)) == 1

    def test_16_bytes(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        assert len(generate_random(rs.raw, rs.sh, 16)) == 16

    def test_256_bytes(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        assert len(generate_random(rs.raw, rs.sh, 256)) == 256

    def test_4096_bytes(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        assert len(generate_random(rs.raw, rs.sh, 4096)) == 4096


class TestOutputBufferEdgeCases:
    """Output-buffer edge cases the existing input-size tests skip.

    PKCS#11 two-call probe protocol leaves several behaviors
    implementation-defined; we catalogue them per module and fail on the
    cases the spec is unambiguous about (e.g. state preservation across
    repeated CKR_BUFFER_TOO_SMALL retries).
    """

    def test_digest_final_buffer_too_small_then_correct(self, p11_raw_session: Any) -> None:
        """C_DigestFinal with too-small buffer → CKR_BUFFER_TOO_SMALL,
        then correct-size buffer → CKR_OK with valid digest.

        Spec §5.2: when CKR_BUFFER_TOO_SMALL is returned, the operation
        state is preserved and the caller may retry with a larger buffer.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")

        mech = mech_simple(CKM_SHA256)
        rv = int(rs.raw.C_DigestInit(rs.sh, mech.byref()))
        if rv != CKR_OK:
            pytest.skip(f"C_DigestInit failed: 0x{rv:08x}")

        # Feed input
        msg = b"buffer-edge-case-test-vector"
        msg_buf = (ctypes.c_ubyte * len(msg))(*msg)
        rv = int(rs.raw.C_DigestUpdate(rs.sh, msg_buf, len(msg)))
        assert rv == CKR_OK, f"C_DigestUpdate: 0x{rv:08x}"

        # First Final: undersized buffer should return BUFFER_TOO_SMALL
        # with required size written to pulSize.  State must be preserved.
        small_buf = (ctypes.c_ubyte * 8)()
        small_len = CK_ULONG(8)
        rv = int(rs.raw.C_DigestFinal(rs.sh, small_buf, byref(small_len)))
        assert rv == CKR_BUFFER_TOO_SMALL, (
            f"C_DigestFinal with 8-byte buffer for SHA256 returned 0x{rv:08x}, "
            f"expected CKR_BUFFER_TOO_SMALL"
        )
        assert small_len.value == 32, (
            f"After CKR_BUFFER_TOO_SMALL, pulSize must equal required size; "
            f"got {small_len.value}, expected 32"
        )

        # Retry with correct size — state must be preserved per spec.
        out_buf = (ctypes.c_ubyte * 32)()
        out_len = CK_ULONG(32)
        rv = int(rs.raw.C_DigestFinal(rs.sh, out_buf, byref(out_len)))
        assert rv == CKR_OK, (
            f"Retry C_DigestFinal with 32-byte buffer returned 0x{rv:08x} — "
            f"module failed to preserve operation state across "
            f"CKR_BUFFER_TOO_SMALL"
        )
        assert out_len.value == 32

    def test_digest_final_preserves_state_across_multiple_retries(
        self, p11_raw_session: Any
    ) -> None:
        """Three sequential CKR_BUFFER_TOO_SMALL retries followed by correct size.

        Operation state must remain intact through repeated too-small
        attempts.  Caller's buffer-size negotiation logic relies on this.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")

        mech = mech_simple(CKM_SHA256)
        rv = int(rs.raw.C_DigestInit(rs.sh, mech.byref()))
        if rv != CKR_OK:
            pytest.skip(f"C_DigestInit failed: 0x{rv:08x}")

        msg = b"retry-state-preservation"
        msg_buf = (ctypes.c_ubyte * len(msg))(*msg)
        int(rs.raw.C_DigestUpdate(rs.sh, msg_buf, len(msg)))

        # Three retries with progressively-larger but still-too-small buffers
        for attempt_size in (1, 8, 16):
            buf = (ctypes.c_ubyte * attempt_size)()
            buf_len = CK_ULONG(attempt_size)
            rv = int(rs.raw.C_DigestFinal(rs.sh, buf, byref(buf_len)))
            assert rv == CKR_BUFFER_TOO_SMALL, (
                f"Retry #{attempt_size}: expected CKR_BUFFER_TOO_SMALL, got 0x{rv:08x}"
            )
            assert buf_len.value == 32, (
                f"Retry #{attempt_size}: pulSize must be 32, got {buf_len.value}"
            )

        # Final attempt with correct size: state must still be intact
        out_buf = (ctypes.c_ubyte * 32)()
        out_len = CK_ULONG(32)
        rv = int(rs.raw.C_DigestFinal(rs.sh, out_buf, byref(out_len)))
        assert rv == CKR_OK, (
            f"After 3 retries, correct-size C_DigestFinal returned 0x{rv:08x} — "
            f"state was not preserved"
        )

    def test_digest_final_probe_null_buffer_returns_size(self, p11_raw_session: Any) -> None:
        """C_DigestFinal(NULL pBuffer, &pulSize) must populate pulSize.

        Spec §5.2 two-call probe: NULL output buffer returns the required
        size without writing data, with rv = CKR_OK.  State is preserved.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")

        mech = mech_simple(CKM_SHA256)
        rv = int(rs.raw.C_DigestInit(rs.sh, mech.byref()))
        if rv != CKR_OK:
            pytest.skip(f"C_DigestInit failed: 0x{rv:08x}")

        msg = b"probe-null-buffer"
        msg_buf = (ctypes.c_ubyte * len(msg))(*msg)
        int(rs.raw.C_DigestUpdate(rs.sh, msg_buf, len(msg)))

        probe_len = CK_ULONG(0)  # garbage; should be overwritten
        rv = int(rs.raw.C_DigestFinal(rs.sh, None, byref(probe_len)))
        assert rv == CKR_OK, (
            f"C_DigestFinal(NULL, &size) returned 0x{rv:08x}; spec says CKR_OK with size populated"
        )
        assert probe_len.value == 32, (
            f"Probe must populate pulSize with 32 (SHA256 output); got {probe_len.value}"
        )

        # State must still be intact: a follow-up Final with real buffer succeeds.
        out_buf = (ctypes.c_ubyte * 32)()
        out_len = CK_ULONG(32)
        rv = int(rs.raw.C_DigestFinal(rs.sh, out_buf, byref(out_len)))
        assert rv == CKR_OK, (
            f"After NULL-buffer probe, real C_DigestFinal returned 0x{rv:08x} — state was lost"
        )

    def test_digest_final_with_oversize_buffer_writes_actual_size(
        self, p11_raw_session: Any
    ) -> None:
        """Oversize buffer is accepted; pulSize set to actual written bytes."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")

        mech = mech_simple(CKM_SHA256)
        rv = int(rs.raw.C_DigestInit(rs.sh, mech.byref()))
        if rv != CKR_OK:
            pytest.skip(f"C_DigestInit failed: 0x{rv:08x}")

        msg = b"oversize-buffer-test"
        msg_buf = (ctypes.c_ubyte * len(msg))(*msg)
        int(rs.raw.C_DigestUpdate(rs.sh, msg_buf, len(msg)))

        oversize_buf = (ctypes.c_ubyte * 1024)()
        oversize_len = CK_ULONG(1024)
        rv = int(rs.raw.C_DigestFinal(rs.sh, oversize_buf, byref(oversize_len)))
        assert rv == CKR_OK, f"C_DigestFinal with 1024-byte buffer: 0x{rv:08x}"
        assert oversize_len.value == 32, (
            f"With oversize buffer, pulSize must reflect actual written bytes (32); "
            f"got {oversize_len.value}"
        )

    def test_sign_final_buffer_too_small_then_correct(self, p11_raw_session: Any) -> None:
        """C_SignFinal with too-small buffer → BUFFER_TOO_SMALL, retry → OK.

        Asymmetric signature sizes (RSA-2048 → 256 bytes) make the
        too-small case easy to set up.
        """
        rs = p11_raw_session
        pub, priv = _gen_rsa_sign_buffer_keypair(rs)
        try:
            mech = mech_simple(CKM_SHA256_RSA_PKCS)
            rv = int(rs.raw.C_SignInit(rs.sh, mech.byref(), priv))
            if rv != CKR_OK:
                pytest.skip(f"C_SignInit failed: 0x{rv:08x}")

            msg = b"signature-buffer-edge"
            msg_buf = (ctypes.c_ubyte * len(msg))(*msg)
            int(rs.raw.C_SignUpdate(rs.sh, msg_buf, len(msg)))

            # Too-small buffer
            small_buf = (ctypes.c_ubyte * 16)()
            small_len = CK_ULONG(16)
            rv = int(rs.raw.C_SignFinal(rs.sh, small_buf, byref(small_len)))
            assert rv == CKR_BUFFER_TOO_SMALL, (
                f"C_SignFinal with 16-byte buffer for RSA-2048 returned 0x{rv:08x}, "
                f"expected CKR_BUFFER_TOO_SMALL"
            )
            assert small_len.value == 256, (
                f"After CKR_BUFFER_TOO_SMALL, pulSize must be 256 (RSA-2048); got {small_len.value}"
            )

            # Retry with correct size
            sig_buf = (ctypes.c_ubyte * 256)()
            sig_len = CK_ULONG(256)
            rv = int(rs.raw.C_SignFinal(rs.sh, sig_buf, byref(sig_len)))
            assert rv == CKR_OK, (
                f"Retry C_SignFinal with 256-byte buffer returned 0x{rv:08x} — "
                f"signature state was not preserved across BUFFER_TOO_SMALL"
            )
            assert sig_len.value == 256
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_generate_random_zero_length_buffer(self, p11_raw_session: Any) -> None:
        """C_GenerateRandom with length=0 must complete cleanly.

        Spec §5.19 doesn't carve out zero-length specifically; it is a
        no-op writing zero bytes.  Some modules return CKR_ARGUMENTS_BAD;
        either is acceptable but a segfault or hang is not.
        """
        rs = p11_raw_session
        buf = (ctypes.c_ubyte * 1)()
        rv = int(rs.raw.C_GenerateRandom(rs.sh, buf, 0))
        # Either CKR_OK (zero-length read is a no-op) or CKR_ARGUMENTS_BAD
        # (some modules treat 0-length as bad arg) is acceptable.
        # Spec §5.19 does not carve out zero-length; allow_ok=True since success is spec-legal.
        classify_negative_rv(
            rv,
            (CKR_ARGUMENTS_BAD,),
            label="C_GenerateRandom zero length",
            allow_ok=True,
        )
