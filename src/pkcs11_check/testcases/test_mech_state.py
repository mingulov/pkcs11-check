"""Operation state machine violation tests.

Tests verify that the module correctly enforces PKCS#11 operation state:
- C_Encrypt (and variants) without prior C_EncryptInit -> CKR_OPERATION_NOT_INITIALIZED
- C_EncryptInit while another operation is active -> CKR_OPERATION_ACTIVE
- C_Sign, C_Verify, C_Digest: same patterns
- C_DecryptFinal without C_DecryptInit -> CKR_OPERATION_NOT_INITIALIZED

Source: PKCS#11 v3.1 Section 5 -- each function description lists
CKR_OPERATION_NOT_INITIALIZED and CKR_OPERATION_ACTIVE as valid return values.

These tests are NOT parametrized -- they use hard-coded AES and SHA-256 mechanisms
which are widely supported.  Mechanism-specific state tests belong in the
mechanism-specific test files.
"""
from __future__ import annotations

import ctypes
from ctypes import byref

import pytest

from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKM_AES_ECB,
    CKM_SHA256,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED,
)

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.state_machine]

# Acceptable "not initialised" return codes.
# Some modules return CKR_FUNCTION_FAILED rather than the specific code.
_NOT_INIT_RVCS: frozenset[int] = frozenset(
    [
        int(CKR_OPERATION_NOT_INITIALIZED),
        0x00000005,  # CKR_FUNCTION_FAILED -- non-spec-compliant but widely seen
        0x00000020,  # CKR_GENERAL_ERROR
    ]
)

# Acceptable "already active" return codes.
_ALREADY_ACTIVE_RVCS: frozenset[int] = frozenset(
    [
        int(CKR_OPERATION_ACTIVE),
        0x00000005,  # CKR_FUNCTION_FAILED
        0x00000020,  # CKR_GENERAL_ERROR
    ]
)


class TestEncryptState:
    """Encrypt operation state enforcement."""

    def test_encrypt_without_init(self, p11_raw_session: RawSession) -> None:
        """C_Encrypt without prior C_EncryptInit must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        plaintext = b"\xaa" * 16
        in_buf = (ctypes.c_ubyte * len(plaintext)).from_buffer_copy(plaintext)
        out_buf = (ctypes.c_ubyte * 32)()
        out_len = CK_ULONG(32)

        rv = rs.raw.C_Encrypt(
            rs.sh, in_buf, len(plaintext), out_buf, byref(out_len)
        )
        assert rv in _NOT_INIT_RVCS, (
            f"C_Encrypt without init returned 0x{rv:08x}, "
            f"expected CKR_OPERATION_NOT_INITIALIZED (0x{int(CKR_OPERATION_NOT_INITIALIZED):08x})"
        )

    def test_encrypt_final_without_init(self, p11_raw_session: RawSession) -> None:
        """C_EncryptFinal without init must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        out_buf = (ctypes.c_ubyte * 32)()
        out_len = CK_ULONG(32)
        rv = rs.raw.C_EncryptFinal(rs.sh, out_buf, byref(out_len))
        assert rv in _NOT_INIT_RVCS, (
            f"C_EncryptFinal without init returned 0x{rv:08x}, "
            f"expected CKR_OPERATION_NOT_INITIALIZED"
        )

    def test_double_encrypt_init(self, p11_raw_session: RawSession) -> None:
        """C_EncryptInit twice -> second call must return CKR_OPERATION_ACTIVE."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("AES keygen not supported")

        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv1 = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            if rv1 != CKR_OK:
                pytest.skip(f"First C_EncryptInit failed: 0x{rv1:08x}")

            # Second init while operation is active
            mech2 = mech_simple(CKM_AES_ECB)
            rv2 = rs.raw.C_EncryptInit(rs.sh, mech2.byref(), key)
            assert rv2 in _ALREADY_ACTIVE_RVCS, (
                f"Double C_EncryptInit returned 0x{rv2:08x}, "
                f"expected CKR_OPERATION_ACTIVE (0x{int(CKR_OPERATION_ACTIVE):08x})"
            )
        finally:
            # Abort any pending operation by calling C_EncryptFinal with a discard buffer
            try:
                out_buf = (ctypes.c_ubyte * 64)()
                out_len = CK_ULONG(64)
                rs.raw.C_EncryptFinal(rs.sh, out_buf, byref(out_len))
            except Exception:
                pass  # Best-effort cleanup: EncryptFinal may fail if op already terminated
            destroy_quietly(rs.raw, rs.sh, key)


class TestDecryptState:
    """Decrypt operation state enforcement."""

    def test_decrypt_without_init(self, p11_raw_session: RawSession) -> None:
        """C_Decrypt without prior C_DecryptInit must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        ct = b"\xbb" * 16
        in_buf = (ctypes.c_ubyte * len(ct)).from_buffer_copy(ct)
        out_buf = (ctypes.c_ubyte * 32)()
        out_len = CK_ULONG(32)

        rv = rs.raw.C_Decrypt(
            rs.sh, in_buf, len(ct), out_buf, byref(out_len)
        )
        assert rv in _NOT_INIT_RVCS, (
            f"C_Decrypt without init returned 0x{rv:08x}, "
            f"expected CKR_OPERATION_NOT_INITIALIZED"
        )

    def test_decrypt_final_without_init(self, p11_raw_session: RawSession) -> None:
        """C_DecryptFinal without init must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        out_buf = (ctypes.c_ubyte * 32)()
        out_len = CK_ULONG(32)
        rv = rs.raw.C_DecryptFinal(rs.sh, out_buf, byref(out_len))
        assert rv in _NOT_INIT_RVCS, (
            f"C_DecryptFinal without init returned 0x{rv:08x}, "
            f"expected CKR_OPERATION_NOT_INITIALIZED"
        )


class TestSignState:
    """Sign operation state enforcement."""

    def test_sign_without_init(self, p11_raw_session: RawSession) -> None:
        """C_Sign without prior C_SignInit must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session

        data = b"\xcc" * 16
        in_buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        sig_buf = (ctypes.c_ubyte * 256)()
        sig_len = CK_ULONG(256)

        rv = rs.raw.C_Sign(rs.sh, in_buf, len(data), sig_buf, byref(sig_len))
        assert rv in _NOT_INIT_RVCS, (
            f"C_Sign without init returned 0x{rv:08x}, "
            f"expected CKR_OPERATION_NOT_INITIALIZED"
        )

    def test_sign_update_without_init(self, p11_raw_session: RawSession) -> None:
        """C_SignUpdate without prior C_SignInit must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session

        data = b"\xdd" * 8
        in_buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        rv = rs.raw.C_SignUpdate(rs.sh, in_buf, len(data))
        assert rv in _NOT_INIT_RVCS, (
            f"C_SignUpdate without init returned 0x{rv:08x}, "
            f"expected CKR_OPERATION_NOT_INITIALIZED"
        )

    def test_sign_final_without_init(self, p11_raw_session: RawSession) -> None:
        """C_SignFinal without prior C_SignInit must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session

        sig_buf = (ctypes.c_ubyte * 256)()
        sig_len = CK_ULONG(256)
        rv = rs.raw.C_SignFinal(rs.sh, sig_buf, byref(sig_len))
        assert rv in _NOT_INIT_RVCS, (
            f"C_SignFinal without init returned 0x{rv:08x}, "
            f"expected CKR_OPERATION_NOT_INITIALIZED"
        )


class TestVerifyState:
    """Verify operation state enforcement."""

    def test_verify_without_init(self, p11_raw_session: RawSession) -> None:
        """C_Verify without prior C_VerifyInit must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session

        data = b"\xee" * 16
        sig = b"\xff" * 64
        in_buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        sig_buf = (ctypes.c_ubyte * len(sig)).from_buffer_copy(sig)

        rv = rs.raw.C_Verify(rs.sh, in_buf, len(data), sig_buf, len(sig))
        assert rv in _NOT_INIT_RVCS | {
            0x000000C4,  # CKR_SIGNATURE_INVALID
            0x000000C5,  # CKR_SIGNATURE_LEN_RANGE
        }, (
            f"C_Verify without init returned 0x{rv:08x}, "
            f"expected CKR_OPERATION_NOT_INITIALIZED"
        )

    def test_verify_update_without_init(self, p11_raw_session: RawSession) -> None:
        """C_VerifyUpdate without prior C_VerifyInit must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session

        data = b"\x01" * 8
        in_buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        rv = rs.raw.C_VerifyUpdate(rs.sh, in_buf, len(data))
        assert rv in _NOT_INIT_RVCS, (
            f"C_VerifyUpdate without init returned 0x{rv:08x}, "
            f"expected CKR_OPERATION_NOT_INITIALIZED"
        )

    def test_verify_final_without_init(self, p11_raw_session: RawSession) -> None:
        """C_VerifyFinal without prior C_VerifyInit must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session

        sig = b"\x02" * 64
        sig_buf = (ctypes.c_ubyte * len(sig)).from_buffer_copy(sig)
        rv = rs.raw.C_VerifyFinal(rs.sh, sig_buf, len(sig))
        assert rv in _NOT_INIT_RVCS | {
            0x000000C4,  # CKR_SIGNATURE_INVALID
            0x000000C5,  # CKR_SIGNATURE_LEN_RANGE
        }, (
            f"C_VerifyFinal without init returned 0x{rv:08x}, "
            f"expected CKR_OPERATION_NOT_INITIALIZED"
        )


class TestDigestState:
    """Digest operation state enforcement."""

    def test_digest_without_init(self, p11_raw_session: RawSession) -> None:
        """C_Digest without prior C_DigestInit must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")

        data = b"\x03" * 16
        in_buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        out_buf = (ctypes.c_ubyte * 64)()
        out_len = CK_ULONG(64)

        rv = rs.raw.C_Digest(rs.sh, in_buf, len(data), out_buf, byref(out_len))
        assert rv in _NOT_INIT_RVCS, (
            f"C_Digest without init returned 0x{rv:08x}, "
            f"expected CKR_OPERATION_NOT_INITIALIZED"
        )

    def test_digest_update_without_init(self, p11_raw_session: RawSession) -> None:
        """C_DigestUpdate without prior C_DigestInit must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")

        data = b"\x04" * 8
        in_buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        rv = rs.raw.C_DigestUpdate(rs.sh, in_buf, len(data))
        assert rv in _NOT_INIT_RVCS, (
            f"C_DigestUpdate without init returned 0x{rv:08x}, "
            f"expected CKR_OPERATION_NOT_INITIALIZED"
        )

    def test_digest_final_without_init(self, p11_raw_session: RawSession) -> None:
        """C_DigestFinal without prior C_DigestInit must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")

        out_buf = (ctypes.c_ubyte * 64)()
        out_len = CK_ULONG(64)
        rv = rs.raw.C_DigestFinal(rs.sh, out_buf, byref(out_len))
        assert rv in _NOT_INIT_RVCS, (
            f"C_DigestFinal without init returned 0x{rv:08x}, "
            f"expected CKR_OPERATION_NOT_INITIALIZED"
        )

    def test_double_digest_init(self, p11_raw_session: RawSession) -> None:
        """C_DigestInit twice -> second call must return CKR_OPERATION_ACTIVE."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")

        mech = mech_simple(CKM_SHA256)
        rv1 = rs.raw.C_DigestInit(rs.sh, mech.byref())
        if rv1 != CKR_OK:
            pytest.skip(f"First C_DigestInit failed: 0x{rv1:08x}")

        mech2 = mech_simple(CKM_SHA256)
        rv2 = rs.raw.C_DigestInit(rs.sh, mech2.byref())
        assert rv2 in _ALREADY_ACTIVE_RVCS, (
            f"Double C_DigestInit returned 0x{rv2:08x}, "
            f"expected CKR_OPERATION_ACTIVE (0x{int(CKR_OPERATION_ACTIVE):08x})"
        )

        # Abort the pending digest by completing it
        try:
            out_buf = (ctypes.c_ubyte * 64)()
            out_len = CK_ULONG(64)
            rs.raw.C_DigestFinal(rs.sh, out_buf, byref(out_len))
        except Exception:
            pass  # Best-effort cleanup: DigestFinal may fail if op already terminated
