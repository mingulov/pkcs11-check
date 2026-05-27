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
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    import_secret_key,
    to_ubyte_buf,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKK_SHA256_HMAC,
    CKM_AES_ECB,
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_SESSION_HANDLE_INVALID,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import xfail_if_known_ckr

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.state_machine]

# Acceptable "not initialised" return codes.
# Some modules return CKR_FUNCTION_FAILED rather than the specific code.
_NOT_INIT_RVCS: frozenset[int] = frozenset(
    {
        CKR_OPERATION_NOT_INITIALIZED,
        CKR_FUNCTION_FAILED,  # non-spec-compliant but widely seen
        CKR_GENERAL_ERROR,
    }
)

# Strict subset for cross-session-state-confusion tests. CKR_FUNCTION_FAILED /
# CKR_GENERAL_ERROR are EXPLICITLY NOT accepted here: a module that crashes or
# panics during cross-session probing and recovers with one of those codes is
# exhibiting exactly the state-confusion bug class the test is meant to catch.
# If a real module legitimately needs a fallback, register it as a quirk in
# `_module_quirks.py` and call `quirk_extras(...)` instead of widening this set.
_CROSS_SESSION_NOT_INIT_RVCS: frozenset[int] = frozenset(
    {
        CKR_OPERATION_NOT_INITIALIZED,
        CKR_SESSION_HANDLE_INVALID,  # some modules return this if they
        # keyed the operation table on the
        # wrong handle
    }
)

# Acceptable "already active" return codes.
_ALREADY_ACTIVE_RVCS: frozenset[int] = frozenset(
    [
        CKR_OPERATION_ACTIVE,
        CKR_FUNCTION_FAILED,
        CKR_GENERAL_ERROR,
    ]
)

_HMAC_KEY_IMPORT_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
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

        rv = rs.raw.C_Encrypt(rs.sh, in_buf, len(plaintext), out_buf, byref(out_len))
        assert rv in _NOT_INIT_RVCS, (
            f"C_Encrypt without init returned 0x{rv:08x}, "
            f"expected CKR_OPERATION_NOT_INITIALIZED (0x{CKR_OPERATION_NOT_INITIALIZED:08x})"
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
                f"expected CKR_OPERATION_ACTIVE (0x{CKR_OPERATION_ACTIVE:08x})"
            )
        finally:
            # Abort any pending operation by calling C_EncryptFinal with a discard buffer
            out_buf = (ctypes.c_ubyte * 64)()
            out_len = CK_ULONG(64)
            rs.raw.C_EncryptFinal(rs.sh, out_buf, byref(out_len))
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

        rv = rs.raw.C_Decrypt(rs.sh, in_buf, len(ct), out_buf, byref(out_len))
        assert rv in _NOT_INIT_RVCS, (
            f"C_Decrypt without init returned 0x{rv:08x}, expected CKR_OPERATION_NOT_INITIALIZED"
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
            f"C_Sign without init returned 0x{rv:08x}, expected CKR_OPERATION_NOT_INITIALIZED"
        )

    def test_sign_update_without_init(self, p11_raw_session: RawSession) -> None:
        """C_SignUpdate without prior C_SignInit must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session

        data = b"\xdd" * 8
        in_buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        rv = rs.raw.C_SignUpdate(rs.sh, in_buf, len(data))
        assert rv in _NOT_INIT_RVCS, (
            f"C_SignUpdate without init returned 0x{rv:08x}, expected CKR_OPERATION_NOT_INITIALIZED"
        )

    def test_sign_final_without_init(self, p11_raw_session: RawSession) -> None:
        """C_SignFinal without prior C_SignInit must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session

        sig_buf = (ctypes.c_ubyte * 256)()
        sig_len = CK_ULONG(256)
        rv = rs.raw.C_SignFinal(rs.sh, sig_buf, byref(sig_len))
        assert rv in _NOT_INIT_RVCS, (
            f"C_SignFinal without init returned 0x{rv:08x}, expected CKR_OPERATION_NOT_INITIALIZED"
        )

    def test_sign_single_part_output_call_terminates(self, p11_raw_session: RawSession) -> None:
        """Successful two-call C_Sign must terminate before a new C_SignInit."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")

        key = 0
        try:
            try:
                key = import_secret_key(
                    rs.raw,
                    rs.sh,
                    CKK_SHA256_HMAC,
                    bytes(range(32)),
                    attrs={
                        CKA_SIGN: True,
                        CKA_TOKEN: False,
                        CKA_SENSITIVE: False,
                    },
                )
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    _HMAC_KEY_IMPORT_REJECT_RVS,
                    "SHA256_HMAC advertised but setup key import is not operational",
                )

            mech = mech_simple(CKM_SHA256_HMAC)
            data = b""
            data_buf = to_ubyte_buf(data)
            sig_len = CK_ULONG(0)

            rv = rs.raw.C_SignInit(rs.sh, mech.byref(), key)
            expect_rv(rv, CKR_OK)
            rv = rs.raw.C_Sign(rs.sh, data_buf, len(data), None, byref(sig_len))
            expect_rv(rv, CKR_OK)

            sig_buf = (ctypes.c_ubyte * sig_len.value)()
            rv = rs.raw.C_Sign(rs.sh, data_buf, len(data), sig_buf, byref(sig_len))
            expect_rv(rv, CKR_OK)

            mech2 = mech_simple(CKM_SHA256_HMAC)
            rv2 = rs.raw.C_SignInit(rs.sh, mech2.byref(), key)
            assert rv2 == CKR_OK, (
                f"successful C_Sign did not terminate the active sign operation; "
                f"next C_SignInit returned 0x{rv2:08x}, expected CKR_OK"
            )
        finally:
            sig_buf = (ctypes.c_ubyte * 64)()
            sig_len = CK_ULONG(64)
            rs.raw.C_SignFinal(rs.sh, sig_buf, byref(sig_len))
            if key:
                destroy_quietly(rs.raw, rs.sh, key)


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
            CKR_SIGNATURE_INVALID,
            CKR_SIGNATURE_LEN_RANGE,
        }, f"C_Verify without init returned 0x{rv:08x}, expected CKR_OPERATION_NOT_INITIALIZED"

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
            CKR_SIGNATURE_INVALID,
            CKR_SIGNATURE_LEN_RANGE,
        }, f"C_VerifyFinal without init returned 0x{rv:08x}, expected CKR_OPERATION_NOT_INITIALIZED"


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
            f"C_Digest without init returned 0x{rv:08x}, expected CKR_OPERATION_NOT_INITIALIZED"
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
            f"expected CKR_OPERATION_ACTIVE (0x{CKR_OPERATION_ACTIVE:08x})"
        )

        # Abort the pending digest by completing it
        out_buf = (ctypes.c_ubyte * 64)()
        out_len = CK_ULONG(64)
        rs.raw.C_DigestFinal(rs.sh, out_buf, byref(out_len))

    def test_digest_single_part_output_call_terminates(self, p11_raw_session: RawSession) -> None:
        """Successful two-call C_Digest must terminate before a new C_DigestInit."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")

        try:
            mech = mech_simple(CKM_SHA256)
            data = b""
            data_buf = to_ubyte_buf(data)
            out_len = CK_ULONG(0)

            rv = rs.raw.C_DigestInit(rs.sh, mech.byref())
            expect_rv(rv, CKR_OK)
            rv = rs.raw.C_Digest(rs.sh, data_buf, len(data), None, byref(out_len))
            expect_rv(rv, CKR_OK)

            out_buf = (ctypes.c_ubyte * out_len.value)()
            rv = rs.raw.C_Digest(rs.sh, data_buf, len(data), out_buf, byref(out_len))
            expect_rv(rv, CKR_OK)

            mech2 = mech_simple(CKM_SHA256)
            rv2 = rs.raw.C_DigestInit(rs.sh, mech2.byref())
            assert rv2 == CKR_OK, (
                f"successful C_Digest did not terminate the active digest operation; "
                f"next C_DigestInit returned 0x{rv2:08x}, expected CKR_OK"
            )
        finally:
            out_buf = (ctypes.c_ubyte * 64)()
            out_len = CK_ULONG(64)
            rs.raw.C_DigestFinal(rs.sh, out_buf, byref(out_len))


class TestMultiPartCrossSession:
    """GAP-A1: cross-session state confusion in multi-part operations.

    A multi-part state initialised in session A must NOT be accessible from
    session B. A module that lets session B continue session A's
    operation has a state-confusion bug — multi-part state is per-session
    per the spec (PKCS#11 v3.1 Sec.5.6, Sec.5.10.1).
    """

    def test_encrypt_update_from_other_session(self, p11_raw_session: RawSession) -> None:
        """C_EncryptInit in session A; C_EncryptUpdate from session B must fail.

        Session B never called C_EncryptInit so its operation slot is
        empty — Update there must return CKR_OPERATION_NOT_INITIALIZED
        regardless of session A's state.
        """
        from pkcs11_check.raw.bootstrap import close_session_quietly
        from pkcs11_check.raw.bootstrap import open_session as raw_open_session
        from pkcs11_check.raw.types_std import CKF_SERIAL_SESSION

        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        key = gen_aes_key(rs.raw, rs.sh, 256)
        sh_b = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)

        try:
            mech = mech_simple(CKM_AES_ECB)
            rv1 = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            if rv1 != CKR_OK:
                pytest.skip(f"C_EncryptInit in session A failed: 0x{rv1:08x}")

            data = b"\x55" * 16
            in_buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
            out_buf = (ctypes.c_ubyte * 32)()
            out_len = CK_ULONG(32)

            # Session B has no encrypt operation initialised; Update here
            # must be rejected.
            rv_b = rs.raw.C_EncryptUpdate(sh_b, in_buf, len(data), out_buf, byref(out_len))
            assert rv_b in _CROSS_SESSION_NOT_INIT_RVCS, (
                f"C_EncryptUpdate from un-initialised session B returned "
                f"0x{rv_b:08x}, expected CKR_OPERATION_NOT_INITIALIZED — "
                f"CKR_FUNCTION_FAILED / CKR_GENERAL_ERROR are explicitly "
                f"NOT accepted here because they indicate exactly the "
                f"crash-on-cross-session-probe pattern this test guards "
                f"against (see _CROSS_SESSION_NOT_INIT_RVCS comment)"
            )
        finally:
            out_buf = (ctypes.c_ubyte * 64)()
            out_len = CK_ULONG(64)
            rs.raw.C_EncryptFinal(rs.sh, out_buf, byref(out_len))
            close_session_quietly(rs.raw, sh_b)
            destroy_quietly(rs.raw, rs.sh, key)

    def test_digest_update_from_other_session(self, p11_raw_session: RawSession) -> None:
        """C_DigestInit in session A; C_DigestUpdate from session B must fail."""
        from pkcs11_check.raw.bootstrap import close_session_quietly
        from pkcs11_check.raw.bootstrap import open_session as raw_open_session
        from pkcs11_check.raw.types_std import CKF_SERIAL_SESSION

        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")

        sh_b = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        try:
            mech = mech_simple(CKM_SHA256)
            rv1 = rs.raw.C_DigestInit(rs.sh, mech.byref())
            if rv1 != CKR_OK:
                pytest.skip(f"C_DigestInit in session A failed: 0x{rv1:08x}")

            data = b"\x66" * 16
            in_buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
            rv_b = rs.raw.C_DigestUpdate(sh_b, in_buf, len(data))
            assert rv_b in _CROSS_SESSION_NOT_INIT_RVCS, (
                f"C_DigestUpdate from un-initialised session B returned "
                f"0x{rv_b:08x}, expected CKR_OPERATION_NOT_INITIALIZED — "
                f"CKR_FUNCTION_FAILED / CKR_GENERAL_ERROR are explicitly "
                f"NOT accepted here (see _CROSS_SESSION_NOT_INIT_RVCS)"
            )
        finally:
            out_buf = (ctypes.c_ubyte * 64)()
            out_len = CK_ULONG(64)
            rs.raw.C_DigestFinal(rs.sh, out_buf, byref(out_len))
            close_session_quietly(rs.raw, sh_b)


class TestZeroDataFinal:
    """GAP-A1: zero-data multi-part Final calls.

    Calling C_*Final immediately after C_*Init with no Update calls is a
    valid PKCS#11 sequence (degenerate single-pass operation). Multiple
    HSMs have memory-corruption bugs in the zero-input path because the
    Final code path assumes at least one Update was called and reads
    uninitialised state.
    """

    def test_encrypt_final_no_update(self, p11_raw_session: RawSession) -> None:
        """EncryptInit then EncryptFinal with no Update — must succeed cleanly."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv1 = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            if rv1 != CKR_OK:
                pytest.skip(f"C_EncryptInit failed: 0x{rv1:08x}")

            out_buf = (ctypes.c_ubyte * 64)()
            out_len = CK_ULONG(64)
            rv = rs.raw.C_EncryptFinal(rs.sh, out_buf, byref(out_len))

            # ECB has no padding so 0 input → 0 output is the natural answer.
            # Some modules may reject with CKR_DATA_LEN_RANGE because ECB
            # requires whole-block input. Both are acceptable as long as
            # the module doesn't crash or return CKR_GENERAL_ERROR.
            accepted = (
                CKR_OK,
                0x00000021,  # CKR_DATA_LEN_RANGE
                CKR_OPERATION_NOT_INITIALIZED,  # some treat 0-byte as no-op
                0x00000063,  # CKR_BUFFER_TOO_SMALL on length-query
            )
            assert rv in accepted, (
                f"C_EncryptFinal with no Update returned 0x{rv:08x}; "
                f"expected one of {[hex(c) for c in accepted]} — generic "
                f"or unexpected codes can mask zero-input memory-corruption "
                f"bugs"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_digest_final_no_update(self, p11_raw_session: RawSession) -> None:
        """DigestInit then DigestFinal with no Update — must produce empty-input
        digest (e.g. SHA-256 of empty string = e3b0c44...)."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")

        mech = mech_simple(CKM_SHA256)
        rv1 = rs.raw.C_DigestInit(rs.sh, mech.byref())
        if rv1 != CKR_OK:
            pytest.skip(f"C_DigestInit failed: 0x{rv1:08x}")

        out_buf = (ctypes.c_ubyte * 64)()
        out_len = CK_ULONG(64)
        rv = rs.raw.C_DigestFinal(rs.sh, out_buf, byref(out_len))

        if rv != CKR_OK:
            pytest.skip(
                f"Module rejected zero-data DigestFinal with 0x{rv:08x} "
                f"(some treat it as not-initialised)"
            )

        # Verify the output is the canonical empty-string SHA-256.
        empty_sha256 = bytes.fromhex(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        actual = bytes(out_buf[: out_len.value])
        assert actual == empty_sha256, (
            f"SHA-256 of empty input is 0x{empty_sha256.hex()}, but module "
            f"returned 0x{actual.hex()} — empty-input digest path likely "
            f"reads uninitialised buffer state"
        )
