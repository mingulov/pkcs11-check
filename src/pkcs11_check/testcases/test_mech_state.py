"""Operation state machine violation tests.

Tests verify that the module correctly enforces PKCS#11 operation state:
- C_Encrypt (and variants) without prior C_EncryptInit -> CKR_OPERATION_NOT_INITIALIZED
- C_EncryptInit while another operation is active -> CKR_OPERATION_ACTIVE
- C_Sign, C_Verify, C_Digest: same patterns
- C_DecryptFinal without C_DecryptInit -> CKR_OPERATION_NOT_INITIALIZED

Source: PKCS#11 v3.2 -- each function description lists
CKR_OPERATION_NOT_INITIALIZED and CKR_OPERATION_ACTIVE as valid return values.

These tests are NOT parametrized -- they use hard-coded AES and SHA-256 mechanisms
which are widely supported.  Mechanism-specific state tests belong in the
mechanism-specific test files.
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import NoReturn

import pytest

from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    import_secret_key,
    to_ubyte_buf,
)
from pkcs11_check.raw.rv import ckr_name, expect_rv, is_standard_ckr, is_vendor_defined_ckr
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
from pkcs11_check.testcases.conftest import (
    assert_correct,
    classify_negative_rv,
    gen_aes_key_or_xfail,
    skip_unless_create_object_supported,
    xfail_if_known_ckr,
)

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.state_machine]


# Single-session operation-state guards (op-without-init, double-init) are
# classified 3-way via classify_negative_rv: CKR_OK -> fail, the spec-preferred
# code -> pass, any other clean reject (e.g. CKR_FUNCTION_FAILED, widely seen but
# non-spec-compliant) -> xfail.

# Strict subset for cross-session-state-confusion tests. CKR_FUNCTION_FAILED /
# CKR_GENERAL_ERROR are EXPLICITLY NOT accepted here: a module that crashes or
# panics during cross-session probing and recovers with one of those codes is
# exhibiting exactly the state-confusion bug class the test is meant to catch.
# If a real module legitimately needs a different clean code here, the 3-way
# negative classifier records it as an xfail (a noted deviation) -- never widen
# this set to mask it.
_CROSS_SESSION_NOT_INIT_RVCS: frozenset[int] = frozenset(
    {
        CKR_OPERATION_NOT_INITIALIZED,
        CKR_SESSION_HANDLE_INVALID,  # some modules return this if they
        # keyed the operation table on the
        # wrong handle
    }
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

_EMPTY_SHA256 = bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")


def _classify_positive_rejection(
    rv: int, *, label: str, operation: str, mechanism: str
) -> NoReturn:
    """Classify a nonzero CK_RV from a positive zero-data Init/Final call.

    Any defined standard/vendor clean rejection (including the real
    CKR_BUFFER_TOO_SMALL 0x150, CKR_KEY_TYPE_INCONSISTENT 0x63, and
    CKR_DATA_LEN_RANGE) is adverse ``not_operational`` xfail with the exact
    RV. An undefined RV is metadata ``self_contradiction`` fail.
    """
    if is_standard_ckr(rv) or is_vendor_defined_ckr(rv):
        xfail_as(
            "not_operational",
            label=label,
            operation=operation,
            mechanism=mechanism,
            expected=CKR_OK,
            actual=rv,
            summary=(
                f"{label}: advertised {operation} is not operational; rejected with {ckr_name(rv)}"
            ),
        )
    fail_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation=operation,
        mechanism=mechanism,
        expected=CKR_OK,
        actual=rv,
        summary=f"{label}: {operation} returned undefined CK_RV {ckr_name(rv)}",
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
        classify_negative_rv(
            rv,
            (CKR_OPERATION_NOT_INITIALIZED,),
            label="C_Encrypt without prior C_EncryptInit",
        )

    def test_encrypt_final_without_init(self, p11_raw_session: RawSession) -> None:
        """C_EncryptFinal without init must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        out_buf = (ctypes.c_ubyte * 32)()
        out_len = CK_ULONG(32)
        rv = rs.raw.C_EncryptFinal(rs.sh, out_buf, byref(out_len))
        classify_negative_rv(
            rv,
            (CKR_OPERATION_NOT_INITIALIZED,),
            label="C_EncryptFinal without prior C_EncryptInit",
        )

    def test_double_encrypt_init(self, p11_raw_session: RawSession) -> None:
        """C_EncryptInit twice -> second call must return CKR_OPERATION_ACTIVE."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("AES keygen not supported")

        key = gen_aes_key_or_xfail(rs, 256)
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv1 = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            if rv1 != CKR_OK:
                pytest.skip(f"First C_EncryptInit failed: 0x{rv1:08x}")

            # Second init while operation is active
            mech2 = mech_simple(CKM_AES_ECB)
            rv2 = rs.raw.C_EncryptInit(rs.sh, mech2.byref(), key)
            classify_negative_rv(
                rv2,
                (CKR_OPERATION_ACTIVE,),
                label="second C_EncryptInit while an encrypt operation is active",
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
        classify_negative_rv(
            rv,
            (CKR_OPERATION_NOT_INITIALIZED,),
            label="C_Decrypt without prior C_DecryptInit",
        )

    def test_decrypt_final_without_init(self, p11_raw_session: RawSession) -> None:
        """C_DecryptFinal without init must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        out_buf = (ctypes.c_ubyte * 32)()
        out_len = CK_ULONG(32)
        rv = rs.raw.C_DecryptFinal(rs.sh, out_buf, byref(out_len))
        classify_negative_rv(
            rv,
            (CKR_OPERATION_NOT_INITIALIZED,),
            label="C_DecryptFinal without prior C_DecryptInit",
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
        classify_negative_rv(
            rv,
            (CKR_OPERATION_NOT_INITIALIZED,),
            label="C_Sign without prior C_SignInit",
        )

    def test_sign_update_without_init(self, p11_raw_session: RawSession) -> None:
        """C_SignUpdate without prior C_SignInit must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session

        data = b"\xdd" * 8
        in_buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        rv = rs.raw.C_SignUpdate(rs.sh, in_buf, len(data))
        classify_negative_rv(
            rv,
            (CKR_OPERATION_NOT_INITIALIZED,),
            label="C_SignUpdate without prior C_SignInit",
        )

    def test_sign_final_without_init(self, p11_raw_session: RawSession) -> None:
        """C_SignFinal without prior C_SignInit must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session

        sig_buf = (ctypes.c_ubyte * 256)()
        sig_len = CK_ULONG(256)
        rv = rs.raw.C_SignFinal(rs.sh, sig_buf, byref(sig_len))
        classify_negative_rv(
            rv,
            (CKR_OPERATION_NOT_INITIALIZED,),
            label="C_SignFinal without prior C_SignInit",
        )

    def test_sign_single_part_output_call_terminates(self, p11_raw_session: RawSession) -> None:
        """Successful two-call C_Sign must terminate before a new C_SignInit."""
        rs = p11_raw_session
        skip_unless_create_object_supported(rs)
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
        classify_negative_rv(
            rv,
            (
                CKR_OPERATION_NOT_INITIALIZED,
                CKR_SIGNATURE_INVALID,
                CKR_SIGNATURE_LEN_RANGE,
            ),
            label="C_Verify without prior C_VerifyInit",
        )

    def test_verify_update_without_init(self, p11_raw_session: RawSession) -> None:
        """C_VerifyUpdate without prior C_VerifyInit must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session

        data = b"\x01" * 8
        in_buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        rv = rs.raw.C_VerifyUpdate(rs.sh, in_buf, len(data))
        classify_negative_rv(
            rv,
            (CKR_OPERATION_NOT_INITIALIZED,),
            label="C_VerifyUpdate without prior C_VerifyInit",
        )

    def test_verify_final_without_init(self, p11_raw_session: RawSession) -> None:
        """C_VerifyFinal without prior C_VerifyInit must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session

        sig = b"\x02" * 64
        sig_buf = (ctypes.c_ubyte * len(sig)).from_buffer_copy(sig)
        rv = rs.raw.C_VerifyFinal(rs.sh, sig_buf, len(sig))
        classify_negative_rv(
            rv,
            (
                CKR_OPERATION_NOT_INITIALIZED,
                CKR_SIGNATURE_INVALID,
                CKR_SIGNATURE_LEN_RANGE,
            ),
            label="C_VerifyFinal without prior C_VerifyInit",
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
        classify_negative_rv(
            rv,
            (CKR_OPERATION_NOT_INITIALIZED,),
            label="C_Digest without prior C_DigestInit",
        )

    def test_digest_update_without_init(self, p11_raw_session: RawSession) -> None:
        """C_DigestUpdate without prior C_DigestInit must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")

        data = b"\x04" * 8
        in_buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        rv = rs.raw.C_DigestUpdate(rs.sh, in_buf, len(data))
        classify_negative_rv(
            rv,
            (CKR_OPERATION_NOT_INITIALIZED,),
            label="C_DigestUpdate without prior C_DigestInit",
        )

    def test_digest_final_without_init(self, p11_raw_session: RawSession) -> None:
        """C_DigestFinal without prior C_DigestInit must return CKR_OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")

        out_buf = (ctypes.c_ubyte * 64)()
        out_len = CK_ULONG(64)
        rv = rs.raw.C_DigestFinal(rs.sh, out_buf, byref(out_len))
        classify_negative_rv(
            rv,
            (CKR_OPERATION_NOT_INITIALIZED,),
            label="C_DigestFinal without prior C_DigestInit",
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
        classify_negative_rv(
            rv2,
            (CKR_OPERATION_ACTIVE,),
            label="second C_DigestInit while a digest operation is active",
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
    per the spec (PKCS#11 v3.2).
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

        key = gen_aes_key_or_xfail(rs, 256)
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
        """EncryptInit then EncryptFinal with no Update — zero input, zero output."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        key = gen_aes_key_or_xfail(rs, 256)
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv1 = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            if rv1 != CKR_OK:
                _classify_positive_rejection(
                    rv1,
                    label="C_EncryptInit:zero-data encrypt setup",
                    operation="C_EncryptInit",
                    mechanism="CKM_AES_ECB",
                )

            # Supplied 64-byte non-NULL buffer pre-filled with a canary: this
            # is NOT a length query. ECB has no padding so 0 input -> 0 output
            # is the only correct CKR_OK answer, and the buffer must be
            # untouched. A module that reports bytes or scribbles on the caller
            # buffer has a zero-input memory-corruption bug.
            canary = bytes([0xA5]) * 64
            out_buf = (ctypes.c_ubyte * 64).from_buffer_copy(canary)
            out_len = CK_ULONG(64)
            rv = rs.raw.C_EncryptFinal(rs.sh, out_buf, byref(out_len))
            if rv != CKR_OK:
                _classify_positive_rejection(
                    rv,
                    label="C_EncryptFinal:zero-data encrypt final",
                    operation="C_EncryptFinal",
                    mechanism="CKM_AES_ECB",
                )
            if out_len.value != 0:
                fail_as(
                    "wrong_result",
                    kind="crypto",
                    label="C_EncryptFinal:zero-data encrypt final",
                    operation="C_EncryptFinal",
                    mechanism="CKM_AES_ECB",
                    summary=(
                        "C_EncryptFinal:zero-data encrypt final: CKR_OK with "
                        f"{out_len.value} output bytes for zero input; expected "
                        "exactly 0 (ECB has no padding)"
                    ),
                )
            if bytes(out_buf) != canary:
                fail_as(
                    "self_contradiction",
                    kind="lifecycle",
                    label="C_EncryptFinal:zero-data encrypt final",
                    operation="C_EncryptFinal",
                    mechanism="CKM_AES_ECB",
                    summary=(
                        "C_EncryptFinal:zero-data encrypt final: CKR_OK with "
                        "zero output length but the caller buffer was mutated"
                    ),
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
            _classify_positive_rejection(
                rv1,
                label="C_DigestInit:zero-data digest setup",
                operation="C_DigestInit",
                mechanism="CKM_SHA256",
            )

        out_buf = (ctypes.c_ubyte * 64)()
        out_len = CK_ULONG(64)
        rv = rs.raw.C_DigestFinal(rs.sh, out_buf, byref(out_len))
        if rv != CKR_OK:
            _classify_positive_rejection(
                rv,
                label="C_DigestFinal:zero-data digest final",
                operation="C_DigestFinal",
                mechanism="CKM_SHA256",
            )

        if out_len.value != 32:
            fail_as(
                "wrong_result",
                kind="crypto",
                label="C_DigestFinal:zero-data digest final",
                operation="C_DigestFinal",
                mechanism="CKM_SHA256",
                summary=(
                    "C_DigestFinal:zero-data digest final: CKR_OK with output "
                    f"length {out_len.value}; expected exactly 32"
                ),
            )
        assert_correct(
            actual=bytes(out_buf[: out_len.value]),
            expected=_EMPTY_SHA256,
            label="C_DigestFinal:zero-data digest final",
            operation="C_DigestFinal",
            mechanism="CKM_SHA256",
        )
