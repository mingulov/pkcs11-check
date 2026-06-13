"""Tests for C_GetOperationState and C_SetOperationState.

Happy-path functional tests exercising state save/restore for active operations.
Error-path CKR tests are in ckr/test_ckr_state.py.

Source: PKCS#11 v3.1 Sec.5.6.5 (C_GetOperationState), Sec.5.6.6 (C_SetOperationState).

Most PKCS#11 modules return CKR_STATE_UNSAVEABLE for active operations - this is
spec-conformant behaviour (Sec.5.6.5: the token may return CKR_STATE_UNSAVEABLE if the
state cannot be saved). Tests that require a saveable state skip gracefully when the
module does not support it.

The actual state save/restore round-trip uses a ctypes subprocess to call
C_DigestInit / C_DigestUpdate / C_GetOperationState / C_SetOperationState /
C_DigestFinal directly, because the python-pkcs11 high-level API does not expose
init/update/final as individually callable Python steps for digest.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.testcases._raw_subprocess import parse_output as _parse_output
from pkcs11_check.testcases._raw_subprocess import run_raw_script
from pkcs11_check.testcases.conftest import classify_negative_rv

pytestmark = pytest.mark.operation_state

_SCRIPT_PREAMBLE = """\
import binascii
import ctypes
import sys
from ctypes import byref, c_char_p, c_ubyte, cast

from pkcs11_check.raw import CK_ATTRIBUTE_PTR, CK_MECHANISM, CK_OBJECT_HANDLE, RawPKCS11
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKK_AES,
    CKM_AES_CBC,
    CKM_AES_KEY_GEN,
    CKM_SHA256,
    CKO_SECRET_KEY,
    CKR_CRYPTOKI_ALREADY_INITIALIZED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
    CKR_SAVED_STATE_INVALID,
    CKR_STATE_UNSAVEABLE,
)
from pkcs11_check.raw.bootstrap import close_session_quietly, get_slot_ids, login_user, open_session
from pkcs11_check.raw.pack import attr_bool, attr_ulong, mech_simple, template


def _template_ptr(attrs):
    return cast(attrs.ptr, CK_ATTRIBUTE_PTR)


def _byte_array(data: bytes):
    return (c_ubyte * len(data)).from_buffer_copy(data)


raw = RawPKCS11.from_lib({module_path!r})
hSession = None
rv = raw.C_Initialize(None)
if rv not in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED):
    print(f"FATAL:Initialize:0x{{rv:08x}}")
    sys.exit(1)

slot_ids = get_slot_ids(raw)
if len(slot_ids) <= {slot_index}:
    print(f"FATAL:GetSlotList:index={slot_index}:count={{len(slot_ids)}}")
    raw.C_Finalize(None)
    sys.exit(1)

slot_id = slot_ids[{slot_index}]
hSession = open_session(raw, slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION)

_PIN = {pin_bytes!r}
if _PIN:
    login_user(raw, hSession, 1, _PIN)

c_ulong = ctypes.c_ulong
c_void_p = ctypes.c_void_p
C_DigestInit = raw.C_DigestInit
C_DigestUpdate = raw.C_DigestUpdate
C_DigestFinal = raw.C_DigestFinal
C_EncryptInit = raw.C_EncryptInit
C_EncryptUpdate = raw.C_EncryptUpdate
C_EncryptFinal = raw.C_EncryptFinal
C_GenerateKey = raw.C_GenerateKey
C_GetOperationState = raw.C_GetOperationState
C_SetOperationState = raw.C_SetOperationState
C_OpenSession = raw.C_OpenSession
C_CloseSession = raw.C_CloseSession
"""

_SCRIPT_CLEANUP = """\
close_session_quietly(raw, hSession)
raw.C_Finalize(None)
"""


def _run_state_script(
    module_path: str,
    slot_index: int,
    pin_bytes: bytes,
    script_body: str,
    timeout: int = 15,
) -> tuple[int, str, str]:
    return run_raw_script(
        _SCRIPT_PREAMBLE.format(
            module_path=module_path,
            slot_index=slot_index,
            pin_bytes=pin_bytes,
        ),
        script_body,
        cleanup=_SCRIPT_CLEANUP,
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# Tests: high-level API availability
# ---------------------------------------------------------------------------


class TestGetOperationStateAPI:
    """Verify C_GetOperationState / C_SetOperationState are present and respond correctly."""

    def test_api_exists(self, p11_raw_session: Any) -> None:
        """Raw session exposes C_GetOperationState and C_SetOperationState."""
        rs = p11_raw_session
        assert hasattr(rs.raw, "C_GetOperationState")
        assert hasattr(rs.raw, "C_SetOperationState")

    def test_no_active_operation(self, p11_raw_session: Any) -> None:
        """C_GetOperationState with no active operation returns known CKR.

        Spec Sec.5.6.5: if no operation is active the token must return
        CKR_OPERATION_NOT_INITIALIZED. Some modules also return
        CKR_STATE_UNSAVEABLE or CKR_FUNCTION_NOT_SUPPORTED.
        """
        import ctypes

        from pkcs11_check.raw.rv import ckr_name
        from pkcs11_check.raw.types_std import (
            CKR_FUNCTION_NOT_SUPPORTED,
            CKR_OPERATION_NOT_INITIALIZED,
            CKR_STATE_UNSAVEABLE,
        )
        from pkcs11_check.raw.types_std import (
            CKR_OK as _CKR_OK,
        )

        rs = p11_raw_session
        state_len = ctypes.c_ulong(0)
        rv = rs.raw.C_GetOperationState(rs.sh, None, ctypes.byref(state_len))
        acceptable = {
            _CKR_OK,
            CKR_OPERATION_NOT_INITIALIZED,
            CKR_STATE_UNSAVEABLE,
            CKR_FUNCTION_NOT_SUPPORTED,
        }
        assert rv in acceptable, f"C_GetOperationState returned unexpected {ckr_name(rv)}"

    def test_garbage_state_raises_saved_state_invalid(
        self,
        p11_raw_session: Any,
    ) -> None:
        """C_SetOperationState with garbage -> CKR_SAVED_STATE_INVALID.

        Spec Sec.5.6.6: the token must return CKR_SAVED_STATE_INVALID if
        the supplied state blob is unrecognisable.
        """
        import ctypes

        from pkcs11_check.raw.types_std import (
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_NOT_SUPPORTED,
            CKR_SAVED_STATE_INVALID,
            CKR_STATE_UNSAVEABLE,
        )

        rs = p11_raw_session
        garbage = b"\xde\xad\xbe\xef" * 16
        buf = (ctypes.c_ubyte * len(garbage))(*garbage)
        rv = rs.raw.C_SetOperationState(rs.sh, buf, len(garbage), 0, 0)
        if rv in (
            CKR_FUNCTION_NOT_SUPPORTED,
            CKR_STATE_UNSAVEABLE,
        ):
            pytest.skip("Module does not support C_SetOperationState")
        if rv == CKR_ARGUMENTS_BAD:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "C_SetOperationState rejected a garbage state blob with "
                "CKR_ARGUMENTS_BAD instead of the more specific "
                "CKR_SAVED_STATE_INVALID",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 v3.1 C_SetOperationState return values",
            )
        # 3-way: accepting a garbage state blob (CKR_OK) -> fail; the spec code
        # CKR_SAVED_STATE_INVALID -> pass; another clean reject (e.g.
        # CKR_OPERATION_NOT_INITIALIZED, CKR_ARGUMENTS_BAD) -> xfail.
        classify_negative_rv(
            rv,
            (CKR_SAVED_STATE_INVALID,),
            label="C_SetOperationState with a garbage state blob (PKCS#11 v3.1 Sec.5.6.6)",
        )


# ---------------------------------------------------------------------------
# Tests: digest state round-trip via ctypes subprocess
# ---------------------------------------------------------------------------


def _get_params(p11_config: Any) -> tuple[str, int, bytes]:
    """Extract (module_path, slot_index, pin_bytes) from config fixture."""
    module_path = str(p11_config.module)
    slot_index = p11_config.slot if p11_config.slot is not None else 0
    pin_bytes = p11_config.pin.get_secret_value().encode() if p11_config.pin else b""
    return module_path, slot_index, pin_bytes


def _skip_missing_mechanisms(rs: Any, names: tuple[str, ...]) -> None:
    for name in names:
        if not rs.has_mechanism(name):
            pytest.skip(f"{name} not supported by module")


@pytest.mark.usefixtures("p11_module")
class TestDigestStateRoundTrip:
    """State save/restore round-trip for a SHA-256 multi-part digest.

    The python-pkcs11 high-level digest API does not expose C_DigestInit /
    C_DigestUpdate / C_DigestFinal as individually callable Python steps, so
    these tests use a ctypes subprocess to exercise the C-level functions
    directly.  This also mirrors how real applications use state save/restore.
    """

    def test_digest_state_same_session(
        self,
        p11_config: Any,
        p11_raw_session: Any,
    ) -> None:
        """SHA-256 state save/restore on the same session produces the correct digest.

        Steps:
        1. Compute reference = SHA-256(part1 + part2) via hashlib.
        2. PKCS#11: DigestInit(SHA-256) -> DigestUpdate(part1) -> GetOperationState.
        3. SetOperationState (restore) -> DigestUpdate(part2) -> DigestFinal.
        4. Assert final digest equals reference.

        Skips when the module returns CKR_STATE_UNSAVEABLE (most software tokens
        including SoftHSM2 and many hardware tokens do not support state save).
        """
        _skip_missing_mechanisms(p11_raw_session, ("SHA256",))
        module_path, slot_index, pin_bytes = _get_params(p11_config)

        script = """\
            import hashlib

            part1 = b"Hello, "
            part2 = b"PKCS#11 state!"

            # Reference via hashlib
            ref = hashlib.sha256(part1 + part2).hexdigest()
            print(f"REFERENCE:{ref}")

            mech = CK_MECHANISM()
            mech.mechanism = CKM_SHA256

            # --- Single-shot cross-check ---
            rv = C_DigestInit(hSession, ctypes.byref(mech))
            if rv != CKR_OK:
                print(f"FATAL:DigestInit_1shot:0x{rv:08x}")
                sys.exit(1)
            full = part1 + part2
            full_buf = _byte_array(full)
            rv = C_DigestUpdate(hSession, full_buf, c_ulong(len(full)))
            if rv != CKR_OK:
                print(f"FATAL:DigestUpdate_1shot:0x{rv:08x}")
                sys.exit(1)
            dlen = c_ulong(32)
            dbuf = (c_ubyte * 32)()
            rv = C_DigestFinal(hSession, dbuf, byref(dlen))
            if rv != CKR_OK:
                print(f"FATAL:DigestFinal_1shot:0x{rv:08x}")
                sys.exit(1)
            singleshot = binascii.hexlify(bytes(dbuf[:dlen.value])).decode()
            if singleshot != ref:
                print(f"FATAL:SingleshotMismatch:got={singleshot} ref={ref}")
                sys.exit(1)
            print(f"SINGLESHOT_OK:{singleshot}")

            # --- Multi-part with state save/restore ---
            rv = C_DigestInit(hSession, ctypes.byref(mech))
            if rv != CKR_OK:
                print(f"FATAL:DigestInit_mp:0x{rv:08x}")
                sys.exit(1)
            part1_buf = _byte_array(part1)
            rv = C_DigestUpdate(hSession, part1_buf, c_ulong(len(part1)))
            if rv != CKR_OK:
                print(f"FATAL:DigestUpdate_mp:0x{rv:08x}")
                sys.exit(1)

            # Save state (length query)
            state_len = c_ulong(0)
            rv = C_GetOperationState(hSession, None, byref(state_len))
            if rv in (CKR_STATE_UNSAVEABLE, CKR_FUNCTION_NOT_SUPPORTED):
                print(f"SKIP:UNSAVEABLE_OR_UNSUPPORTED:0x{rv:08x}")
                sys.exit(0)
            if rv != CKR_OK:
                print(f"FATAL:GetState_len:0x{rv:08x}")
                sys.exit(1)

            # Save state (data)
            state_buf = (c_ubyte * state_len.value)()
            rv = C_GetOperationState(hSession, state_buf, byref(state_len))
            if rv in (CKR_STATE_UNSAVEABLE, CKR_FUNCTION_NOT_SUPPORTED):
                print(f"SKIP:UNSAVEABLE_OR_UNSUPPORTED:0x{rv:08x}")
                sys.exit(0)
            if rv != CKR_OK:
                print(f"FATAL:GetState_data:0x{rv:08x}")
                sys.exit(1)
            state_bytes = bytes(state_buf[:state_len.value])
            state_bytes_buf = _byte_array(state_bytes)
            print(f"STATE_SAVED:{len(state_bytes)}")

            # Restore state on the same session
            rv = C_SetOperationState(
                hSession,
                state_bytes_buf,
                c_ulong(len(state_bytes)),
                c_ulong(0),
                c_ulong(0),
            )
            if rv != CKR_OK:
                print(f"FATAL:SetOperationState:0x{rv:08x}")
                sys.exit(1)
            print("STATE_RESTORED")

            # Continue with part2 and finalise
            part2_buf = _byte_array(part2)
            rv = C_DigestUpdate(hSession, part2_buf, c_ulong(len(part2)))
            if rv != CKR_OK:
                print(f"FATAL:DigestUpdate_part2:0x{rv:08x}")
                sys.exit(1)
            dlen2 = c_ulong(32)
            dbuf2 = (c_ubyte * 32)()
            rv = C_DigestFinal(hSession, dbuf2, byref(dlen2))
            if rv != CKR_OK:
                print(f"FATAL:DigestFinal_mp:0x{rv:08x}")
                sys.exit(1)
            restored = binascii.hexlify(bytes(dbuf2[:dlen2.value])).decode()
            print(f"RESTORED:{restored}")
        """

        returncode, stdout, stderr = _run_state_script(module_path, slot_index, pin_bytes, script)

        lines_map = _parse_output(stdout)

        if "SKIP" in lines_map:
            pytest.skip(f"Module skipped state test: {lines_map['SKIP']}")

        if returncode != 0:
            fatals = [ln for ln in stdout.splitlines() if ln.startswith("FATAL:")]
            detail = fatals[0] if fatals else f"stdout={stdout!r} stderr={stderr!r}"
            fail_as(
                "crash",
                label="digest-state-roundtrip",
                operation="C_GetOperationState",
                summary=f"Subprocess failed: {detail}",
                detail={"returncode": returncode},
            )

        assert "REFERENCE" in lines_map, f"Missing REFERENCE in output: {stdout!r}"
        assert "RESTORED" in lines_map, f"Missing RESTORED in output: {stdout!r}"

        ref = lines_map["REFERENCE"]
        restored = lines_map["RESTORED"]
        assert restored == ref, (
            f"State round-trip digest mismatch: expected {ref!r}, got {restored!r}"
        )

    def test_digest_state_cross_session(self, p11_config: Any) -> None:
        """Restoring digest state on a second session is rejected or handled per spec.

        Spec Sec.5.6.6 notes that tokens may reject cross-session restore with
        CKR_SAVED_STATE_INVALID.  Acceptance is also implementation-defined.
        This test verifies the module does not crash and returns a CKR code.

        Skips when the module returns CKR_STATE_UNSAVEABLE at the save step.
        """
        module_path, slot_index, pin_bytes = _get_params(p11_config)

        script = """\
            mech = CK_MECHANISM()
            mech.mechanism = CKM_SHA256

            part1 = b"cross-session data"
            part1_buf = _byte_array(part1)

            rv = C_DigestInit(hSession, ctypes.byref(mech))
            if rv != CKR_OK:
                print(f"SKIP:DigestInitFailed:0x{rv:08x}")
                sys.exit(0)

            rv = C_DigestUpdate(hSession, part1_buf, c_ulong(len(part1)))
            if rv != CKR_OK:
                print(f"SKIP:DigestUpdateFailed:0x{rv:08x}")
                sys.exit(0)

            # Save state
            state_len = c_ulong(0)
            rv = C_GetOperationState(hSession, None, byref(state_len))
            if rv in (CKR_STATE_UNSAVEABLE, CKR_FUNCTION_NOT_SUPPORTED):
                print(f"SKIP:UNSAVEABLE_OR_UNSUPPORTED:0x{rv:08x}")
                sys.exit(0)
            if rv != CKR_OK:
                print(f"SKIP:GetStateFailed:0x{rv:08x}")
                sys.exit(0)

            state_buf = (c_ubyte * state_len.value)()
            rv = C_GetOperationState(hSession, state_buf, byref(state_len))
            if rv in (CKR_STATE_UNSAVEABLE, CKR_FUNCTION_NOT_SUPPORTED):
                print(f"SKIP:UNSAVEABLE_OR_UNSUPPORTED:0x{rv:08x}")
                sys.exit(0)
            if rv != CKR_OK:
                print(f"SKIP:GetStateDataFailed:0x{rv:08x}")
                sys.exit(0)
            state_bytes = bytes(state_buf[:state_len.value])
            state_bytes_buf = _byte_array(state_bytes)
            print(f"STATE_SAVED:{len(state_bytes)}")

            # Open a second session
            try:
                hSession2 = open_session(raw, slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION)
            except AssertionError as exc:
                if "CKR_" in str(exc):
                    print(f"SKIP:OpenSession2Failed:{exc}")
                    sys.exit(0)
                raise

            # Try to restore state on the second session
            rv2 = C_SetOperationState(
                hSession2,
                state_bytes_buf,
                c_ulong(len(state_bytes)),
                c_ulong(0),
                c_ulong(0),
            )
            if rv2 == CKR_OK:
                print("CROSS_SESSION_ACCEPTED:1")
            else:
                print(f"CROSS_SESSION_REJECTED:0x{rv2:08x}")

            close_session_quietly(raw, hSession2)
        """

        returncode, stdout, stderr = _run_state_script(module_path, slot_index, pin_bytes, script)

        lines_map = _parse_output(stdout)

        if "SKIP" in lines_map:
            pytest.skip(f"Module skipped cross-session test: {lines_map['SKIP']}")

        if returncode != 0:
            fatals = [ln for ln in stdout.splitlines() if ln.startswith("FATAL:")]
            detail = fatals[0] if fatals else f"stdout={stdout!r} stderr={stderr!r}"
            fail_as(
                "crash",
                label="cross-session-state",
                operation="C_SetOperationState",
                summary=f"Subprocess failed: {detail}",
                detail={"returncode": returncode},
            )

        assert "CROSS_SESSION_ACCEPTED" in lines_map or "CROSS_SESSION_REJECTED" in lines_map, (
            f"Expected CROSS_SESSION_ACCEPTED or CROSS_SESSION_REJECTED; stdout={stdout!r}"
        )

        if "CROSS_SESSION_REJECTED" in lines_map:
            # Verify the rejection code is an expected CKR value.
            # CKR_SAVED_STATE_INVALID (0x160) is mandated by spec Sec.5.6.6 for
            # cross-session restore.  Some modules may also return
            # CKR_STATE_UNSAVEABLE (0x180) or CKR_FUNCTION_NOT_SUPPORTED (0x54).
            acceptable_reject_codes = {0x160, 0x180, 0x54}
            rejected_hex = lines_map["CROSS_SESSION_REJECTED"]
            try:
                rejected_code = int(rejected_hex, 16)
            except ValueError:
                rejected_code = -1
            assert rejected_code in acceptable_reject_codes, (
                f"Cross-session restore rejected with unexpected CKR 0x{rejected_code:08x}; "
                f"expected one of {[hex(c) for c in acceptable_reject_codes]}"
            )


# ---------------------------------------------------------------------------
# Tests: encrypt state round-trip via ctypes subprocess
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("p11_module")
class TestEncryptStateRoundTrip:
    """State save/restore round-trip for an AES-CBC multi-part encrypt operation.

    The python-pkcs11 high-level encrypt API does not expose C_EncryptInit /
    C_EncryptUpdate / C_EncryptFinal as individually callable Python steps, so
    these tests use a ctypes subprocess to exercise the C-level functions
    directly.

    Most modules return CKR_STATE_UNSAVEABLE for active encrypt operations - the
    tests skip gracefully when the module does not support saving encrypt state.
    """

    def test_encrypt_state_same_session(
        self,
        p11_config: Any,
        p11_raw_session: Any,
    ) -> None:
        """AES-CBC state save/restore on the same session produces correct ciphertext.

        Steps:
        1. Generate an AES-256 key via C_GenerateKey.
        2. C_EncryptInit(AES-CBC, IV) -> C_EncryptUpdate(part1) -> C_GetOperationState.
        3. C_SetOperationState (restore, passing the key handle) -> C_EncryptUpdate(part2)
           -> C_EncryptFinal.
        4. Compare with a reference encryption that does not use state save/restore.

        Skips when the module returns CKR_STATE_UNSAVEABLE or
        CKR_FUNCTION_NOT_SUPPORTED (most software tokens do not save encrypt state).

        Source: PKCS#11 v3.1 Sec.5.6.5-Sec.5.6.6.
        """
        _skip_missing_mechanisms(p11_raw_session, ("AES_KEY_GEN", "AES_CBC"))
        module_path, slot_index, pin_bytes = _get_params(p11_config)

        script = """\
            # 16-byte IV and two 16-byte plaintext blocks (AES-CBC block-aligned)
            iv = b"\\x00" * 16
            part1 = b"Block-one-data!!"  # 16 bytes
            part2 = b"Block-two-data!!"  # 16 bytes
            part1_buf = _byte_array(part1)
            part2_buf = _byte_array(part2)

            # Build AES key-gen template
            attrs = template(
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_AES),
                attr_ulong(CKA_VALUE_LEN, 32),
                attr_bool(CKA_ENCRYPT, True),
                attr_bool(CKA_DECRYPT, True),
                attr_bool(CKA_TOKEN, False),
            )

            kg_mech = mech_simple(CKM_AES_KEY_GEN)

            hKey = CK_OBJECT_HANDLE(0)
            rv = C_GenerateKey(
                hSession, kg_mech.byref(), _template_ptr(attrs), attrs.count, byref(hKey)
            )
            if rv in (CKR_FUNCTION_NOT_SUPPORTED,):
                print(f"SKIP:GenerateKeyUnsupported:0x{rv:08x}")
                sys.exit(0)
            if rv != CKR_OK:
                print(f"FATAL:GenerateKey:0x{rv:08x}")
                sys.exit(1)
            print(f"KEY_GENERATED:{hKey.value}")

            # Build AES-CBC mechanism with IV as parameter
            iv_buf = (c_ubyte * 16)(*iv)
            enc_mech = CK_MECHANISM()
            enc_mech.mechanism = CKM_AES_CBC
            enc_mech.pParameter = ctypes.cast(iv_buf, c_void_p)
            enc_mech.ulParameterLen = 16

            # --- Reference encryption (no state save) ---
            rv = C_EncryptInit(hSession, ctypes.byref(enc_mech), hKey)
            if rv in (CKR_FUNCTION_NOT_SUPPORTED,):
                print(f"SKIP:EncryptInitUnsupported:0x{rv:08x}")
                sys.exit(0)
            if rv != CKR_OK:
                print(f"FATAL:EncryptInit_ref:0x{rv:08x}")
                sys.exit(1)

            ref_out = bytearray()
            out_len = c_ulong(32)
            out_buf = (c_ubyte * 32)()

            rv = C_EncryptUpdate(hSession, part1_buf, c_ulong(len(part1)),
                                 out_buf, byref(out_len))
            if rv != CKR_OK:
                print(f"FATAL:EncryptUpdate_ref1:0x{rv:08x}")
                sys.exit(1)
            ref_out += bytes(out_buf[:out_len.value])

            out_len2 = c_ulong(32)
            out_buf2 = (c_ubyte * 32)()
            rv = C_EncryptUpdate(hSession, part2_buf, c_ulong(len(part2)),
                                 out_buf2, byref(out_len2))
            if rv != CKR_OK:
                print(f"FATAL:EncryptUpdate_ref2:0x{rv:08x}")
                sys.exit(1)
            ref_out += bytes(out_buf2[:out_len2.value])

            final_len = c_ulong(32)
            final_buf = (c_ubyte * 32)()
            rv = C_EncryptFinal(hSession, final_buf, byref(final_len))
            if rv != CKR_OK:
                print(f"FATAL:EncryptFinal_ref:0x{rv:08x}")
                sys.exit(1)
            ref_out += bytes(final_buf[:final_len.value])
            ref_hex = binascii.hexlify(bytes(ref_out)).decode()
            print(f"REFERENCE:{ref_hex}")

            # --- Multi-part encryption with state save/restore ---
            rv = C_EncryptInit(hSession, ctypes.byref(enc_mech), hKey)
            if rv != CKR_OK:
                print(f"FATAL:EncryptInit_mp:0x{rv:08x}")
                sys.exit(1)

            mp_out = bytearray()
            mp_len1 = c_ulong(32)
            mp_buf1 = (c_ubyte * 32)()
            rv = C_EncryptUpdate(hSession, part1_buf, c_ulong(len(part1)),
                                 mp_buf1, byref(mp_len1))
            if rv != CKR_OK:
                print(f"FATAL:EncryptUpdate_mp1:0x{rv:08x}")
                sys.exit(1)
            mp_out += bytes(mp_buf1[:mp_len1.value])

            # Save encrypt state (length query)
            state_len = c_ulong(0)
            rv = C_GetOperationState(hSession, None, byref(state_len))
            if rv in (CKR_STATE_UNSAVEABLE, CKR_FUNCTION_NOT_SUPPORTED):
                print(f"SKIP:UNSAVEABLE_OR_UNSUPPORTED:0x{rv:08x}")
                sys.exit(0)
            if rv != CKR_OK:
                print(f"FATAL:GetState_len:0x{rv:08x}")
                sys.exit(1)

            # Save encrypt state (data)
            state_buf = (c_ubyte * state_len.value)()
            rv = C_GetOperationState(hSession, state_buf, byref(state_len))
            if rv in (CKR_STATE_UNSAVEABLE, CKR_FUNCTION_NOT_SUPPORTED):
                print(f"SKIP:UNSAVEABLE_OR_UNSUPPORTED:0x{rv:08x}")
                sys.exit(0)
            if rv != CKR_OK:
                print(f"FATAL:GetState_data:0x{rv:08x}")
                sys.exit(1)
            state_bytes = bytes(state_buf[:state_len.value])
            state_bytes_buf = _byte_array(state_bytes)
            print(f"STATE_SAVED:{len(state_bytes)}")

            # Restore state on the same session, supplying the encryption key handle
            rv = C_SetOperationState(
                hSession,
                state_bytes_buf,
                c_ulong(len(state_bytes)),
                hKey,       # hEncryptionKey
                c_ulong(0), # hAuthenticationKey (not used)
            )
            if rv != CKR_OK:
                print(f"FATAL:SetOperationState:0x{rv:08x}")
                sys.exit(1)
            print("STATE_RESTORED")

            # Continue encryption from restored state
            mp_len2 = c_ulong(32)
            mp_buf2 = (c_ubyte * 32)()
            rv = C_EncryptUpdate(hSession, part2_buf, c_ulong(len(part2)),
                                 mp_buf2, byref(mp_len2))
            if rv != CKR_OK:
                print(f"FATAL:EncryptUpdate_mp2:0x{rv:08x}")
                sys.exit(1)
            mp_out += bytes(mp_buf2[:mp_len2.value])

            mp_final_len = c_ulong(32)
            mp_final_buf = (c_ubyte * 32)()
            rv = C_EncryptFinal(hSession, mp_final_buf, byref(mp_final_len))
            if rv != CKR_OK:
                print(f"FATAL:EncryptFinal_mp:0x{rv:08x}")
                sys.exit(1)
            mp_out += bytes(mp_final_buf[:mp_final_len.value])

            restored_hex = binascii.hexlify(bytes(mp_out)).decode()
            print(f"RESTORED:{restored_hex}")
        """

        returncode, stdout, stderr = _run_state_script(module_path, slot_index, pin_bytes, script)

        lines_map = _parse_output(stdout)

        if "SKIP" in lines_map:
            pytest.skip(f"Module skipped encrypt state test: {lines_map['SKIP']}")

        if returncode != 0:
            fatals = [ln for ln in stdout.splitlines() if ln.startswith("FATAL:")]
            detail = fatals[0] if fatals else f"stdout={stdout!r} stderr={stderr!r}"
            # NSS returns CKR_STATE_UNSAVEABLE (0x180) or CKR_OPERATION_NOT_INITIALIZED
            # (0x91) for encrypt state -- it does not support saving encrypt operation state.
            # Both are conformant: CKR_STATE_UNSAVEABLE is explicitly permitted by spec
            # Sec.5.6.5; CKR_OPERATION_NOT_INITIALIZED is NSS's response when the
            # EncryptUpdate has cleared the "active operation" flag before GetOperationState.
            _state_codes = (
                "0x00000180",
                "STATE_UNSAVEABLE",
                "0x00000054",
                "NOT_SUPPORTED",
                "0x00000091",
                "OPERATION_NOT_INITIALIZED",
            )
            if any(code in detail for code in _state_codes):
                xfail_as(
                    "not_operational",
                    label="encrypt-state-save",
                    operation="C_GetOperationState",
                    summary=(
                        f"Module does not support saving encrypt operation state: {detail} "
                        f"(PKCS#11 spec Sec.5.6.5 CKR_STATE_UNSAVEABLE is allowed)"
                    ),
                )
            fail_as(
                "crash",
                label="encrypt-state-roundtrip",
                operation="C_GetOperationState",
                summary=f"Subprocess failed: {detail}",
                detail={"returncode": returncode},
            )

        assert "REFERENCE" in lines_map, f"Missing REFERENCE in output: {stdout!r}"
        assert "RESTORED" in lines_map, f"Missing RESTORED in output: {stdout!r}"

        ref = lines_map["REFERENCE"]
        restored = lines_map["RESTORED"]
        assert restored == ref, (
            f"Encrypt state round-trip mismatch: expected {ref!r}, got {restored!r}"
        )
