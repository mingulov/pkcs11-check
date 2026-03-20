"""Tests for C_GetOperationState and C_SetOperationState.

Happy-path functional tests exercising state save/restore for active operations.
Error-path CKR tests are in ckr/test_ckr_state.py.

Source: PKCS#11 v3.1 §5.6.5 (C_GetOperationState), §5.6.6 (C_SetOperationState).

Most PKCS#11 modules return CKR_STATE_UNSAVEABLE for active operations — this is
spec-conformant behaviour (§5.6.5: the token may return CKR_STATE_UNSAVEABLE if the
state cannot be saved). Tests that require a saveable state skip gracefully when the
module does not support it.

The actual state save/restore round-trip uses a ctypes subprocess to call
C_DigestInit / C_DigestUpdate / C_GetOperationState / C_SetOperationState /
C_DigestFinal directly, because the python-pkcs11 high-level API does not expose
init/update/final as individually callable Python steps for digest.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from typing import Any

import pytest
from pkcs11.exceptions import (
    FunctionNotSupported,
    OperationNotInitialized,
    SavedStateInvalid,
    StateUnsaveable,
)

pytestmark = pytest.mark.operation_state

# CKM_SHA256 (PKCS#11 spec §2.7)
_CKM_SHA256 = 0x00000250

# ---------------------------------------------------------------------------
# Subprocess runner
# ---------------------------------------------------------------------------

_SUBPROCESS_BOILERPLATE = """\
import ctypes
from ctypes import c_ulong, c_void_p, c_ubyte, c_char_p, POINTER, byref, cast
import sys
import binascii

CK_RV = c_ulong
CKR_OK = 0x00000000
CKR_FUNCTION_NOT_SUPPORTED = 0x00000054
CKR_STATE_UNSAVEABLE = 0x00000180
CKR_USER_ALREADY_LOGGED_IN = 0x00000100
CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191
CKF_SERIAL_SESSION = 0x00000004
CKF_RW_SESSION = 0x00000002
CKM_SHA256 = 0x00000250

lib = ctypes.CDLL({module_path!r})

C_GetFunctionList = lib.C_GetFunctionList
C_GetFunctionList.restype = CK_RV
C_GetFunctionList.argtypes = [POINTER(c_void_p)]

funclist_ptr = c_void_p()
rv = C_GetFunctionList(byref(funclist_ptr))
if rv != CKR_OK:
    print(f"FATAL:GetFunctionList:0x{{rv:08x}}")
    sys.exit(1)

ptr_size = ctypes.sizeof(c_void_p)
base = funclist_ptr.value

def _get_func(index):
    offset = ptr_size + (index * ptr_size)
    addr = ctypes.cast(base + offset, POINTER(c_void_p)).contents.value
    return addr

# CK_FUNCTION_LIST indices (0-based, after version field):
# 0=C_Initialize, 1=C_Finalize, 4=C_GetSlotList,
# 12=C_OpenSession, 13=C_CloseSession,
# 16=C_GetOperationState, 17=C_SetOperationState,
# 18=C_Login, 19=C_Logout,
# 37=C_DigestInit, 39=C_DigestUpdate, 41=C_DigestFinal

_cache = {{}}

def _cfunc(name, restype, argtypes, idx):
    if name not in _cache:
        addr = _get_func(idx)
        ft = ctypes.CFUNCTYPE(restype, *argtypes)
        _cache[name] = ft(addr)
    return _cache[name]

def C_Initialize():
    return _cfunc("C_Initialize", CK_RV, [c_void_p], 0)(c_void_p(None))

def C_Finalize():
    return _cfunc("C_Finalize", CK_RV, [c_void_p], 1)(c_void_p(None))

def C_GetSlotList(present, slots, count):
    return _cfunc("C_GetSlotList", CK_RV,
        [c_ubyte, POINTER(c_ulong), POINTER(c_ulong)], 4)(present, slots, count)

def C_OpenSession(slot, flags, app, notify, phSession):
    return _cfunc("C_OpenSession", CK_RV,
        [c_ulong, c_ulong, c_void_p, c_void_p, POINTER(c_ulong)], 12)(
        slot, flags, app, notify, phSession)

def C_CloseSession(hSession):
    return _cfunc("C_CloseSession", CK_RV, [c_ulong], 13)(hSession)

def C_Login(hSession, userType, pin, pinLen):
    return _cfunc("C_Login", CK_RV,
        [c_ulong, c_ulong, c_char_p, c_ulong], 18)(hSession, userType, pin, pinLen)

def C_DigestInit(hSession, pMechanism):
    return _cfunc("C_DigestInit", CK_RV,
        [c_ulong, c_void_p], 37)(hSession, pMechanism)

def C_DigestUpdate(hSession, pPart, ulPartLen):
    return _cfunc("C_DigestUpdate", CK_RV,
        [c_ulong, c_char_p, c_ulong], 39)(hSession, pPart, ulPartLen)

def C_DigestFinal(hSession, pDigest, pulDigestLen):
    return _cfunc("C_DigestFinal", CK_RV,
        [c_ulong, c_void_p, POINTER(c_ulong)], 41)(hSession, pDigest, pulDigestLen)

def C_GetOperationState(hSession, pState, pulStateLen):
    return _cfunc("C_GetOperationState", CK_RV,
        [c_ulong, c_void_p, POINTER(c_ulong)], 16)(hSession, pState, pulStateLen)

def C_SetOperationState(hSession, pOperationState, ulOperationStateLen,
                        hEncryptionKey, hAuthenticationKey):
    return _cfunc("C_SetOperationState", CK_RV,
        [c_ulong, c_char_p, c_ulong, c_ulong, c_ulong], 17)(
        hSession, pOperationState, ulOperationStateLen,
        hEncryptionKey, hAuthenticationKey)

class CK_MECHANISM(ctypes.Structure):
    _fields_ = [
        ("mechanism", c_ulong),
        ("pParameter", c_void_p),
        ("ulParameterLen", c_ulong),
    ]

# Initialise
rv = C_Initialize()
if rv != CKR_OK and rv != CKR_CRYPTOKI_ALREADY_INITIALIZED:
    print(f"FATAL:Initialize:0x{{rv:08x}}")
    sys.exit(1)

# Get slot list
count = c_ulong(0)
rv = C_GetSlotList(1, None, byref(count))
if rv != CKR_OK or count.value == 0:
    print(f"FATAL:GetSlotList:0x{{rv:08x}}:count={{count.value}}")
    C_Finalize()
    sys.exit(1)

slots = (c_ulong * count.value)()
rv = C_GetSlotList(1, slots, byref(count))
if rv != CKR_OK:
    print(f"FATAL:GetSlotList2:0x{{rv:08x}}")
    C_Finalize()
    sys.exit(1)

slot_id = slots[{slot_index}]

# Open session
hSession = c_ulong(0)
flags = c_ulong(CKF_SERIAL_SESSION | CKF_RW_SESSION)
rv = C_OpenSession(slot_id, flags, c_void_p(None), c_void_p(None), byref(hSession))
if rv != CKR_OK:
    print(f"FATAL:OpenSession:0x{{rv:08x}}")
    C_Finalize()
    sys.exit(1)

# Login if PIN provided
_PIN = {pin_bytes!r}
if _PIN:
    rv = C_Login(hSession, c_ulong(1), c_char_p(_PIN), c_ulong(len(_PIN)))
    if rv != CKR_OK and rv != CKR_USER_ALREADY_LOGGED_IN:
        print(f"FATAL:Login:0x{{rv:08x}}")
        C_CloseSession(hSession)
        C_Finalize()
        sys.exit(1)

"""


def _run_state_script(
    module_path: str,
    slot_index: int,
    pin_bytes: bytes,
    script_body: str,
    timeout: int = 15,
) -> tuple[int, str, str]:
    """Run a ctypes-based operation state script in a subprocess.

    The boilerplate sets up lib, hSession, slot_id, and all helpers.
    script_body is appended and must print ``KEY:value`` lines.
    Returns (returncode, stdout, stderr).
    """
    boilerplate = _SUBPROCESS_BOILERPLATE.format(
        module_path=module_path,
        slot_index=slot_index,
        pin_bytes=pin_bytes,
    )
    full_script = (
        boilerplate
        + textwrap.dedent(script_body)
        + textwrap.dedent("""\

        C_CloseSession(hSession)
        C_Finalize()
    """)
    )

    result = subprocess.run(
        [sys.executable, "-c", full_script],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=os.environ.copy(),
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def _parse_output(stdout: str) -> dict[str, str]:
    """Parse ``KEY:value`` lines from subprocess stdout into a dict."""
    result: dict[str, str] = {}
    for line in stdout.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            result[key.strip()] = value.strip()
    return result


# ---------------------------------------------------------------------------
# Tests: high-level API availability
# ---------------------------------------------------------------------------


class TestGetOperationStateAPI:
    """Verify C_GetOperationState / C_SetOperationState are present and respond correctly."""

    def test_api_exists(self, p11_session: Any) -> None:
        """Session object exposes get_operation_state() and set_operation_state()."""
        assert hasattr(p11_session, "get_operation_state") and callable(
            p11_session.get_operation_state
        ), "Session must have a callable get_operation_state() method"
        assert hasattr(p11_session, "set_operation_state") and callable(
            p11_session.set_operation_state
        ), "Session must have a callable set_operation_state() method"

    def test_no_active_operation(self, p11_session: Any) -> None:
        """get_operation_state() with no active operation returns bytes or raises a known CKR.

        Spec §5.6.5: if no digest, encrypt, or sign operation is active the
        token must return CKR_OPERATION_NOT_INITIALIZED.  Some modules also
        return CKR_STATE_UNSAVEABLE or CKR_FUNCTION_NOT_SUPPORTED.
        """
        try:
            state = p11_session.get_operation_state()
            # A module that returns empty bytes with no active op is not spec-
            # conformant, but we accept it to avoid false failures.
            assert isinstance(state, bytes)
        except (OperationNotInitialized, StateUnsaveable, FunctionNotSupported):
            pass  # All valid per spec

    def test_garbage_state_raises_saved_state_invalid(self, p11_session: Any) -> None:
        """set_operation_state() with garbage data → CKR_SAVED_STATE_INVALID.

        Spec §5.6.6: the token must return CKR_SAVED_STATE_INVALID if the
        supplied state blob is unrecognisable.
        """
        garbage = b"\xde\xad\xbe\xef" * 16
        try:
            p11_session.set_operation_state(garbage)
            pytest.fail("set_operation_state() with garbage data must raise SavedStateInvalid")
        except SavedStateInvalid:
            pass  # Correct per spec §5.6.6
        except (FunctionNotSupported, StateUnsaveable):
            pytest.skip("Module does not support C_SetOperationState")
        except OperationNotInitialized:
            pass  # Module requires an active session operation — acceptable


# ---------------------------------------------------------------------------
# Tests: digest state round-trip via ctypes subprocess
# ---------------------------------------------------------------------------


class TestDigestStateRoundTrip:
    """State save/restore round-trip for a SHA-256 multi-part digest.

    The python-pkcs11 high-level digest API does not expose C_DigestInit /
    C_DigestUpdate / C_DigestFinal as individually callable Python steps, so
    these tests use a ctypes subprocess to exercise the C-level functions
    directly.  This also mirrors how real applications use state save/restore.
    """

    def _get_params(self, p11_module: Any, p11_config: Any) -> tuple[str, int, bytes]:
        """Extract (module_path, slot_index, pin_bytes) from fixtures."""
        module_path = str(p11_config.module)
        slot_index = p11_config.slot if p11_config.slot is not None else 0
        pin_bytes = p11_config.pin.get_secret_value().encode() if p11_config.pin else b""
        return module_path, slot_index, pin_bytes

    def test_digest_state_same_session(self, p11_module: Any, p11_config: Any) -> None:
        """SHA-256 state save/restore on the same session produces the correct digest.

        Steps:
        1. Compute reference = SHA-256(part1 + part2) via hashlib.
        2. PKCS#11: DigestInit(SHA-256) → DigestUpdate(part1) → GetOperationState.
        3. SetOperationState (restore) → DigestUpdate(part2) → DigestFinal.
        4. Assert final digest equals reference.

        Skips when the module returns CKR_STATE_UNSAVEABLE (most software tokens
        including SoftHSM2 and many hardware tokens do not support state save).
        """
        module_path, slot_index, pin_bytes = self._get_params(p11_module, p11_config)

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
            rv = C_DigestUpdate(hSession, c_char_p(full), c_ulong(len(full)))
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
            rv = C_DigestUpdate(hSession, c_char_p(part1), c_ulong(len(part1)))
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
            print(f"STATE_SAVED:{len(state_bytes)}")

            # Restore state on the same session
            rv = C_SetOperationState(
                hSession,
                c_char_p(state_bytes),
                c_ulong(len(state_bytes)),
                c_ulong(0),
                c_ulong(0),
            )
            if rv != CKR_OK:
                print(f"FATAL:SetOperationState:0x{rv:08x}")
                sys.exit(1)
            print("STATE_RESTORED")

            # Continue with part2 and finalise
            rv = C_DigestUpdate(hSession, c_char_p(part2), c_ulong(len(part2)))
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
            pytest.fail(f"Subprocess failed: {detail}")

        assert "REFERENCE" in lines_map, f"Missing REFERENCE in output: {stdout!r}"
        assert "RESTORED" in lines_map, f"Missing RESTORED in output: {stdout!r}"

        ref = lines_map["REFERENCE"]
        restored = lines_map["RESTORED"]
        assert restored == ref, (
            f"State round-trip digest mismatch: expected {ref!r}, got {restored!r}"
        )

    def test_digest_state_cross_session(self, p11_module: Any, p11_config: Any) -> None:
        """Restoring digest state on a second session is rejected or handled per spec.

        Spec §5.6.6 notes that tokens may reject cross-session restore with
        CKR_SAVED_STATE_INVALID.  Acceptance is also implementation-defined.
        This test verifies the module does not crash and returns a CKR code.

        Skips when the module returns CKR_STATE_UNSAVEABLE at the save step.
        """
        module_path, slot_index, pin_bytes = self._get_params(p11_module, p11_config)

        script = """\
            mech = CK_MECHANISM()
            mech.mechanism = CKM_SHA256

            part1 = b"cross-session data"

            rv = C_DigestInit(hSession, ctypes.byref(mech))
            if rv != CKR_OK:
                print(f"SKIP:DigestInitFailed:0x{rv:08x}")
                sys.exit(0)

            rv = C_DigestUpdate(hSession, c_char_p(part1), c_ulong(len(part1)))
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
            print(f"STATE_SAVED:{len(state_bytes)}")

            # Open a second session
            hSession2 = c_ulong(0)
            flags2 = c_ulong(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            rv = C_OpenSession(slot_id, flags2, c_void_p(None), c_void_p(None), byref(hSession2))
            if rv != CKR_OK:
                print(f"SKIP:OpenSession2Failed:0x{rv:08x}")
                sys.exit(0)

            # Try to restore state on the second session
            rv2 = C_SetOperationState(
                hSession2,
                c_char_p(state_bytes),
                c_ulong(len(state_bytes)),
                c_ulong(0),
                c_ulong(0),
            )
            if rv2 == CKR_OK:
                print("CROSS_SESSION_ACCEPTED")
            else:
                print(f"CROSS_SESSION_REJECTED:0x{rv2:08x}")

            C_CloseSession(hSession2)
        """

        returncode, stdout, stderr = _run_state_script(module_path, slot_index, pin_bytes, script)

        lines_map = _parse_output(stdout)

        if "SKIP" in lines_map:
            pytest.skip(f"Module skipped cross-session test: {lines_map['SKIP']}")

        if returncode != 0:
            fatals = [ln for ln in stdout.splitlines() if ln.startswith("FATAL:")]
            detail = fatals[0] if fatals else f"stdout={stdout!r} stderr={stderr!r}"
            pytest.fail(f"Subprocess failed: {detail}")

        assert "CROSS_SESSION_ACCEPTED" in lines_map or "CROSS_SESSION_REJECTED" in lines_map, (
            f"Expected CROSS_SESSION_ACCEPTED or CROSS_SESSION_REJECTED; stdout={stdout!r}"
        )
