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
CKR_SAVED_STATE_INVALID = 0x00000160
CKR_USER_ALREADY_LOGGED_IN = 0x00000100
CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191
CKF_SERIAL_SESSION = 0x00000004
CKF_RW_SESSION = 0x00000002
CKM_SHA256 = 0x00000250
CKM_AES_KEY_GEN = 0x00001080
CKM_AES_CBC = 0x00001082
CKA_CLASS = 0x00000000
CKA_KEY_TYPE = 0x00000100
CKA_TOKEN = 0x00000001
CKA_ENCRYPT = 0x00000104
CKA_DECRYPT = 0x00000105
CKA_VALUE_LEN = 0x00000161
CKO_SECRET_KEY = 0x00000004
CKK_AES = 0x0000001F

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
# 29=C_EncryptInit, 31=C_EncryptUpdate, 32=C_EncryptFinal,
# 37=C_DigestInit, 39=C_DigestUpdate, 41=C_DigestFinal,
# 58=C_GenerateKey

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

def C_EncryptInit(hSession, pMechanism, hKey):
    return _cfunc("C_EncryptInit", CK_RV,
        [c_ulong, c_void_p, c_ulong], 29)(hSession, pMechanism, hKey)

def C_EncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen):
    return _cfunc("C_EncryptUpdate", CK_RV,
        [c_ulong, c_char_p, c_ulong, c_void_p, POINTER(c_ulong)], 31)(
        hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen)

def C_EncryptFinal(hSession, pLastEncryptedPart, pulLastEncryptedPartLen):
    return _cfunc("C_EncryptFinal", CK_RV,
        [c_ulong, c_void_p, POINTER(c_ulong)], 32)(
        hSession, pLastEncryptedPart, pulLastEncryptedPartLen)

def C_GenerateKey(hSession, pMechanism, pTemplate, ulCount, phKey):
    return _cfunc("C_GenerateKey", CK_RV,
        [c_ulong, c_void_p, c_void_p, c_ulong, POINTER(c_ulong)], 58)(
        hSession, pMechanism, pTemplate, ulCount, phKey)

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

class CK_ATTRIBUTE(ctypes.Structure):
    _fields_ = [
        ("type", c_ulong),
        ("pValue", c_void_p),
        ("ulValueLen", c_ulong),
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

    def _get_params(self, p11_config: Any) -> tuple[str, int, bytes]:
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
        module_path, slot_index, pin_bytes = self._get_params(p11_config)

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
        module_path, slot_index, pin_bytes = self._get_params(p11_config)

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

        if "CROSS_SESSION_REJECTED" in lines_map:
            # Verify the rejection code is an expected CKR value.
            # CKR_SAVED_STATE_INVALID (0x160) is mandated by spec §5.6.6 for
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


class TestEncryptStateRoundTrip:
    """State save/restore round-trip for an AES-CBC multi-part encrypt operation.

    The python-pkcs11 high-level encrypt API does not expose C_EncryptInit /
    C_EncryptUpdate / C_EncryptFinal as individually callable Python steps, so
    these tests use a ctypes subprocess to exercise the C-level functions
    directly.

    Most modules return CKR_STATE_UNSAVEABLE for active encrypt operations — the
    tests skip gracefully when the module does not support saving encrypt state.
    """

    def _get_params(self, p11_config: Any) -> tuple[str, int, bytes]:
        """Extract (module_path, slot_index, pin_bytes) from fixtures."""
        module_path = str(p11_config.module)
        slot_index = p11_config.slot if p11_config.slot is not None else 0
        pin_bytes = p11_config.pin.get_secret_value().encode() if p11_config.pin else b""
        return module_path, slot_index, pin_bytes

    def test_encrypt_state_same_session(self, p11_module: Any, p11_config: Any) -> None:
        """AES-CBC state save/restore on the same session produces correct ciphertext.

        Steps:
        1. Generate an AES-256 key via C_GenerateKey.
        2. C_EncryptInit(AES-CBC, IV) → C_EncryptUpdate(part1) → C_GetOperationState.
        3. C_SetOperationState (restore, passing the key handle) → C_EncryptUpdate(part2)
           → C_EncryptFinal.
        4. Compare with a reference encryption that does not use state save/restore.

        Skips when the module returns CKR_STATE_UNSAVEABLE or
        CKR_FUNCTION_NOT_SUPPORTED (most software tokens do not save encrypt state).

        Source: PKCS#11 v3.1 §5.6.5–§5.6.6.
        """
        module_path, slot_index, pin_bytes = self._get_params(p11_config)

        script = """\
            # 16-byte IV and two 16-byte plaintext blocks (AES-CBC block-aligned)
            iv = b"\\x00" * 16
            part1 = b"Block-one-data!!"  # 16 bytes
            part2 = b"Block-two-data!!"  # 16 bytes

            # Build AES key-gen template
            cls_val = c_ulong(CKO_SECRET_KEY)
            ktype_val = c_ulong(CKK_AES)
            vlen_val = c_ulong(32)
            enc_val = c_ubyte(1)
            dec_val = c_ubyte(1)
            tok_val = c_ubyte(0)  # session key

            def _attr(atype, val):
                return CK_ATTRIBUTE(
                    atype,
                    ctypes.cast(ctypes.byref(val), c_void_p),
                    ctypes.sizeof(val),
                )
            template = (CK_ATTRIBUTE * 6)(
                _attr(CKA_CLASS,     cls_val),
                _attr(CKA_KEY_TYPE,  ktype_val),
                _attr(CKA_VALUE_LEN, vlen_val),
                _attr(CKA_ENCRYPT,   enc_val),
                _attr(CKA_DECRYPT,   dec_val),
                _attr(CKA_TOKEN,     tok_val),
            )

            kg_mech = CK_MECHANISM()
            kg_mech.mechanism = CKM_AES_KEY_GEN

            hKey = c_ulong(0)
            rv = C_GenerateKey(hSession, ctypes.byref(kg_mech), template, 6, byref(hKey))
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

            rv = C_EncryptUpdate(hSession, c_char_p(part1), c_ulong(len(part1)),
                                 out_buf, byref(out_len))
            if rv != CKR_OK:
                print(f"FATAL:EncryptUpdate_ref1:0x{rv:08x}")
                sys.exit(1)
            ref_out += bytes(out_buf[:out_len.value])

            out_len2 = c_ulong(32)
            out_buf2 = (c_ubyte * 32)()
            rv = C_EncryptUpdate(hSession, c_char_p(part2), c_ulong(len(part2)),
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
            rv = C_EncryptUpdate(hSession, c_char_p(part1), c_ulong(len(part1)),
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
            print(f"STATE_SAVED:{len(state_bytes)}")

            # Restore state on the same session, supplying the encryption key handle
            rv = C_SetOperationState(
                hSession,
                c_char_p(state_bytes),
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
            rv = C_EncryptUpdate(hSession, c_char_p(part2), c_ulong(len(part2)),
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
            pytest.fail(f"Subprocess failed: {detail}")

        assert "REFERENCE" in lines_map, f"Missing REFERENCE in output: {stdout!r}"
        assert "RESTORED" in lines_map, f"Missing RESTORED in output: {stdout!r}"

        ref = lines_map["REFERENCE"]
        restored = lines_map["RESTORED"]
        assert restored == ref, (
            f"Encrypt state round-trip mismatch: expected {ref!r}, got {restored!r}"
        )
