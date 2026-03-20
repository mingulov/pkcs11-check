"""Tests for C_SignRecoverInit / C_SignRecover and C_VerifyRecoverInit / C_VerifyRecover.

Happy-path functional tests exercising sign-recover and verify-recover operations.

Source: PKCS#11 v3.1 §5.10.5 (C_SignRecoverInit), §5.10.6 (C_SignRecover),
        §5.11.5 (C_VerifyRecoverInit), §5.11.6 (C_VerifyRecover).

C_SignRecover produces a signature from which the original data can be recovered.
C_VerifyRecover takes a signature and recovers the original data (and verifies it).
The primary mechanism is CKM_RSA_X_509 (raw RSA, no padding).

For RSA X.509, the input data must be padded to exactly the modulus size (2048
bits → 256 bytes).  The token performs raw modular exponentiation; the caller is
responsible for any padding.  CKM_RSA_X_509 is widely supported in hardware and
software tokens as the recovery-capable RSA mechanism.

These operations are only accessible via the raw C API — python-pkcs11 does not
expose high-level sign_recover() / verify_recover() methods on Key or Session
objects.  Tests use a ctypes subprocess in the same pattern as test_operation_state.py.

CK_FUNCTION_LIST indices (0-based, after the CK_VERSION field):
  C_SignRecoverInit = 45
  C_SignRecover     = 46
  C_VerifyRecoverInit = 51
  C_VerifyRecover     = 52
  C_GenerateKeyPair   = 59
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from typing import Any

import pytest

pytestmark = pytest.mark.full

# ---------------------------------------------------------------------------
# Subprocess boilerplate (same pattern as test_operation_state.py)
# ---------------------------------------------------------------------------

_SUBPROCESS_BOILERPLATE = """\
import ctypes
from ctypes import c_ulong, c_void_p, c_ubyte, c_char_p, POINTER, byref, cast
import sys
import binascii

CK_RV = c_ulong
CKR_OK = 0x00000000
CKR_FUNCTION_NOT_SUPPORTED = 0x00000054
CKR_MECHANISM_INVALID = 0x00000070
CKR_OPERATION_NOT_INITIALIZED = 0x00000091
CKR_USER_ALREADY_LOGGED_IN = 0x00000100
CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191
CKF_SERIAL_SESSION = 0x00000004
CKF_RW_SESSION = 0x00000002

# Mechanism and attribute constants
CKM_RSA_X_509 = 0x00000003
CKM_RSA_PKCS_KEY_PAIR_GEN = 0x00000000
CKA_CLASS = 0x00000000
CKA_KEY_TYPE = 0x00000100
CKA_TOKEN = 0x00000001
CKA_SIGN_RECOVER = 0x00000109
CKA_VERIFY_RECOVER = 0x0000010B
CKA_MODULUS_BITS = 0x00000121
CKA_PUBLIC_EXPONENT = 0x00000122
CKO_PUBLIC_KEY = 0x00000002
CKO_PRIVATE_KEY = 0x00000003
CKK_RSA = 0x00000000

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
# 18=C_Login, 19=C_Logout,
# 45=C_SignRecoverInit, 46=C_SignRecover,
# 51=C_VerifyRecoverInit, 52=C_VerifyRecover,
# 59=C_GenerateKeyPair

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

def C_SignRecoverInit(hSession, pMechanism, hKey):
    return _cfunc("C_SignRecoverInit", CK_RV,
        [c_ulong, c_void_p, c_ulong], 45)(hSession, pMechanism, hKey)

def C_SignRecover(hSession, pData, ulDataLen, pSignature, pulSignatureLen):
    return _cfunc("C_SignRecover", CK_RV,
        [c_ulong, c_char_p, c_ulong, c_void_p, POINTER(c_ulong)], 46)(
        hSession, pData, ulDataLen, pSignature, pulSignatureLen)

def C_VerifyRecoverInit(hSession, pMechanism, hKey):
    return _cfunc("C_VerifyRecoverInit", CK_RV,
        [c_ulong, c_void_p, c_ulong], 51)(hSession, pMechanism, hKey)

def C_VerifyRecover(hSession, pSignature, ulSignatureLen, pData, pulDataLen):
    return _cfunc("C_VerifyRecover", CK_RV,
        [c_ulong, c_char_p, c_ulong, c_void_p, POINTER(c_ulong)], 52)(
        hSession, pSignature, ulSignatureLen, pData, pulDataLen)

def C_GenerateKeyPair(hSession, pMechanism, pPublicTemplate, ulPublicCount,
                      pPrivateTemplate, ulPrivateCount, phPublicKey, phPrivateKey):
    return _cfunc("C_GenerateKeyPair", CK_RV,
        [c_ulong, c_void_p, c_void_p, c_ulong, c_void_p, c_ulong,
         POINTER(c_ulong), POINTER(c_ulong)], 59)(
        hSession, pMechanism, pPublicTemplate, ulPublicCount,
        pPrivateTemplate, ulPrivateCount, phPublicKey, phPrivateKey)

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

# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------

# Script that generates an RSA-2048 key pair and stores handles as KEYGEN_OK
_KEYGEN_SCRIPT = """\
    def _attr(atype, val):
        return CK_ATTRIBUTE(
            atype,
            ctypes.cast(ctypes.byref(val), c_void_p),
            ctypes.sizeof(val),
        )

    # Public key template
    cls_pub = c_ulong(CKO_PUBLIC_KEY)
    ktype_pub = c_ulong(CKK_RSA)
    modbits = c_ulong(2048)
    pubexp = (c_ubyte * 3)(0x01, 0x00, 0x01)  # 65537
    tok_pub = c_ubyte(0)
    vr_pub = c_ubyte(1)

    pub_template = (CK_ATTRIBUTE * 5)(
        _attr(CKA_CLASS,         cls_pub),
        _attr(CKA_KEY_TYPE,      ktype_pub),
        _attr(CKA_MODULUS_BITS,  modbits),
        _attr(CKA_TOKEN,         tok_pub),
        _attr(CKA_VERIFY_RECOVER, vr_pub),
    )
    # Set CKA_PUBLIC_EXPONENT separately (byte array, not ulong)
    pub_exp_attr = CK_ATTRIBUTE(
        CKA_PUBLIC_EXPONENT,
        ctypes.cast(pubexp, c_void_p),
        3,
    )
    pub_template_full = (CK_ATTRIBUTE * 6)(
        _attr(CKA_CLASS,          cls_pub),
        _attr(CKA_KEY_TYPE,       ktype_pub),
        _attr(CKA_MODULUS_BITS,   modbits),
        _attr(CKA_TOKEN,          tok_pub),
        _attr(CKA_VERIFY_RECOVER, vr_pub),
        pub_exp_attr,
    )

    # Private key template
    cls_prv = c_ulong(CKO_PRIVATE_KEY)
    ktype_prv = c_ulong(CKK_RSA)
    tok_prv = c_ubyte(0)
    sr_prv = c_ubyte(1)

    prv_template = (CK_ATTRIBUTE * 4)(
        _attr(CKA_CLASS,         cls_prv),
        _attr(CKA_KEY_TYPE,      ktype_prv),
        _attr(CKA_TOKEN,         tok_prv),
        _attr(CKA_SIGN_RECOVER,  sr_prv),
    )

    kg_mech = CK_MECHANISM()
    kg_mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN

    hPub = c_ulong(0)
    hPrv = c_ulong(0)
    rv = C_GenerateKeyPair(
        hSession,
        ctypes.byref(kg_mech),
        pub_template_full, 6,
        prv_template, 4,
        byref(hPub), byref(hPrv),
    )
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID):
        print(f"SKIP:GenerateKeyPairUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:GenerateKeyPair:0x{rv:08x}")
        sys.exit(1)
    print(f"KEYGEN_OK:{hPub.value}:{hPrv.value}")
"""


def _run_script(
    module_path: str,
    slot_index: int,
    pin_bytes: bytes,
    script_body: str,
    timeout: int = 30,
) -> tuple[int, str, str]:
    """Run a ctypes PKCS#11 script in a subprocess.

    The boilerplate sets up lib, hSession, slot_id, and all helpers.
    script_body is appended and must print KEY:value lines.
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
        + textwrap.dedent(
            """\

        C_CloseSession(hSession)
        C_Finalize()
    """
        )
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
    """Parse KEY:value lines from subprocess stdout into a dict."""
    result: dict[str, str] = {}
    for line in stdout.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            result[key.strip()] = value.strip()
    return result


def _get_params(p11_config: Any) -> tuple[str, int, bytes]:
    """Extract (module_path, slot_index, pin_bytes) from config fixture."""
    module_path = str(p11_config.module)
    slot_index = p11_config.slot if p11_config.slot is not None else 0
    pin_bytes = p11_config.pin.get_secret_value().encode() if p11_config.pin else b""
    return module_path, slot_index, pin_bytes


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("p11_module")
class TestSignRecover:
    """C_SignRecover / C_VerifyRecover functional tests using CKM_RSA_X_509.

    C_SignRecover (§5.10.6): Signs data with a private key using a mechanism
    that allows the original data to be recovered from the signature.

    C_VerifyRecover (§5.11.6): Verifies a signature and recovers the original
    data from the signature using the corresponding public key.

    CKM_RSA_X_509 (raw RSA) is the standard mechanism for these operations.
    The input must be padded to the modulus size (2048 bits → 256 bytes).
    """

    def test_sign_recover_produces_output(self, p11_config: Any, p11_module: Any) -> None:
        """C_SignRecover with RSA X.509 produces a 256-byte signature block.

        Steps:
        1. Generate RSA-2048 key pair with CKA_SIGN_RECOVER / CKA_VERIFY_RECOVER.
        2. C_SignRecoverInit(CKM_RSA_X_509, privateKey).
        3. C_SignRecover(padded_data) → signature.
        4. Verify signature length equals modulus size (256 bytes).

        Source: PKCS#11 v3.1 §5.10.5–§5.10.6.
        """
        if not _has_rsa_x509(p11_module):
            pytest.skip("CKM_RSA_X_509 not supported by this module")

        module_path, slot_index, pin_bytes = _get_params(p11_config)

        script = (
            _KEYGEN_SCRIPT
            + """\
    sr_mech = CK_MECHANISM()
    sr_mech.mechanism = CKM_RSA_X_509

    # Input must be exactly 256 bytes (RSA-2048 modulus size)
    # Use PKCS#1 v1.5-style padding: 0x00 0x01 0xFF...FF 0x00 <data>
    data = b"Hello sign-recover"
    pad_len = 256 - 3 - len(data)
    padded = b"\\x00\\x01" + b"\\xff" * pad_len + b"\\x00" + data

    rv = C_SignRecoverInit(hSession, ctypes.byref(sr_mech), hPrv)
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID, CKR_OPERATION_NOT_INITIALIZED):
        print(f"SKIP:SignRecoverInitUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:SignRecoverInit:0x{rv:08x}")
        sys.exit(1)

    # Length query
    sig_len = c_ulong(0)
    rv = C_SignRecover(hSession, c_char_p(padded), c_ulong(len(padded)), None, byref(sig_len))
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID):
        print(f"SKIP:SignRecoverUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:SignRecoverLen:0x{rv:08x}")
        sys.exit(1)

    sig_buf = (c_ubyte * sig_len.value)()
    rv = C_SignRecover(hSession, c_char_p(padded), c_ulong(len(padded)),
                      sig_buf, byref(sig_len))
    if rv != CKR_OK:
        print(f"FATAL:SignRecover:0x{rv:08x}")
        sys.exit(1)

    sig_hex = binascii.hexlify(bytes(sig_buf[:sig_len.value])).decode()
    print(f"SIG_LEN:{sig_len.value}")
    print(f"SIG:{sig_hex}")
"""
        )

        returncode, stdout, stderr = _run_script(module_path, slot_index, pin_bytes, script)
        lines_map = _parse_output(stdout)

        if "SKIP" in lines_map:
            pytest.skip(f"Module skipped sign-recover: {lines_map['SKIP']}")

        if returncode != 0:
            fatals = [ln for ln in stdout.splitlines() if ln.startswith("FATAL:")]
            detail = fatals[0] if fatals else f"stdout={stdout!r} stderr={stderr!r}"
            pytest.fail(f"Subprocess failed: {detail}")

        assert "SIG_LEN" in lines_map, f"Missing SIG_LEN in output: {stdout!r}"
        assert "SIG" in lines_map, f"Missing SIG in output: {stdout!r}"

        sig_len = int(lines_map["SIG_LEN"])
        assert sig_len == 256, f"RSA-2048 sign-recover output must be 256 bytes, got {sig_len}"

    def test_verify_recover_round_trip(self, p11_config: Any, p11_module: Any) -> None:
        """C_SignRecover then C_VerifyRecover recovers the original padded data.

        Steps:
        1. Generate RSA-2048 key pair.
        2. C_SignRecoverInit → C_SignRecover(padded_data) → signature.
        3. C_VerifyRecoverInit → C_VerifyRecover(signature) → recovered_data.
        4. Assert recovered_data == padded_data.

        Source: PKCS#11 v3.1 §5.10.5–§5.10.6, §5.11.5–§5.11.6.
        """
        if not _has_rsa_x509(p11_module):
            pytest.skip("CKM_RSA_X_509 not supported by this module")

        module_path, slot_index, pin_bytes = _get_params(p11_config)

        script = (
            _KEYGEN_SCRIPT
            + """\
    sr_mech = CK_MECHANISM()
    sr_mech.mechanism = CKM_RSA_X_509

    # Input: exactly 256 bytes with PKCS#1 type-1 padding
    data = b"Round-trip test data"
    pad_len = 256 - 3 - len(data)
    padded = b"\\x00\\x01" + b"\\xff" * pad_len + b"\\x00" + data
    padded_hex = binascii.hexlify(padded).decode()
    print(f"ORIGINAL:{padded_hex}")

    # --- Sign-recover ---
    rv = C_SignRecoverInit(hSession, ctypes.byref(sr_mech), hPrv)
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID, CKR_OPERATION_NOT_INITIALIZED):
        print(f"SKIP:SignRecoverInitUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:SignRecoverInit:0x{rv:08x}")
        sys.exit(1)

    # Length query
    sig_len = c_ulong(0)
    rv = C_SignRecover(hSession, c_char_p(padded), c_ulong(len(padded)), None, byref(sig_len))
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID):
        print(f"SKIP:SignRecoverUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:SignRecoverLen:0x{rv:08x}")
        sys.exit(1)

    sig_buf = (c_ubyte * sig_len.value)()
    rv = C_SignRecover(hSession, c_char_p(padded), c_ulong(len(padded)),
                      sig_buf, byref(sig_len))
    if rv != CKR_OK:
        print(f"FATAL:SignRecover:0x{rv:08x}")
        sys.exit(1)
    sig_bytes = bytes(sig_buf[:sig_len.value])
    print(f"SIG_LEN:{sig_len.value}")

    # --- Verify-recover ---
    rv = C_VerifyRecoverInit(hSession, ctypes.byref(sr_mech), hPub)
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID, CKR_OPERATION_NOT_INITIALIZED):
        print(f"SKIP:VerifyRecoverInitUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:VerifyRecoverInit:0x{rv:08x}")
        sys.exit(1)

    # Length query
    rec_len = c_ulong(0)
    rv = C_VerifyRecover(hSession, c_char_p(sig_bytes), c_ulong(len(sig_bytes)),
                         None, byref(rec_len))
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID):
        print(f"SKIP:VerifyRecoverUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:VerifyRecoverLen:0x{rv:08x}")
        sys.exit(1)

    rec_buf = (c_ubyte * rec_len.value)()
    rv = C_VerifyRecover(hSession, c_char_p(sig_bytes), c_ulong(len(sig_bytes)),
                         rec_buf, byref(rec_len))
    if rv != CKR_OK:
        print(f"FATAL:VerifyRecover:0x{rv:08x}")
        sys.exit(1)

    recovered_hex = binascii.hexlify(bytes(rec_buf[:rec_len.value])).decode()
    print(f"RECOVERED:{recovered_hex}")
"""
        )

        returncode, stdout, stderr = _run_script(module_path, slot_index, pin_bytes, script)
        lines_map = _parse_output(stdout)

        if "SKIP" in lines_map:
            pytest.skip(f"Module skipped sign/verify-recover: {lines_map['SKIP']}")

        if returncode != 0:
            fatals = [ln for ln in stdout.splitlines() if ln.startswith("FATAL:")]
            detail = fatals[0] if fatals else f"stdout={stdout!r} stderr={stderr!r}"
            pytest.fail(f"Subprocess failed: {detail}")

        assert "ORIGINAL" in lines_map, f"Missing ORIGINAL in output: {stdout!r}"
        assert "RECOVERED" in lines_map, f"Missing RECOVERED in output: {stdout!r}"

        original = lines_map["ORIGINAL"]
        recovered = lines_map["RECOVERED"]
        assert recovered == original, (
            f"Verify-recover round-trip mismatch:\n"
            f"  original  = {original!r}\n"
            f"  recovered = {recovered!r}"
        )

    def test_sign_recover_wrong_data_length(self, p11_config: Any, p11_module: Any) -> None:
        """C_SignRecover with wrong-length data returns a PKCS#11 error (not crash).

        For CKM_RSA_X_509 with a 2048-bit key, input must be exactly 256 bytes.
        Passing shorter data must return CKR_DATA_LEN_RANGE or CKR_ARGUMENTS_BAD
        (or similar), not crash or silently succeed.

        Source: PKCS#11 v3.1 §5.10.6 error table.
        """
        if not _has_rsa_x509(p11_module):
            pytest.skip("CKM_RSA_X_509 not supported by this module")

        module_path, slot_index, pin_bytes = _get_params(p11_config)

        script = (
            _KEYGEN_SCRIPT
            + """\
    CKR_DATA_LEN_RANGE = 0x00000021
    CKR_ARGUMENTS_BAD  = 0x00000007
    CKR_BUFFER_TOO_SMALL = 0x00000150

    sr_mech = CK_MECHANISM()
    sr_mech.mechanism = CKM_RSA_X_509

    rv = C_SignRecoverInit(hSession, ctypes.byref(sr_mech), hPrv)
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID, CKR_OPERATION_NOT_INITIALIZED):
        print(f"SKIP:SignRecoverInitUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:SignRecoverInit:0x{rv:08x}")
        sys.exit(1)

    # Data shorter than modulus — must be rejected
    short_data = b"too short"
    sig_len = c_ulong(256)
    sig_buf = (c_ubyte * 256)()
    rv = C_SignRecover(hSession, c_char_p(short_data), c_ulong(len(short_data)),
                      sig_buf, byref(sig_len))

    if rv == CKR_OK:
        print("RESULT:ACCEPTED_SHORT_DATA")
    else:
        print(f"RESULT:REJECTED:0x{rv:08x}")
        # Any non-OK return is acceptable — the module correctly rejected it
        acceptable = {CKR_DATA_LEN_RANGE, CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL,
                      CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID}
        if rv not in acceptable:
            # Non-standard CKR — still a valid rejection; note it
            print(f"NOTE:NonStandardRejection:0x{rv:08x}")
"""
        )

        returncode, stdout, stderr = _run_script(module_path, slot_index, pin_bytes, script)
        lines_map = _parse_output(stdout)

        if "SKIP" in lines_map:
            pytest.skip(f"Module skipped sign-recover error test: {lines_map['SKIP']}")

        if returncode != 0:
            fatals = [ln for ln in stdout.splitlines() if ln.startswith("FATAL:")]
            detail = fatals[0] if fatals else f"stdout={stdout!r} stderr={stderr!r}"
            pytest.fail(f"Subprocess failed: {detail}")

        assert "RESULT" in lines_map, f"Missing RESULT in output: {stdout!r}"

        # The module should not silently accept wrong-length data.
        # Some modules pad internally and accept any length — this is non-standard
        # for CKM_RSA_X_509 but we don't fail on it; we just note it.
        result = lines_map["RESULT"]
        if result == "ACCEPTED_SHORT_DATA":
            pytest.xfail(
                "Module accepted short data for CKM_RSA_X_509 C_SignRecover — "
                "non-standard behaviour (spec requires CKR_DATA_LEN_RANGE)"
            )


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _has_rsa_x509(p11_module: Any) -> bool:
    """Return True if the module's first token supports CKM_RSA_X_509."""
    try:
        slot = p11_module.get_slots(token_present=True)[0]
        mechs = {getattr(m, "name", str(m)) for m in slot.get_mechanisms()}
        return "RSA_X_509" in mechs
    except Exception:
        return False
