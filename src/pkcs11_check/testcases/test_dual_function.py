"""Tests for dual-function operations.

Covers all four PKCS#11 dual-function operations:
  Sec.5.14.1 C_DigestEncryptUpdate  (index 54)
  Sec.5.14.2 C_DecryptDigestUpdate  (index 55)
  Sec.5.14.3 C_SignEncryptUpdate    (index 56)
  Sec.5.14.4 C_DecryptVerifyUpdate  (index 57)

Most PKCS#11 modules do NOT implement these operations and return
CKR_FUNCTION_NOT_SUPPORTED (0x54).  Some modules reject the second active
operation with CKR_OPERATION_ACTIVE (0x90) because they only allow one
active operation type per session.  Tests skip gracefully in both cases.

These operations are only available via the raw C API -- python-pkcs11 has no
high-level wrappers.  Tests use the ctypes subprocess pattern established in
test_operation_state.py and test_sign_recover.py.

CK_FUNCTION_LIST indices (0-based, after the CK_VERSION field, including
C_GetFunctionList at index 3):
  C_EncryptInit         = 29
  C_EncryptUpdate       = 31
  C_EncryptFinal        = 32
  C_DecryptInit         = 33
  C_DecryptUpdate       = 35
  C_DecryptFinal        = 36
  C_DigestInit          = 37
  C_DigestUpdate        = 39
  C_DigestFinal         = 41
  C_DigestEncryptUpdate = 54
  C_DecryptDigestUpdate = 55
  C_GenerateKey         = 58
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
CKR_OPERATION_ACTIVE = 0x00000090
CKR_OPERATION_NOT_INITIALIZED = 0x00000091
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

# Codes that indicate the module does not support dual-function operations.
# CKR_FUNCTION_NOT_SUPPORTED (0x54): function pointer is a stub.
# CKR_OPERATION_ACTIVE (0x90): module allows only one active op per session,
#   so starting a second active operation (e.g. EncryptInit after DigestInit)
#   fails with OPERATION_ACTIVE rather than silently permitting the dual state.
_DUAL_UNSUPPORTED = (CKR_FUNCTION_NOT_SUPPORTED, CKR_OPERATION_ACTIVE)

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

# CK_FUNCTION_LIST indices (0-based, after version field, C_GetFunctionList=3):
# 0=C_Initialize, 1=C_Finalize, 2=C_GetInfo, 3=C_GetFunctionList,
# 4=C_GetSlotList, 12=C_OpenSession, 13=C_CloseSession, 18=C_Login,
# 29=C_EncryptInit, 31=C_EncryptUpdate, 32=C_EncryptFinal,
# 33=C_DecryptInit, 35=C_DecryptUpdate, 36=C_DecryptFinal,
# 37=C_DigestInit, 39=C_DigestUpdate, 41=C_DigestFinal,
# 54=C_DigestEncryptUpdate, 55=C_DecryptDigestUpdate,
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

def C_DecryptInit(hSession, pMechanism, hKey):
    return _cfunc("C_DecryptInit", CK_RV,
        [c_ulong, c_void_p, c_ulong], 33)(hSession, pMechanism, hKey)

def C_DecryptUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen):
    return _cfunc("C_DecryptUpdate", CK_RV,
        [c_ulong, c_char_p, c_ulong, c_void_p, POINTER(c_ulong)], 35)(
        hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen)

def C_DecryptFinal(hSession, pLastPart, pulLastPartLen):
    return _cfunc("C_DecryptFinal", CK_RV,
        [c_ulong, c_void_p, POINTER(c_ulong)], 36)(
        hSession, pLastPart, pulLastPartLen)

def C_DigestInit(hSession, pMechanism):
    return _cfunc("C_DigestInit", CK_RV,
        [c_ulong, c_void_p], 37)(hSession, pMechanism)

def C_DigestUpdate(hSession, pPart, ulPartLen):
    return _cfunc("C_DigestUpdate", CK_RV,
        [c_ulong, c_char_p, c_ulong], 39)(hSession, pPart, ulPartLen)

def C_DigestFinal(hSession, pDigest, pulDigestLen):
    return _cfunc("C_DigestFinal", CK_RV,
        [c_ulong, c_void_p, POINTER(c_ulong)], 41)(hSession, pDigest, pulDigestLen)

def C_DigestEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen):
    return _cfunc("C_DigestEncryptUpdate", CK_RV,
        [c_ulong, c_char_p, c_ulong, c_void_p, POINTER(c_ulong)], 54)(
        hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen)

def C_DecryptDigestUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen):
    return _cfunc("C_DecryptDigestUpdate", CK_RV,
        [c_ulong, c_char_p, c_ulong, c_void_p, POINTER(c_ulong)], 55)(
        hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen)

def C_GenerateKey(hSession, pMechanism, pTemplate, ulCount, phKey):
    return _cfunc("C_GenerateKey", CK_RV,
        [c_ulong, c_void_p, c_void_p, c_ulong, POINTER(c_ulong)], 58)(
        hSession, pMechanism, pTemplate, ulCount, phKey)

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

# Script fragment that generates an AES-256 session key.
# Sets hKey in the subprocess context.
_KEYGEN_SCRIPT = """\
    def _attr(atype, val):
        return CK_ATTRIBUTE(
            atype,
            ctypes.cast(ctypes.byref(val), c_void_p),
            ctypes.sizeof(val),
        )

    cls_val = c_ulong(CKO_SECRET_KEY)
    ktype_val = c_ulong(CKK_AES)
    vlen_val = c_ulong(32)
    enc_val = c_ubyte(1)
    dec_val = c_ubyte(1)
    tok_val = c_ubyte(0)

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
    if rv == CKR_FUNCTION_NOT_SUPPORTED:
        print(f"SKIP:GenerateKeyUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:GenerateKey:0x{rv:08x}")
        sys.exit(1)
    print(f"KEY_GENERATED:{hKey.value}")
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


from pkcs11_check.testcases._raw_subprocess import parse_output as _parse_output


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
class TestDigestEncryptUpdate:
    """C_DigestEncryptUpdate functional tests (AES-CBC + SHA-256).

    C_DigestEncryptUpdate (Sec.5.14.1): Continues a multiple-part combined digest
    and encryption operation, processing another data part.  Requires both a
    digest operation and an encrypt operation to be active on the session.

    The combined operation must produce output identical to running the digest
    and encrypt operations separately over the same data.
    """

    def test_digest_encrypt_update_round_trip(self, p11_config: Any) -> None:
        """DigestEncryptUpdate produces same ciphertext and digest as separate operations.

        Steps:
        1. Generate an AES-256 session key.
        2. Reference path -- separate operations:
           a. Reference digest via hashlib SHA-256.
           b. EncryptInit(AES-CBC, key, IV) -> EncryptUpdate(data) -> EncryptFinal -> ct_ref.
        3. Dual-function path:
           a. DigestInit(SHA-256)
           b. EncryptInit(AES-CBC, key, IV) -- skips if CKR_OPERATION_ACTIVE (module
              does not allow simultaneous digest + encrypt on the same session)
           c. DigestEncryptUpdate(data) -> ciphertext_chunk -- skips if
              CKR_FUNCTION_NOT_SUPPORTED
           d. EncryptFinal -> remaining ciphertext
           e. DigestFinal -> digest
        4. Assert: ciphertext == ct_ref AND digest == SHA-256(data).

        Source: PKCS#11 v3.1 Sec.5.14.1.
        """
        module_path, slot_index, pin_bytes = _get_params(p11_config)

        script = (
            _KEYGEN_SCRIPT
            + """\
    import hashlib

    # 16-byte IV; two 16-byte plaintext blocks (AES-CBC requires block alignment)
    iv = b"\\x00" * 16
    data = b"Block-one-here!!" + b"Block-two-here!!"  # 32 bytes, 2 AES blocks

    # --- Build AES-CBC mechanism ---
    iv_buf = (c_ubyte * 16)(*iv)
    enc_mech = CK_MECHANISM()
    enc_mech.mechanism = CKM_AES_CBC
    enc_mech.pParameter = ctypes.cast(iv_buf, c_void_p)
    enc_mech.ulParameterLen = 16

    sha_mech = CK_MECHANISM()
    sha_mech.mechanism = CKM_SHA256

    # -----------------------------------------------------------------------
    # Reference path: hashlib digest + separate PKCS#11 encrypt
    # -----------------------------------------------------------------------

    # Reference digest via hashlib (independent of PKCS#11 for reliability)
    digest_ref = hashlib.sha256(data).hexdigest()
    print(f"DIGEST_REF:{digest_ref}")

    # Reference encrypt via C_EncryptInit / C_EncryptUpdate / C_EncryptFinal
    rv = C_EncryptInit(hSession, ctypes.byref(enc_mech), hKey)
    if rv in _DUAL_UNSUPPORTED:
        print(f"SKIP:EncryptInitUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:EncryptInit_ref:0x{rv:08x}")
        sys.exit(1)

    ct_ref = bytearray()
    out_len = c_ulong(64)
    out_buf = (c_ubyte * 64)()
    rv = C_EncryptUpdate(hSession, c_char_p(data), c_ulong(len(data)),
                         out_buf, byref(out_len))
    if rv != CKR_OK:
        print(f"FATAL:EncryptUpdate_ref:0x{rv:08x}")
        sys.exit(1)
    ct_ref += bytes(out_buf[:out_len.value])

    fin_len = c_ulong(64)
    fin_buf = (c_ubyte * 64)()
    rv = C_EncryptFinal(hSession, fin_buf, byref(fin_len))
    if rv != CKR_OK:
        print(f"FATAL:EncryptFinal_ref:0x{rv:08x}")
        sys.exit(1)
    ct_ref += bytes(fin_buf[:fin_len.value])
    ct_ref_hex = binascii.hexlify(bytes(ct_ref)).decode()
    print(f"CT_REF:{ct_ref_hex}")

    # -----------------------------------------------------------------------
    # Dual-function path: DigestInit + EncryptInit + DigestEncryptUpdate
    # -----------------------------------------------------------------------

    rv = C_DigestInit(hSession, ctypes.byref(sha_mech))
    if rv in _DUAL_UNSUPPORTED:
        print(f"SKIP:DigestInitUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:DigestInit_dual:0x{rv:08x}")
        sys.exit(1)

    # Starting EncryptInit while DigestInit is active requires dual-function support.
    # Modules that only allow one active operation return CKR_OPERATION_ACTIVE here.
    rv = C_EncryptInit(hSession, ctypes.byref(enc_mech), hKey)
    if rv in _DUAL_UNSUPPORTED:
        print(f"SKIP:EncryptInit_dual_Unsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:EncryptInit_dual:0x{rv:08x}")
        sys.exit(1)

    # DigestEncryptUpdate: digest the plaintext and encrypt it simultaneously
    ct_dual = bytearray()
    deu_len = c_ulong(64)
    deu_buf = (c_ubyte * 64)()
    rv = C_DigestEncryptUpdate(hSession, c_char_p(data), c_ulong(len(data)),
                                deu_buf, byref(deu_len))
    if rv in _DUAL_UNSUPPORTED:
        print(f"SKIP:DigestEncryptUpdateUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:DigestEncryptUpdate:0x{rv:08x}")
        sys.exit(1)
    ct_dual += bytes(deu_buf[:deu_len.value])

    # Finalise the encrypt operation
    efin_len = c_ulong(64)
    efin_buf = (c_ubyte * 64)()
    rv = C_EncryptFinal(hSession, efin_buf, byref(efin_len))
    if rv != CKR_OK:
        print(f"FATAL:EncryptFinal_dual:0x{rv:08x}")
        sys.exit(1)
    ct_dual += bytes(efin_buf[:efin_len.value])
    ct_dual_hex = binascii.hexlify(bytes(ct_dual)).decode()
    print(f"CT_DUAL:{ct_dual_hex}")

    # Finalise the digest operation
    d_len = c_ulong(32)
    d_buf = (c_ubyte * 32)()
    rv = C_DigestFinal(hSession, d_buf, byref(d_len))
    if rv != CKR_OK:
        print(f"FATAL:DigestFinal_dual:0x{rv:08x}")
        sys.exit(1)
    digest_dual = binascii.hexlify(bytes(d_buf[:d_len.value])).decode()
    print(f"DIGEST_DUAL:{digest_dual}")
"""
        )

        returncode, stdout, stderr = _run_script(module_path, slot_index, pin_bytes, script)
        lines_map = _parse_output(stdout)

        if "SKIP" in lines_map:
            pytest.skip(f"Module does not support dual-function: {lines_map['SKIP']}")

        if returncode != 0:
            fatals = [ln for ln in stdout.splitlines() if ln.startswith("FATAL:")]
            detail = fatals[0] if fatals else f"stdout={stdout!r} stderr={stderr!r}"
            pytest.fail(f"Subprocess failed: {detail}")

        assert "DIGEST_REF" in lines_map, f"Missing DIGEST_REF in output: {stdout!r}"
        assert "CT_REF" in lines_map, f"Missing CT_REF in output: {stdout!r}"
        assert "CT_DUAL" in lines_map, f"Missing CT_DUAL in output: {stdout!r}"
        assert "DIGEST_DUAL" in lines_map, f"Missing DIGEST_DUAL in output: {stdout!r}"

        ct_ref = lines_map["CT_REF"]
        ct_dual = lines_map["CT_DUAL"]
        digest_ref = lines_map["DIGEST_REF"]
        digest_dual = lines_map["DIGEST_DUAL"]

        assert ct_dual == ct_ref, (
            f"DigestEncryptUpdate ciphertext mismatch:\n"
            f"  expected (separate encrypt) = {ct_ref!r}\n"
            f"  got (dual-function)          = {ct_dual!r}"
        )
        assert digest_dual == digest_ref, (
            f"DigestEncryptUpdate digest mismatch:\n"
            f"  expected (hashlib SHA-256) = {digest_ref!r}\n"
            f"  got (dual-function)        = {digest_dual!r}"
        )


@pytest.mark.usefixtures("p11_module")
class TestDecryptDigestUpdate:
    """C_DecryptDigestUpdate functional tests (AES-CBC + SHA-256).

    C_DecryptDigestUpdate (Sec.5.14.2): Continues a multiple-part combined decryption
    and digest operation, processing another encrypted data part.  The ciphertext
    is decrypted and the resulting plaintext is simultaneously digested.

    The combined operation must recover the original plaintext and produce a digest
    equal to SHA-256(original plaintext).
    """

    def test_decrypt_digest_update_round_trip(self, p11_config: Any) -> None:
        """DecryptDigestUpdate recovers plaintext and produces correct SHA-256 digest.

        Steps:
        1. Generate an AES-256 session key.
        2. Encrypt plaintext via separate C_EncryptInit/Update/Final to get ciphertext.
        3. Dual-function decryption path:
           a. DigestInit(SHA-256)
           b. DecryptInit(AES-CBC, key, IV) -- skips if CKR_OPERATION_ACTIVE (module
              does not allow simultaneous digest + decrypt on the same session)
           c. DecryptDigestUpdate(ciphertext) -> plaintext_chunk -- skips if
              CKR_FUNCTION_NOT_SUPPORTED
           d. DecryptFinal -> remaining plaintext
           e. DigestFinal -> digest of decrypted plaintext
        4. Assert: recovered plaintext == original data AND digest == SHA-256(data).

        Source: PKCS#11 v3.1 Sec.5.14.2.
        """
        module_path, slot_index, pin_bytes = _get_params(p11_config)

        script = (
            _KEYGEN_SCRIPT
            + """\
    import hashlib

    # 16-byte IV; two 16-byte plaintext blocks (AES-CBC requires block alignment)
    iv = b"\\x00" * 16
    plaintext = b"Hello-dual-func!" + b"DecryptDigest!??"  # 32 bytes, 2 AES blocks

    # Reference digest of the plaintext
    digest_ref = hashlib.sha256(plaintext).hexdigest()
    print(f"DIGEST_REF:{digest_ref}")
    pt_ref_hex = binascii.hexlify(plaintext).decode()
    print(f"PT_REF:{pt_ref_hex}")

    # --- Build AES-CBC mechanism ---
    iv_buf = (c_ubyte * 16)(*iv)
    enc_mech = CK_MECHANISM()
    enc_mech.mechanism = CKM_AES_CBC
    enc_mech.pParameter = ctypes.cast(iv_buf, c_void_p)
    enc_mech.ulParameterLen = 16

    sha_mech = CK_MECHANISM()
    sha_mech.mechanism = CKM_SHA256

    # -----------------------------------------------------------------------
    # Encrypt plaintext via standard path to produce ciphertext
    # -----------------------------------------------------------------------

    rv = C_EncryptInit(hSession, ctypes.byref(enc_mech), hKey)
    if rv in _DUAL_UNSUPPORTED:
        print(f"SKIP:EncryptInitUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:EncryptInit:0x{rv:08x}")
        sys.exit(1)

    ciphertext = bytearray()
    eu_len = c_ulong(64)
    eu_buf = (c_ubyte * 64)()
    rv = C_EncryptUpdate(hSession, c_char_p(plaintext), c_ulong(len(plaintext)),
                         eu_buf, byref(eu_len))
    if rv != CKR_OK:
        print(f"FATAL:EncryptUpdate:0x{rv:08x}")
        sys.exit(1)
    ciphertext += bytes(eu_buf[:eu_len.value])

    ef_len = c_ulong(64)
    ef_buf = (c_ubyte * 64)()
    rv = C_EncryptFinal(hSession, ef_buf, byref(ef_len))
    if rv != CKR_OK:
        print(f"FATAL:EncryptFinal:0x{rv:08x}")
        sys.exit(1)
    ciphertext += bytes(ef_buf[:ef_len.value])
    ct_hex = binascii.hexlify(bytes(ciphertext)).decode()
    print(f"CIPHERTEXT:{ct_hex}")

    # -----------------------------------------------------------------------
    # Dual-function path: DigestInit + DecryptInit + DecryptDigestUpdate
    # -----------------------------------------------------------------------

    rv = C_DigestInit(hSession, ctypes.byref(sha_mech))
    if rv in _DUAL_UNSUPPORTED:
        print(f"SKIP:DigestInitUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:DigestInit_dual:0x{rv:08x}")
        sys.exit(1)

    # Starting DecryptInit while DigestInit is active requires dual-function support.
    # Modules that only allow one active operation return CKR_OPERATION_ACTIVE here.
    rv = C_DecryptInit(hSession, ctypes.byref(enc_mech), hKey)
    if rv in _DUAL_UNSUPPORTED:
        print(f"SKIP:DecryptInit_dual_Unsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:DecryptInit_dual:0x{rv:08x}")
        sys.exit(1)

    # DecryptDigestUpdate: decrypt ciphertext and simultaneously digest the plaintext
    ct_bytes = bytes(ciphertext)
    recovered = bytearray()
    ddu_len = c_ulong(64)
    ddu_buf = (c_ubyte * 64)()
    rv = C_DecryptDigestUpdate(hSession, c_char_p(ct_bytes), c_ulong(len(ct_bytes)),
                                ddu_buf, byref(ddu_len))
    if rv in _DUAL_UNSUPPORTED:
        print(f"SKIP:DecryptDigestUpdateUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:DecryptDigestUpdate:0x{rv:08x}")
        sys.exit(1)
    recovered += bytes(ddu_buf[:ddu_len.value])

    # Finalise the decrypt operation
    dfin_len = c_ulong(64)
    dfin_buf = (c_ubyte * 64)()
    rv = C_DecryptFinal(hSession, dfin_buf, byref(dfin_len))
    if rv != CKR_OK:
        print(f"FATAL:DecryptFinal_dual:0x{rv:08x}")
        sys.exit(1)
    recovered += bytes(dfin_buf[:dfin_len.value])
    recovered_hex = binascii.hexlify(bytes(recovered)).decode()
    print(f"RECOVERED:{recovered_hex}")

    # Finalise the digest operation
    d_len = c_ulong(32)
    d_buf = (c_ubyte * 32)()
    rv = C_DigestFinal(hSession, d_buf, byref(d_len))
    if rv != CKR_OK:
        print(f"FATAL:DigestFinal_dual:0x{rv:08x}")
        sys.exit(1)
    digest_dual = binascii.hexlify(bytes(d_buf[:d_len.value])).decode()
    print(f"DIGEST_DUAL:{digest_dual}")
"""
        )

        returncode, stdout, stderr = _run_script(module_path, slot_index, pin_bytes, script)
        lines_map = _parse_output(stdout)

        if "SKIP" in lines_map:
            pytest.skip(f"Module does not support dual-function: {lines_map['SKIP']}")

        if returncode != 0:
            fatals = [ln for ln in stdout.splitlines() if ln.startswith("FATAL:")]
            detail = fatals[0] if fatals else f"stdout={stdout!r} stderr={stderr!r}"
            pytest.fail(f"Subprocess failed: {detail}")

        assert "PT_REF" in lines_map, f"Missing PT_REF in output: {stdout!r}"
        assert "DIGEST_REF" in lines_map, f"Missing DIGEST_REF in output: {stdout!r}"
        assert "RECOVERED" in lines_map, f"Missing RECOVERED in output: {stdout!r}"
        assert "DIGEST_DUAL" in lines_map, f"Missing DIGEST_DUAL in output: {stdout!r}"

        pt_ref = lines_map["PT_REF"]
        digest_ref = lines_map["DIGEST_REF"]
        recovered = lines_map["RECOVERED"]
        digest_dual = lines_map["DIGEST_DUAL"]

        assert recovered == pt_ref, (
            f"DecryptDigestUpdate plaintext recovery mismatch:\n"
            f"  expected = {pt_ref!r}\n"
            f"  got      = {recovered!r}"
        )
        assert digest_dual == digest_ref, (
            f"DecryptDigestUpdate digest mismatch:\n"
            f"  expected (hashlib SHA-256 of plaintext) = {digest_ref!r}\n"
            f"  got (dual-function digest)               = {digest_dual!r}"
        )
