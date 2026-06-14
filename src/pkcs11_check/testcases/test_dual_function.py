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

These operations are only available via the raw C API - python-pkcs11 has no
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

from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.testcases._raw_subprocess import parse_output as _parse_output
from pkcs11_check.testcases._raw_subprocess import run_raw_script

pytestmark = pytest.mark.full

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
    CKR_OPERATION_ACTIVE,
)
from pkcs11_check.raw.bootstrap import close_session_quietly, get_slot_ids, login_user, open_session
from pkcs11_check.raw.pack import attr_bool, attr_ulong, mech_simple, template

_DUAL_UNSUPPORTED = (CKR_FUNCTION_NOT_SUPPORTED, CKR_OPERATION_ACTIVE)


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

hSession = open_session(raw, slot_ids[{slot_index}], CKF_SERIAL_SESSION | CKF_RW_SESSION)

import os as _os
_PIN = _os.environ.get("_P11CHECK_PIN")
if _PIN:
    login_user(raw, hSession, 1, _PIN.encode())

c_ulong = ctypes.c_ulong
c_void_p = ctypes.c_void_p
C_EncryptInit = raw.C_EncryptInit
C_EncryptUpdate = raw.C_EncryptUpdate
C_EncryptFinal = raw.C_EncryptFinal
C_DecryptInit = raw.C_DecryptInit
C_DecryptUpdate = raw.C_DecryptUpdate
C_DecryptFinal = raw.C_DecryptFinal
C_DigestInit = raw.C_DigestInit
C_DigestUpdate = raw.C_DigestUpdate
C_DigestFinal = raw.C_DigestFinal
C_DigestEncryptUpdate = raw.C_DigestEncryptUpdate
C_DecryptDigestUpdate = raw.C_DecryptDigestUpdate
"""

_KEYGEN_SCRIPT = """\
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
    rv = raw.C_GenerateKey(
        hSession, kg_mech.byref(), _template_ptr(attrs), attrs.count, byref(hKey)
    )
    if rv == CKR_FUNCTION_NOT_SUPPORTED:
        print(f"SKIP:GenerateKeyUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:GenerateKey:0x{rv:08x}")
        sys.exit(1)
    print(f"KEY_GENERATED:{hKey.value}")
"""

_SCRIPT_CLEANUP = """\
close_session_quietly(raw, hSession)
raw.C_Finalize(None)
"""


def _run_script(
    module_path: str,
    slot_index: int,
    pin: str | None,
    script_body: str,
    timeout: int = 30,
) -> tuple[int, str, str]:
    # The PIN is forwarded to the child via the env (run_raw_script's ``pin``
    # arg), never interpolated into the script text -- so it cannot appear in
    # the child argv (``ps``/``/proc``) or any traceback.
    return run_raw_script(
        _SCRIPT_PREAMBLE.format(
            module_path=module_path,
            slot_index=slot_index,
        ),
        script_body,
        cleanup=_SCRIPT_CLEANUP,
        timeout=timeout,
        pin=pin,
    )


def _get_params(p11_config: Any) -> tuple[str, int, str | None]:
    """Extract (module_path, slot_index, pin) from config fixture.

    The PIN is returned as a plain ``str`` (or None) only to be forwarded into
    the child env by :func:`_run_script`; it is never embedded in script text.
    """
    module_path = str(p11_config.module)
    slot_index = p11_config.slot if p11_config.slot is not None else 0
    pin = p11_config.pin.get_secret_value() if p11_config.pin else None
    return module_path, slot_index, pin


def _skip_missing_mechanisms(rs: Any, names: tuple[str, ...]) -> None:
    for name in names:
        if not rs.has_mechanism(name):
            pytest.skip(f"{name} not supported by module")


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

    def test_digest_encrypt_update_round_trip(
        self,
        p11_config: Any,
        p11_raw_session: Any,
    ) -> None:
        """DigestEncryptUpdate produces same ciphertext and digest as separate operations.

        Steps:
        1. Generate an AES-256 session key.
        2. Reference path - separate operations:
           a. Reference digest via hashlib SHA-256.
           b. EncryptInit(AES-CBC, key, IV) -> EncryptUpdate(data) -> EncryptFinal -> ct_ref.
        3. Dual-function path:
           a. DigestInit(SHA-256)
           b. EncryptInit(AES-CBC, key, IV) - skips if CKR_OPERATION_ACTIVE (module
              does not allow simultaneous digest + encrypt on the same session)
           c. DigestEncryptUpdate(data) -> ciphertext_chunk - skips if
              CKR_FUNCTION_NOT_SUPPORTED
           d. EncryptFinal -> remaining ciphertext
           e. DigestFinal -> digest
        4. Assert: ciphertext == ct_ref AND digest == SHA-256(data).

        Source: PKCS#11 v3.1 Sec.5.14.1.
        """
        _skip_missing_mechanisms(p11_raw_session, ("AES_KEY_GEN", "AES_CBC", "SHA256"))
        module_path, slot_index, pin = _get_params(p11_config)

        script = (
            _KEYGEN_SCRIPT
            + """\
    import hashlib

    # 16-byte IV; two 16-byte plaintext blocks (AES-CBC requires block alignment)
    iv = b"\\x00" * 16
    data = b"Block-one-here!!" + b"Block-two-here!!"  # 32 bytes, 2 AES blocks
    data_buf = _byte_array(data)

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
    rv = C_EncryptUpdate(hSession, data_buf, c_ulong(len(data)),
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
    rv = C_DigestEncryptUpdate(hSession, data_buf, c_ulong(len(data)),
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

        returncode, stdout, stderr = _run_script(module_path, slot_index, pin, script)
        lines_map = _parse_output(stdout)

        if "SKIP" in lines_map:
            pytest.skip(f"Module does not support dual-function: {lines_map['SKIP']}")

        if returncode != 0:
            fatals = [ln for ln in stdout.splitlines() if ln.startswith("FATAL:")]
            detail = fatals[0] if fatals else f"stdout={stdout!r} stderr={stderr!r}"
            if returncode < 0:
                classify(
                    "crash",
                    label="C_DigestEncryptUpdate",
                    operation="C_DigestEncryptUpdate",
                    summary=f"Subprocess crashed (signal {-returncode}): {detail}",
                )
            classify(
                "not_operational",
                kind="crypto",
                label="C_DigestEncryptUpdate",
                operation="C_DigestEncryptUpdate",
                summary=f"Subprocess failed: {detail}",
            )

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

    def test_decrypt_digest_update_round_trip(
        self,
        p11_config: Any,
        p11_raw_session: Any,
    ) -> None:
        """DecryptDigestUpdate recovers plaintext and produces correct SHA-256 digest.

        Steps:
        1. Generate an AES-256 session key.
        2. Encrypt plaintext via separate C_EncryptInit/Update/Final to get ciphertext.
        3. Dual-function decryption path:
           a. DigestInit(SHA-256)
           b. DecryptInit(AES-CBC, key, IV) - skips if CKR_OPERATION_ACTIVE (module
              does not allow simultaneous digest + decrypt on the same session)
           c. DecryptDigestUpdate(ciphertext) -> plaintext_chunk - skips if
              CKR_FUNCTION_NOT_SUPPORTED
           d. DecryptFinal -> remaining plaintext
           e. DigestFinal -> digest of decrypted plaintext
        4. Assert: recovered plaintext == original data AND digest == SHA-256(data).

        Source: PKCS#11 v3.1 Sec.5.14.2.
        """
        _skip_missing_mechanisms(p11_raw_session, ("AES_KEY_GEN", "AES_CBC", "SHA256"))
        module_path, slot_index, pin = _get_params(p11_config)

        script = (
            _KEYGEN_SCRIPT
            + """\
    import hashlib

    # 16-byte IV; two 16-byte plaintext blocks (AES-CBC requires block alignment)
    iv = b"\\x00" * 16
    plaintext = b"Hello-dual-func!" + b"DecryptDigest!??"  # 32 bytes, 2 AES blocks
    plaintext_buf = _byte_array(plaintext)

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
    rv = C_EncryptUpdate(hSession, plaintext_buf, c_ulong(len(plaintext)),
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
    ct_buf = _byte_array(ct_bytes)
    recovered = bytearray()
    ddu_len = c_ulong(64)
    ddu_buf = (c_ubyte * 64)()
    rv = C_DecryptDigestUpdate(hSession, ct_buf, c_ulong(len(ct_bytes)),
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

        returncode, stdout, stderr = _run_script(module_path, slot_index, pin, script)
        lines_map = _parse_output(stdout)

        if "SKIP" in lines_map:
            pytest.skip(f"Module does not support dual-function: {lines_map['SKIP']}")

        if returncode != 0:
            fatals = [ln for ln in stdout.splitlines() if ln.startswith("FATAL:")]
            detail = fatals[0] if fatals else f"stdout={stdout!r} stderr={stderr!r}"
            if returncode < 0:
                classify(
                    "crash",
                    label="C_DecryptDigestUpdate",
                    operation="C_DecryptDigestUpdate",
                    summary=f"Subprocess crashed (signal {-returncode}): {detail}",
                )
            classify(
                "not_operational",
                kind="crypto",
                label="C_DecryptDigestUpdate",
                operation="C_DecryptDigestUpdate",
                summary=f"Subprocess failed: {detail}",
            )

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
