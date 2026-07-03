"""Probe: PKCS#11 dual-function combined operations (digest+encrypt / decrypt+digest).

Ports the f-string child-script bodies from testcases/test_dual_function.py into
dispatchable probe functions.  Each probe drives the encrypt / decrypt / digest
init-update-final C-level steps directly (python-pkcs11 exposes no high-level wrappers
for the dual-function operations) to compare a combined dual-function run against the
equivalent separate operations.

Output protocol lines (``KEY_GENERATED:...``, ``DIGEST_REF:...``, ``PT_REF:...``,
``CT_REF:...``, ``CT_DUAL:...``, ``CIPHERTEXT:...``, ``RECOVERED:...``, ``DIGEST_DUAL:...``,
``SKIP:...``, ``FATAL:...``) are byte-identical to the original generated scripts so the
parent (parse_output + assert_correct + the classify crash/not-operational path) requires
no changes.

All probes run at Level.LOGIN; the parent forwards the PIN via
``run_probe(pin=pin_from_config(...))`` -> ``_P11CHECK_PIN`` (Invariant I3).  The PIN is
never embedded in the probe source or params.

Dispatch on ``params.extra["probe"]``:
  ``"digest_encrypt_update"`` -- C_DigestEncryptUpdate vs separate SHA-256 + AES-CBC encrypt.
  ``"decrypt_digest_update"`` -- C_DecryptDigestUpdate vs reference plaintext + SHA-256.
"""

from __future__ import annotations

import binascii
import ctypes
import hashlib
import sys
from collections.abc import Callable
from typing import Any

from pkcs11_check.raw import CK_ATTRIBUTE_PTR, CK_MECHANISM, CK_OBJECT_HANDLE
from pkcs11_check.raw.pack import attr_bool, attr_ulong, mech_simple, template
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKK_AES,
    CKM_AES_CBC,
    CKM_AES_KEY_GEN,
    CKM_SHA256,
    CKO_SECRET_KEY,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main

_DUAL_UNSUPPORTED = (CKR_FUNCTION_NOT_SUPPORTED, CKR_OPERATION_ACTIVE)


def _template_ptr(attrs: Any) -> Any:
    return ctypes.cast(attrs.ptr, CK_ATTRIBUTE_PTR)


def _byte_array(data: bytes) -> Any:
    return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)


def _generate_key(raw: Any, sh: int) -> Any:
    """Generate a session AES-256 key; SKIP/FATAL + exit on the same paths as the legacy child."""
    attrs = template(
        attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
        attr_ulong(CKA_KEY_TYPE, CKK_AES),
        attr_ulong(CKA_VALUE_LEN, 32),
        attr_bool(CKA_ENCRYPT, True),
        attr_bool(CKA_DECRYPT, True),
        attr_bool(CKA_TOKEN, False),
    )
    kg_mech = mech_simple(CKM_AES_KEY_GEN)

    h_key = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKey(
        sh, kg_mech.byref(), _template_ptr(attrs), attrs.count, ctypes.byref(h_key)
    )
    if rv == CKR_FUNCTION_NOT_SUPPORTED:
        print(f"SKIP:GenerateKeyUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:GenerateKey:0x{rv:08x}")
        sys.exit(1)
    print(f"KEY_GENERATED:{h_key.value}")
    return h_key


def _run_digest_encrypt_update(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_DigestEncryptUpdate vs separate SHA-256 digest + AES-CBC encrypt on one session."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh

    byref = ctypes.byref
    c_ulong = ctypes.c_ulong
    c_ubyte = ctypes.c_ubyte
    c_void_p = ctypes.c_void_p

    h_key = _generate_key(raw, sh)

    # 16-byte IV; two 16-byte plaintext blocks (AES-CBC requires block alignment)
    iv = b"\x00" * 16
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
    rv = raw.C_EncryptInit(sh, ctypes.byref(enc_mech), h_key)
    if rv in _DUAL_UNSUPPORTED:
        print(f"SKIP:EncryptInitUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:EncryptInit_ref:0x{rv:08x}")
        sys.exit(1)

    ct_ref = bytearray()
    out_len = c_ulong(64)
    out_buf = (c_ubyte * 64)()
    rv = raw.C_EncryptUpdate(sh, data_buf, c_ulong(len(data)), out_buf, byref(out_len))
    if rv != CKR_OK:
        print(f"FATAL:EncryptUpdate_ref:0x{rv:08x}")
        sys.exit(1)
    ct_ref += bytes(out_buf[: out_len.value])

    fin_len = c_ulong(64)
    fin_buf = (c_ubyte * 64)()
    rv = raw.C_EncryptFinal(sh, fin_buf, byref(fin_len))
    if rv != CKR_OK:
        print(f"FATAL:EncryptFinal_ref:0x{rv:08x}")
        sys.exit(1)
    ct_ref += bytes(fin_buf[: fin_len.value])
    ct_ref_hex = binascii.hexlify(bytes(ct_ref)).decode()
    print(f"CT_REF:{ct_ref_hex}")

    # -----------------------------------------------------------------------
    # Dual-function path: DigestInit + EncryptInit + DigestEncryptUpdate
    # -----------------------------------------------------------------------

    rv = raw.C_DigestInit(sh, ctypes.byref(sha_mech))
    if rv in _DUAL_UNSUPPORTED:
        print(f"SKIP:DigestInitUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:DigestInit_dual:0x{rv:08x}")
        sys.exit(1)

    # Starting EncryptInit while DigestInit is active requires dual-function support.
    # Modules that only allow one active operation return CKR_OPERATION_ACTIVE here.
    rv = raw.C_EncryptInit(sh, ctypes.byref(enc_mech), h_key)
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
    rv = raw.C_DigestEncryptUpdate(sh, data_buf, c_ulong(len(data)), deu_buf, byref(deu_len))
    if rv in _DUAL_UNSUPPORTED:
        print(f"SKIP:DigestEncryptUpdateUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:DigestEncryptUpdate:0x{rv:08x}")
        sys.exit(1)
    ct_dual += bytes(deu_buf[: deu_len.value])

    # Finalise the encrypt operation
    efin_len = c_ulong(64)
    efin_buf = (c_ubyte * 64)()
    rv = raw.C_EncryptFinal(sh, efin_buf, byref(efin_len))
    if rv != CKR_OK:
        print(f"FATAL:EncryptFinal_dual:0x{rv:08x}")
        sys.exit(1)
    ct_dual += bytes(efin_buf[: efin_len.value])
    ct_dual_hex = binascii.hexlify(bytes(ct_dual)).decode()
    print(f"CT_DUAL:{ct_dual_hex}")

    # Finalise the digest operation
    d_len = c_ulong(32)
    d_buf = (c_ubyte * 32)()
    rv = raw.C_DigestFinal(sh, d_buf, byref(d_len))
    if rv != CKR_OK:
        print(f"FATAL:DigestFinal_dual:0x{rv:08x}")
        sys.exit(1)
    digest_dual = binascii.hexlify(bytes(d_buf[: d_len.value])).decode()
    print(f"DIGEST_DUAL:{digest_dual}")


def _run_decrypt_digest_update(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_DecryptDigestUpdate vs reference plaintext + SHA-256 digest on one session."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh

    byref = ctypes.byref
    c_ulong = ctypes.c_ulong
    c_ubyte = ctypes.c_ubyte
    c_void_p = ctypes.c_void_p

    h_key = _generate_key(raw, sh)

    # 16-byte IV; two 16-byte plaintext blocks (AES-CBC requires block alignment)
    iv = b"\x00" * 16
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

    rv = raw.C_EncryptInit(sh, ctypes.byref(enc_mech), h_key)
    if rv in _DUAL_UNSUPPORTED:
        print(f"SKIP:EncryptInitUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:EncryptInit:0x{rv:08x}")
        sys.exit(1)

    ciphertext = bytearray()
    eu_len = c_ulong(64)
    eu_buf = (c_ubyte * 64)()
    rv = raw.C_EncryptUpdate(sh, plaintext_buf, c_ulong(len(plaintext)), eu_buf, byref(eu_len))
    if rv != CKR_OK:
        print(f"FATAL:EncryptUpdate:0x{rv:08x}")
        sys.exit(1)
    ciphertext += bytes(eu_buf[: eu_len.value])

    ef_len = c_ulong(64)
    ef_buf = (c_ubyte * 64)()
    rv = raw.C_EncryptFinal(sh, ef_buf, byref(ef_len))
    if rv != CKR_OK:
        print(f"FATAL:EncryptFinal:0x{rv:08x}")
        sys.exit(1)
    ciphertext += bytes(ef_buf[: ef_len.value])
    ct_hex = binascii.hexlify(bytes(ciphertext)).decode()
    print(f"CIPHERTEXT:{ct_hex}")

    # -----------------------------------------------------------------------
    # Dual-function path: DigestInit + DecryptInit + DecryptDigestUpdate
    # -----------------------------------------------------------------------

    rv = raw.C_DigestInit(sh, ctypes.byref(sha_mech))
    if rv in _DUAL_UNSUPPORTED:
        print(f"SKIP:DigestInitUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:DigestInit_dual:0x{rv:08x}")
        sys.exit(1)

    # Starting DecryptInit while DigestInit is active requires dual-function support.
    # Modules that only allow one active operation return CKR_OPERATION_ACTIVE here.
    rv = raw.C_DecryptInit(sh, ctypes.byref(enc_mech), h_key)
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
    rv = raw.C_DecryptDigestUpdate(sh, ct_buf, c_ulong(len(ct_bytes)), ddu_buf, byref(ddu_len))
    if rv in _DUAL_UNSUPPORTED:
        print(f"SKIP:DecryptDigestUpdateUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:DecryptDigestUpdate:0x{rv:08x}")
        sys.exit(1)
    recovered += bytes(ddu_buf[: ddu_len.value])

    # Finalise the decrypt operation
    dfin_len = c_ulong(64)
    dfin_buf = (c_ubyte * 64)()
    rv = raw.C_DecryptFinal(sh, dfin_buf, byref(dfin_len))
    if rv != CKR_OK:
        print(f"FATAL:DecryptFinal_dual:0x{rv:08x}")
        sys.exit(1)
    recovered += bytes(dfin_buf[: dfin_len.value])
    recovered_hex = binascii.hexlify(bytes(recovered)).decode()
    print(f"RECOVERED:{recovered_hex}")

    # Finalise the digest operation
    d_len = c_ulong(32)
    d_buf = (c_ubyte * 32)()
    rv = raw.C_DigestFinal(sh, d_buf, byref(d_len))
    if rv != CKR_OK:
        print(f"FATAL:DigestFinal_dual:0x{rv:08x}")
        sys.exit(1)
    digest_dual = binascii.hexlify(bytes(d_buf[: d_len.value])).decode()
    print(f"DIGEST_DUAL:{digest_dual}")


_DISPATCH: dict[str, Callable[[ProbeContext, dict[str, Any]], None]] = {
    "digest_encrypt_update": _run_digest_encrypt_update,
    "decrypt_digest_update": _run_decrypt_digest_update,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe: str = extra["probe"]
    handler = _DISPATCH.get(probe)
    if handler is None:
        raise ValueError(f"dual_function probe: unknown 'probe' value {probe!r}")
    handler(ctx, extra)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
