"""Probe: C_Digest / C_Sign (HMAC) with oversized (64-bit) input lengths.

Truncation probe for C_Digest and C_Sign (HMAC-SHA256): pass a length of
0x100000008 (4 GiB + 8) backed by a demand-zero honeypot.  A module that
casts ulDataLen to 32 bits silently hashes / signs only the first 8 bytes.
Output protocol is preserved verbatim for the parent classifier in
security/test_digest_length_truncation.py.

Dispatch on ``params.extra["which"]``:
  ``"digest"``      — C_DigestInit + C_Digest oversized-length probe
                      (prints TARGET_RV + DIGEST_HEX when CKR_OK)
  ``"hmac_sha256"`` — C_CreateObject + C_SignInit + C_Sign oversized-length probe
                      (prints TARGET_RV + HMAC_HEX when CKR_OK)

Required extra keys for ``"digest"``:
  ``"which"``    — ``"digest"``
  ``"mech_id"``  — int, the CKM_ mechanism value

Required extra keys for ``"hmac_sha256"``:
  ``"which"``    — ``"hmac_sha256"``
"""

from __future__ import annotations

import ctypes
from typing import Any

from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKK_GENERIC_SECRET,
    CKM_SHA256_HMAC,
    CKO_SECRET_KEY,
    CKR_OK,
)
from pkcs11_check.testcases._probes.honeypot import (
    SETUP_XFAIL_PREFIX,
    HoneypotUnavailable,
    demand_zero_buffer,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main

# 0x100000008: low 32 bits == 8, so a (uint32_t)/(word32) cast processes only 8 bytes.
_OVERSIZE_LEN = (1 << 32) + 8


def _run_digest(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """C_Digest oversized-length probe.

    Prints ``SETUP_XFAIL:<reason>`` on honeypot or DigestInit failure.
    Prints ``TARGET_RV:0x%08x`` unconditionally once C_Digest is called.
    Prints ``DIGEST_HEX:<hex>`` when rv == CKR_OK.
    """
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    mech_id = int(extra["mech_id"])

    try:
        buf = demand_zero_buffer()
    except HoneypotUnavailable as exc:
        print(f"{SETUP_XFAIL_PREFIX}{exc}")
        return

    mech = CK_MECHANISM()
    mech.mechanism = mech_id
    mech.pParameter = None
    mech.ulParameterLen = 0

    rv = ctx.raw.C_DigestInit(sh, ctypes.byref(mech))
    if rv == CKR_OK:
        out_buf = (ctypes.c_ubyte * 64)()
        out_len = CK_ULONG(64)
        rv2 = ctx.raw.C_Digest(
            sh,
            buf,
            _OVERSIZE_LEN,
            out_buf,
            ctypes.byref(out_len),
        )
        print(f"TARGET_RV:0x{rv2:08x}")
        if rv2 == CKR_OK:
            print("DIGEST_HEX:" + bytes(out_buf[: out_len.value]).hex())
    else:
        print(f"SETUP_XFAIL:C_DigestInit not operational 0x{rv:08x}")


def _run_hmac_sha256(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_Sign (CKM_SHA256_HMAC) oversized-length probe.

    Prints ``SETUP_XFAIL:<reason>`` on key-import, honeypot, or SignInit failure.
    Prints ``TARGET_RV:0x%08x`` unconditionally once C_Sign is called.
    Prints ``HMAC_HEX:<hex>`` when rv == CKR_OK.
    """
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    # Import a 32-byte HMAC signing key via C_CreateObject.
    key_bytes = (ctypes.c_ubyte * 32)(*range(32))
    cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
    kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
    sign_true = ctypes.c_ubyte(1)
    token_false = ctypes.c_ubyte(0)

    attrs = (CK_ATTRIBUTE * 5)()
    attrs[0].type = CKA_CLASS
    attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    attrs[0].ulValueLen = ctypes.sizeof(cls_val)
    attrs[1].type = CKA_KEY_TYPE
    attrs[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
    attrs[1].ulValueLen = ctypes.sizeof(kt_val)
    attrs[2].type = CKA_VALUE
    attrs[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
    attrs[2].ulValueLen = 32
    attrs[3].type = CKA_SIGN
    attrs[3].pValue = ctypes.cast(ctypes.pointer(sign_true), ctypes.c_void_p)
    attrs[3].ulValueLen = 1
    attrs[4].type = CKA_TOKEN
    attrs[4].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    attrs[4].ulValueLen = 1

    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)), 5, ctypes.byref(key)
    )
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:HMAC key import rejected 0x{rv:08x}")
        return

    try:
        try:
            buf = demand_zero_buffer()
        except HoneypotUnavailable as exc:
            print(f"{SETUP_XFAIL_PREFIX}{exc}")
            return

        mech = CK_MECHANISM()
        mech.mechanism = CKM_SHA256_HMAC
        mech.pParameter = None
        mech.ulParameterLen = 0

        rv2 = raw.C_SignInit(sh, ctypes.byref(mech), key.value)
        if rv2 == CKR_OK:
            out_buf = (ctypes.c_ubyte * 64)()
            out_len = CK_ULONG(64)
            rv3 = raw.C_Sign(
                sh,
                buf,
                _OVERSIZE_LEN,
                out_buf,
                ctypes.byref(out_len),
            )
            print(f"TARGET_RV:0x{rv3:08x}")
            if rv3 == CKR_OK:
                print("HMAC_HEX:" + bytes(out_buf[: out_len.value]).hex())
        else:
            print(f"SETUP_XFAIL:C_SignInit not operational 0x{rv2:08x}")
    finally:
        destroy_quietly(raw, sh, key.value)


_DISPATCH = {
    "digest": _run_digest,
    "hmac_sha256": _run_hmac_sha256,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    which = extra["which"]
    if which not in _DISPATCH:
        raise ValueError(f"digest_length probe: unknown 'which' value {which!r}")
    _DISPATCH[which](ctx, extra)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
