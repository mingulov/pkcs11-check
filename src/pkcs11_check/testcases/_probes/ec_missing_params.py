"""Probe: EC keys imported without ``CKA_EC_PARAMS``.

An EC key created without ``CKA_EC_PARAMS`` has no curve.  A conformant module must
reject the incomplete template (e.g. ``CKR_TEMPLATE_INCOMPLETE``) and must never
dereference a missing curve pointer during create / C_GetAttributeValue / C_Sign /
C_Verify / C_DeriveKey.

Dispatch on ``params.extra["which"]``:
  ``"public_no_params"`` — EC public (CLASS+KEY_TYPE+EC_POINT, no EC_PARAMS)
  ``"get_ec_params_private"`` — EC private, C_GetAttributeValue(CKA_EC_PARAMS)
  ``"get_ec_point_private"`` — EC private (3-attr), C_GetAttributeValue(CKA_EC_POINT)
  ``"get_ec_point_public"`` — EC public (2-attr bare), C_GetAttributeValue(CKA_EC_POINT)
  ``"ecdh_derive"`` — EC private (3-attr), C_DeriveKey(CKM_ECDH1_DERIVE)
  ``"sign_private"`` — EC private (4-attr + CKA_SIGN), C_SignInit + C_Sign(CKM_ECDSA)
  ``"verify_public"`` — EC public (4-attr + CKA_VERIFY), C_VerifyInit + C_Verify(CKM_ECDSA)

Output protocol (preserved verbatim for parent classifier):
  CREATE_RV:0x%08x       — return value of C_CreateObject (always printed)
  GETATTR_RV:0x%08x      — return value of C_GetAttributeValue (only when CREATE_RV==CKR_OK)
  DERIVE_RV:0x%08x       — return value of C_DeriveKey (only when CREATE_RV==CKR_OK)
  SIGNINIT_RV:0x%08x     — return value of C_SignInit (only when CREATE_RV==CKR_OK)
  SIGN_RV:0x%08x         — return value of C_Sign (only when SIGNINIT_RV==CKR_OK)
  VERIFYINIT_RV:0x%08x   — return value of C_VerifyInit (only when CREATE_RV==CKR_OK)
  VERIFY_RV:0x%08x       — return value of C_Verify (only when VERIFYINIT_RV==CKR_OK)

Required extra keys:
  ``"which"``  — one of the dispatch strings listed above
"""

from __future__ import annotations

import ctypes
from typing import Any

from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_ECDH1_DERIVE_PARAMS,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_KEY_TYPE,
    CKA_SIGN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKD_NULL,
    CKK_EC,
    CKK_GENERIC_SECRET,
    CKM_ECDH1_DERIVE,
    CKM_ECDSA,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKR_OK,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main

# 67-byte DER OCTET STRING wrapping an X9.63 uncompressed point (04 41 04 X||Y).
# Bytes are arbitrary; a conformant module rejects before validating the point.
_POINT = bytes([0x04, 0x41, 0x04] + [0x11] * 64)


def _run_public_no_params(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_CreateObject EC public (CLASS+KEY_TYPE+EC_POINT, no EC_PARAMS).

    Prints ``CREATE_RV:0x%08x`` unconditionally.
    """
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    cls_val = CK_ULONG(CKO_PUBLIC_KEY)
    kt_val = CK_ULONG(CKK_EC)
    point_buf = (ctypes.c_ubyte * len(_POINT))(*_POINT)

    attrs = (CK_ATTRIBUTE * 3)()
    attrs[0].type = CKA_CLASS
    attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    attrs[0].ulValueLen = ctypes.sizeof(cls_val)
    attrs[1].type = CKA_KEY_TYPE
    attrs[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
    attrs[1].ulValueLen = ctypes.sizeof(kt_val)
    attrs[2].type = CKA_EC_POINT
    attrs[2].pValue = ctypes.cast(point_buf, ctypes.c_void_p)
    attrs[2].ulValueLen = len(_POINT)

    obj = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)), 3, ctypes.byref(obj)
    )
    print(f"CREATE_RV:0x{rv:08x}")
    if rv == CKR_OK:
        destroy_quietly(raw, sh, obj.value)


def _run_get_ec_params_private(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_CreateObject EC private (3-attr), then C_GetAttributeValue(CKA_EC_PARAMS).

    Prints ``CREATE_RV:0x%08x`` unconditionally.
    Prints ``GETATTR_RV:0x%08x`` only when CREATE_RV==CKR_OK.
    """
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    scalar = (ctypes.c_ubyte * 32)(*range(1, 33))
    cls_val = CK_ULONG(CKO_PRIVATE_KEY)
    kt_val = CK_ULONG(CKK_EC)

    attrs = (CK_ATTRIBUTE * 3)()
    attrs[0].type = CKA_CLASS
    attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    attrs[0].ulValueLen = ctypes.sizeof(cls_val)
    attrs[1].type = CKA_KEY_TYPE
    attrs[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
    attrs[1].ulValueLen = ctypes.sizeof(kt_val)
    attrs[2].type = CKA_VALUE
    attrs[2].pValue = ctypes.cast(scalar, ctypes.c_void_p)
    attrs[2].ulValueLen = 32

    obj = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)), 3, ctypes.byref(obj)
    )
    print(f"CREATE_RV:0x{rv:08x}")
    if rv == CKR_OK:
        q = CK_ATTRIBUTE()
        q.type = CKA_EC_PARAMS
        q.pValue = None
        q.ulValueLen = 0
        grv = raw.C_GetAttributeValue(sh, obj, ctypes.byref(q), 1)
        print(f"GETATTR_RV:0x{grv:08x}")
        destroy_quietly(raw, sh, obj.value)


def _run_get_ec_point_private(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_CreateObject EC private (CLASS+KEY_TYPE+VALUE), then C_GetAttributeValue(CKA_EC_POINT).

    Prints ``CREATE_RV:0x%08x`` unconditionally.
    Prints ``GETATTR_RV:0x%08x`` only when CREATE_RV==CKR_OK.
    """
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    scalar = (ctypes.c_ubyte * 32)(*range(1, 33))
    cls_val = CK_ULONG(CKO_PRIVATE_KEY)
    kt_val = CK_ULONG(CKK_EC)

    attrs = (CK_ATTRIBUTE * 3)()
    attrs[0].type = CKA_CLASS
    attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    attrs[0].ulValueLen = ctypes.sizeof(cls_val)
    attrs[1].type = CKA_KEY_TYPE
    attrs[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
    attrs[1].ulValueLen = ctypes.sizeof(kt_val)
    attrs[2].type = CKA_VALUE
    attrs[2].pValue = ctypes.cast(scalar, ctypes.c_void_p)
    attrs[2].ulValueLen = 32

    obj = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)), 3, ctypes.byref(obj)
    )
    print(f"CREATE_RV:0x{rv:08x}")
    if rv == CKR_OK:
        q = CK_ATTRIBUTE()
        q.type = CKA_EC_POINT
        q.pValue = None
        q.ulValueLen = 0
        grv = raw.C_GetAttributeValue(sh, obj, ctypes.byref(q), 1)
        print(f"GETATTR_RV:0x{grv:08x}")
        destroy_quietly(raw, sh, obj.value)


def _run_get_ec_point_public(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_CreateObject EC public (CLASS+KEY_TYPE only, 2-attr), C_GetAttributeValue(CKA_EC_POINT).

    Prints ``CREATE_RV:0x%08x`` unconditionally.
    Prints ``GETATTR_RV:0x%08x`` only when CREATE_RV==CKR_OK.
    """
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    cls_val = CK_ULONG(CKO_PUBLIC_KEY)
    kt_val = CK_ULONG(CKK_EC)

    attrs = (CK_ATTRIBUTE * 2)()
    attrs[0].type = CKA_CLASS
    attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    attrs[0].ulValueLen = ctypes.sizeof(cls_val)
    attrs[1].type = CKA_KEY_TYPE
    attrs[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
    attrs[1].ulValueLen = ctypes.sizeof(kt_val)

    obj = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)), 2, ctypes.byref(obj)
    )
    print(f"CREATE_RV:0x{rv:08x}")
    if rv == CKR_OK:
        q = CK_ATTRIBUTE()
        q.type = CKA_EC_POINT
        q.pValue = None
        q.ulValueLen = 0
        grv = raw.C_GetAttributeValue(sh, obj, ctypes.byref(q), 1)
        print(f"GETATTR_RV:0x{grv:08x}")
        destroy_quietly(raw, sh, obj.value)


def _run_ecdh_derive(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_CreateObject EC private (3-attr), then C_DeriveKey(CKM_ECDH1_DERIVE).

    Prints ``CREATE_RV:0x%08x`` unconditionally.
    Prints ``DERIVE_RV:0x%08x`` only when CREATE_RV==CKR_OK.
    """
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    scalar = (ctypes.c_ubyte * 32)(*range(1, 33))
    cls_val = CK_ULONG(CKO_PRIVATE_KEY)
    kt_val = CK_ULONG(CKK_EC)
    attrs = (CK_ATTRIBUTE * 3)()
    attrs[0].type = CKA_CLASS
    attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    attrs[0].ulValueLen = ctypes.sizeof(cls_val)
    attrs[1].type = CKA_KEY_TYPE
    attrs[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
    attrs[1].ulValueLen = ctypes.sizeof(kt_val)
    attrs[2].type = CKA_VALUE
    attrs[2].pValue = ctypes.cast(scalar, ctypes.c_void_p)
    attrs[2].ulValueLen = 32

    base = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)), 3, ctypes.byref(base)
    )
    print(f"CREATE_RV:0x{rv:08x}")
    if rv == CKR_OK:
        point_buf = (ctypes.c_ubyte * len(_POINT))(*_POINT)
        params = CK_ECDH1_DERIVE_PARAMS()
        params.kdf = CKD_NULL
        params.ulSharedDataLen = 0
        params.pSharedData = None
        params.ulPublicDataLen = len(_POINT)
        params.pPublicData = ctypes.cast(point_buf, ctypes.c_void_p)
        mech = CK_MECHANISM()
        mech.mechanism = CKM_ECDH1_DERIVE
        mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
        mech.ulParameterLen = ctypes.sizeof(params)
        out_cls = CK_ULONG(CKO_SECRET_KEY)
        out_kt = CK_ULONG(CKK_GENERIC_SECRET)
        out_len = CK_ULONG(32)
        otmpl = (CK_ATTRIBUTE * 3)()
        otmpl[0].type = CKA_CLASS
        otmpl[0].pValue = ctypes.cast(ctypes.pointer(out_cls), ctypes.c_void_p)
        otmpl[0].ulValueLen = ctypes.sizeof(out_cls)
        otmpl[1].type = CKA_KEY_TYPE
        otmpl[1].pValue = ctypes.cast(ctypes.pointer(out_kt), ctypes.c_void_p)
        otmpl[1].ulValueLen = ctypes.sizeof(out_kt)
        otmpl[2].type = CKA_VALUE_LEN
        otmpl[2].pValue = ctypes.cast(ctypes.pointer(out_len), ctypes.c_void_p)
        otmpl[2].ulValueLen = ctypes.sizeof(out_len)
        derived = CK_OBJECT_HANDLE(0)
        drv = raw.C_DeriveKey(
            sh,
            ctypes.byref(mech),
            base,
            ctypes.cast(otmpl, ctypes.POINTER(CK_ATTRIBUTE)),
            3,
            ctypes.byref(derived),
        )
        print(f"DERIVE_RV:0x{drv:08x}")
        if drv == CKR_OK:
            destroy_quietly(raw, sh, derived.value)
        destroy_quietly(raw, sh, base.value)


def _run_sign_private(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_CreateObject EC private (4-attr with CKA_SIGN), then C_SignInit+C_Sign.

    Prints ``CREATE_RV:0x%08x`` unconditionally.
    Prints ``SIGNINIT_RV:0x%08x`` only when CREATE_RV==CKR_OK.
    Prints ``SIGN_RV:0x%08x`` only when SIGNINIT_RV==CKR_OK.
    """
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    scalar = (ctypes.c_ubyte * 32)(*range(1, 33))
    cls_val = CK_ULONG(CKO_PRIVATE_KEY)
    kt_val = CK_ULONG(CKK_EC)
    sign_true = ctypes.c_ubyte(1)

    attrs = (CK_ATTRIBUTE * 4)()
    attrs[0].type = CKA_CLASS
    attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    attrs[0].ulValueLen = ctypes.sizeof(cls_val)
    attrs[1].type = CKA_KEY_TYPE
    attrs[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
    attrs[1].ulValueLen = ctypes.sizeof(kt_val)
    attrs[2].type = CKA_VALUE
    attrs[2].pValue = ctypes.cast(scalar, ctypes.c_void_p)
    attrs[2].ulValueLen = 32
    attrs[3].type = CKA_SIGN
    attrs[3].pValue = ctypes.cast(ctypes.pointer(sign_true), ctypes.c_void_p)
    attrs[3].ulValueLen = 1

    obj = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)), 4, ctypes.byref(obj)
    )
    print(f"CREATE_RV:0x{rv:08x}")
    if rv == CKR_OK:
        digest = (ctypes.c_ubyte * 32)(*range(32))
        mech = CK_MECHANISM()
        mech.mechanism = CKM_ECDSA
        mech.pParameter = None
        mech.ulParameterLen = 0
        irv = raw.C_SignInit(sh, ctypes.byref(mech), obj)
        print(f"SIGNINIT_RV:0x{irv:08x}")
        if irv == CKR_OK:
            sig_buf = (ctypes.c_ubyte * 256)()
            sig_len = CK_ULONG(0)
            srv = raw.C_Sign(sh, digest, 32, sig_buf, ctypes.byref(sig_len))
            print(f"SIGN_RV:0x{srv:08x}")
        destroy_quietly(raw, sh, obj.value)


def _run_verify_public(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_CreateObject EC public (4-attr with CKA_VERIFY), then C_VerifyInit+C_Verify.

    Prints ``CREATE_RV:0x%08x`` unconditionally.
    Prints ``VERIFYINIT_RV:0x%08x`` only when CREATE_RV==CKR_OK.
    Prints ``VERIFY_RV:0x%08x`` only when VERIFYINIT_RV==CKR_OK.
    """
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    cls_val = CK_ULONG(CKO_PUBLIC_KEY)
    kt_val = CK_ULONG(CKK_EC)
    point_buf = (ctypes.c_ubyte * len(_POINT))(*_POINT)
    verify_true = ctypes.c_ubyte(1)

    attrs = (CK_ATTRIBUTE * 4)()
    attrs[0].type = CKA_CLASS
    attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    attrs[0].ulValueLen = ctypes.sizeof(cls_val)
    attrs[1].type = CKA_KEY_TYPE
    attrs[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
    attrs[1].ulValueLen = ctypes.sizeof(kt_val)
    attrs[2].type = CKA_EC_POINT
    attrs[2].pValue = ctypes.cast(point_buf, ctypes.c_void_p)
    attrs[2].ulValueLen = len(_POINT)
    attrs[3].type = CKA_VERIFY
    attrs[3].pValue = ctypes.cast(ctypes.pointer(verify_true), ctypes.c_void_p)
    attrs[3].ulValueLen = 1

    obj = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)), 4, ctypes.byref(obj)
    )
    print(f"CREATE_RV:0x{rv:08x}")
    if rv == CKR_OK:
        digest = (ctypes.c_ubyte * 32)(*range(32))
        sig_bytes = [0x30, 0x44, 0x02, 0x20] + [0x11] * 32 + [0x02, 0x20] + [0x22] * 32
        sig_buf = (ctypes.c_ubyte * 72)(*sig_bytes)
        mech = CK_MECHANISM()
        mech.mechanism = CKM_ECDSA
        mech.pParameter = None
        mech.ulParameterLen = 0
        irv = raw.C_VerifyInit(sh, ctypes.byref(mech), obj)
        print(f"VERIFYINIT_RV:0x{irv:08x}")
        if irv == CKR_OK:
            vrv = raw.C_Verify(sh, digest, 32, sig_buf, 72)
            print(f"VERIFY_RV:0x{vrv:08x}")
        destroy_quietly(raw, sh, obj.value)


_DISPATCH = {
    "public_no_params": _run_public_no_params,
    "get_ec_params_private": _run_get_ec_params_private,
    "get_ec_point_private": _run_get_ec_point_private,
    "get_ec_point_public": _run_get_ec_point_public,
    "ecdh_derive": _run_ecdh_derive,
    "sign_private": _run_sign_private,
    "verify_public": _run_verify_public,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    which = extra["which"]
    if which not in _DISPATCH:
        raise ValueError(f"ec_missing_params probe: unknown 'which' value {which!r}")
    _DISPATCH[which](ctx, extra)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
