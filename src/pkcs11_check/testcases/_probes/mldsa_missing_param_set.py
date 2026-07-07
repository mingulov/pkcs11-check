"""Probe: ML-DSA key create without ``CKA_PARAMETER_SET`` (crash safety).

Ports the f-string child-script body from
security/test_mldsa_missing_param_set.py into a dispatchable probe function.
A conformant module must reject a ``C_CreateObject`` template for
``CKO_PRIVATE_KEY`` / ``CKK_ML_DSA`` that omits ``CKA_PARAMETER_SET``; a module
that silently creates the param-less key may crash or produce undefined output
when the module's ML-DSA key-init path attempts to use an uninitialised
parameter set.  Output protocol lines (``CREATE_RV:``, ``SIGNINIT_RV:``,
``SIGN_RV:``) are byte-identical to the original so the parent
(assert_subprocess_no_crash + classify_negative_rv) requires no changes.

The probe runs at Level.LOGIN; the parent forwards the PIN via
``run_probe(pin=pin_from_config(...))`` -> ``_P11CHECK_PIN`` (Invariant I3).

Dispatch on ``params.extra["probe"]``:
  ``"create_without_param_set"`` -- C_CreateObject(CKO_PRIVATE_KEY/CKK_ML_DSA)
                                    with no CKA_PARAMETER_SET; on accept, also
                                    probes C_SignInit + C_Sign.
"""

from __future__ import annotations

import ctypes
from collections.abc import Callable
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
    CKK_ML_DSA,
    CKM_ML_DSA,
    CKO_PRIVATE_KEY,
    CKR_OK,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _run_create_without_param_set(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_CreateObject(CKK_ML_DSA) with no CKA_PARAMETER_SET must reject cleanly."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh

    # Template: CKO_PRIVATE_KEY / CKK_ML_DSA, no CKA_PARAMETER_SET intentionally.
    cls_val = CK_ULONG(CKO_PRIVATE_KEY)
    key_type_val = CK_ULONG(CKK_ML_DSA)
    token_false = ctypes.c_ubyte(0)
    sign_true = ctypes.c_ubyte(1)

    attrs = (CK_ATTRIBUTE * 4)()
    attrs[0].type = CKA_CLASS
    attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    attrs[0].ulValueLen = ctypes.sizeof(cls_val)
    attrs[1].type = CKA_KEY_TYPE
    attrs[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
    attrs[1].ulValueLen = ctypes.sizeof(key_type_val)
    attrs[2].type = CKA_TOKEN
    attrs[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    attrs[2].ulValueLen = 1
    attrs[3].type = CKA_SIGN
    attrs[3].pValue = ctypes.cast(ctypes.pointer(sign_true), ctypes.c_void_p)
    attrs[3].ulValueLen = 1

    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh,
        ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)),
        4,
        ctypes.byref(key),
    )
    print(f"CREATE_RV:0x{rv:08x}", flush=True)

    if rv == CKR_OK:
        # Module accepted the param-less template -- probe the sign path too.
        message = b"mldsa-no-paramset-probe"
        msg_buf = (ctypes.c_ubyte * len(message)).from_buffer_copy(message)
        mech = CK_MECHANISM()
        mech.mechanism = CKM_ML_DSA
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv_init = raw.C_SignInit(sh, ctypes.byref(mech), key.value)
        print(f"SIGNINIT_RV:0x{rv_init:08x}", flush=True)
        if rv_init == CKR_OK:
            sig_len = CK_ULONG(0)
            rv_sign = raw.C_Sign(sh, msg_buf, len(message), None, ctypes.byref(sig_len))
            print(f"SIGN_RV:0x{rv_sign:08x}", flush=True)
            if rv_sign == CKR_OK and sig_len.value > 0:
                sig_buf = (ctypes.c_ubyte * sig_len.value)()
                rv_sign2 = raw.C_Sign(sh, msg_buf, len(message), sig_buf, ctypes.byref(sig_len))
                print(f"SIGN_RV:0x{rv_sign2:08x}", flush=True)
        destroy_quietly(raw, sh, key.value)


_DISPATCH: dict[str, Callable[[ProbeContext, dict[str, Any]], None]] = {
    "create_without_param_set": _run_create_without_param_set,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe: str = extra["probe"]
    handler = _DISPATCH.get(probe)
    if handler is None:
        raise ValueError(f"mldsa_missing_param_set probe: unknown 'probe' value {probe!r}")
    handler(ctx, extra)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
