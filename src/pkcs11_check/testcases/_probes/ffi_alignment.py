"""Probe: FFI pointer-alignment hardening crash probes.

Ports the f-string child-script bodies from security/test_ffi_alignment.py into
dispatchable probe functions.  Caller buffers whose bytes encode valid PKCS#11
structs or scalar values but whose pointers are intentionally 1-byte-misaligned:
a crash-safety boundary for modules reached through foreign-function bindings.
Output protocol lines are byte-identical to the originals so the parent
(assert_subprocess_no_crash) requires no changes.

Both probes run at Level.LOGIN; the parent forwards the PIN via
``run_probe(pin=pin_from_config(...))`` -> ``_P11CHECK_PIN`` (Invariant I3).

Dispatch on ``params.extra["probe"]``:
  ``"misaligned_scalar_attrs"``  -- C_GenerateKey with CK_ATTRIBUTE.pValue pointers
                                    into 1-byte-misaligned scalar storage
                                    (prints ``TARGET_RV:C_GenerateKey:<rv>``)
  ``"misaligned_mechanism_ptr"`` -- C_GenerateKey (setup) then C_EncryptInit with a
                                    1-byte-misaligned CK_MECHANISM_PTR
                                    (prints ``SETUP_RV:C_GenerateKey:<rv>`` then,
                                    on setup success, ``TARGET_RV:C_EncryptInit:<rv>``)
"""

from __future__ import annotations

import ctypes
from collections.abc import Callable
from typing import Any

from pkcs11_check.raw.pack import attr_bool, attr_ulong, mech_simple, template
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_BBOOL,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKM_AES_ECB,
    CKM_AES_KEY_GEN,
    CKR_OK,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _misaligned_ptr_to_struct(value: Any) -> tuple[Any, Any]:
    """Copy *value* into 1-byte-misaligned storage; return (backing, typed pointer)."""
    storage = (ctypes.c_ubyte * (ctypes.sizeof(value) + 1))()
    ctypes.memmove(ctypes.addressof(storage) + 1, ctypes.byref(value), ctypes.sizeof(value))
    ptr_type = ctypes.POINTER(type(value))
    return storage, ctypes.cast(ctypes.byref(storage, 1), ptr_type)


def _misaligned_scalar(ctype: Any, value: int) -> tuple[Any, Any]:
    """Copy a scalar into 1-byte-misaligned storage; return (backing, void pointer)."""
    storage = (ctypes.c_ubyte * (ctypes.sizeof(ctype) + 1))()
    scalar = ctype(value)
    ctypes.memmove(ctypes.addressof(storage) + 1, ctypes.byref(scalar), ctypes.sizeof(scalar))
    return storage, ctypes.cast(ctypes.byref(storage, 1), ctypes.c_void_p)


def _run_misaligned_scalar_attrs(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_GenerateKey must not crash on unaligned scalar pValue pointers."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh

    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_KEY_GEN
    mech.pParameter = None
    mech.ulParameterLen = 0

    attrs = (CK_ATTRIBUTE * 4)()
    storages: list[Any] = []
    for idx, (attr_type, ctype, attr_value) in enumerate(
        (
            (CKA_VALUE_LEN, CK_ULONG, 16),
            (CKA_ENCRYPT, CK_BBOOL, 1),
            (CKA_DECRYPT, CK_BBOOL, 1),
            (CKA_TOKEN, CK_BBOOL, 0),
        )
    ):
        storage, ptr = _misaligned_scalar(ctype, attr_value)
        storages.append(storage)
        attrs[idx].type = attr_type
        attrs[idx].pValue = ptr
        attrs[idx].ulValueLen = ctypes.sizeof(ctype)

    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKey(sh, ctypes.byref(mech), attrs, len(attrs), ctypes.byref(key))
    print(f"TARGET_RV:C_GenerateKey:{rv}", flush=True)
    if rv == CKR_OK:
        raw.C_DestroyObject(sh, key)


def _run_misaligned_mechanism_ptr(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_EncryptInit must not crash on an unaligned CK_MECHANISM_PTR."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh

    key_template = template(
        attr_ulong(CKA_VALUE_LEN, 16),
        attr_bool(CKA_ENCRYPT, True),
        attr_bool(CKA_DECRYPT, True),
        attr_bool(CKA_TOKEN, False),
    )
    key = CK_OBJECT_HANDLE(0)
    keygen_mech = mech_simple(CKM_AES_KEY_GEN)
    rv = raw.C_GenerateKey(
        sh,
        keygen_mech.byref(),
        key_template.ptr,
        key_template.count,
        ctypes.byref(key),
    )
    print(f"SETUP_RV:C_GenerateKey:{rv}", flush=True)
    if rv != CKR_OK:
        return

    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_ECB
        mech.pParameter = None
        mech.ulParameterLen = 0
        storages: list[Any] = []
        mech_storage, mech_ptr = _misaligned_ptr_to_struct(mech)
        storages.append(mech_storage)
        rv = raw.C_EncryptInit(sh, mech_ptr, key)
        print(f"TARGET_RV:C_EncryptInit:{rv}", flush=True)
    finally:
        raw.C_DestroyObject(sh, key)


_DISPATCH: dict[str, Callable[[ProbeContext, dict[str, Any]], None]] = {
    "misaligned_scalar_attrs": _run_misaligned_scalar_attrs,
    "misaligned_mechanism_ptr": _run_misaligned_mechanism_ptr,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe: str = extra["probe"]
    handler = _DISPATCH.get(probe)
    if handler is None:
        raise ValueError(f"ffi_alignment probe: unknown 'probe' value {probe!r}")
    handler(ctx, extra)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
