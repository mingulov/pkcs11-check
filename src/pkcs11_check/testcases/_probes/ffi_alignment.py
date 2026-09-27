"""Probe: FFI pointer-alignment hardening crash probes.

Ports the f-string child-script bodies from security/test_ffi_alignment.py into
dispatchable probe functions.  Caller buffers whose bytes encode valid PKCS#11
structs or scalar values but whose pointers are intentionally 1-byte-misaligned:
a hostile-caller robustness boundary for modules reached through
foreign-function bindings. Each probe prints a flushed ``HOSTILE_CALLER:``
marker immediately before its hostile target call; the parent routes marked
output to a non-normative observation and keeps the
``assert_subprocess_no_crash`` path only for unmarked (setup-phase) output.

Both probes run at Level.LOGIN; the parent forwards the PIN via
``run_probe(pin=pin_from_config(...))`` -> ``_P11CHECK_PIN`` (Invariant I3).

Dispatch on ``params.extra["probe"]``:
  ``"misaligned_scalar_attrs"``  -- C_GenerateKey with CK_ATTRIBUTE.pValue pointers
                                    into 1-byte-misaligned scalar storage
                                    (prints ``HOSTILE_CALLER:`` before the call,
                                    then ``TARGET_RV:C_GenerateKey:<rv>``)
  ``"misaligned_mechanism_ptr"`` -- C_GenerateKey (setup) then C_EncryptInit with a
                                    1-byte-misaligned CK_MECHANISM_PTR
                                    (prints ``SETUP_RV:C_GenerateKey:<rv>`` then,
                                    on setup success, ``HOSTILE_CALLER:`` and
                                    ``TARGET_RV:C_EncryptInit:<rv>``)

Both target calls are hostile by construction (P11C-0198-013): a typed
``CK_MECHANISM*`` that is not correctly aligned has undefined behavior on
dereference, and unaligned ``CK_VOID_PTR`` scalar storage carries no cited
acceptance obligation. The parent routes marked output as a non-normative
hostile-caller robustness observation, never as a conformance or
memory-safety finding.
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

# Child->parent wire marker: the probe executed the provider call with
# 1-byte-misaligned caller pointers. The parent must route such output as a
# non-normative hostile-caller robustness observation, never as a conformance
# or security finding (P11C-0198-013). Equal-valued to the ffi_length and
# arithmetic_overflow families' constants.
HOSTILE_CALLER_PREFIX = "HOSTILE_CALLER:"


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
    """C_GenerateKey with unaligned scalar pValue pointers (hostile-caller observation)."""
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

    # The target call below is hostile by construction (misaligned pValue
    # pointers); mark the wire BEFORE it so the marker survives a child crash.
    print(
        f"{HOSTILE_CALLER_PREFIX}C_GenerateKey(misaligned CK_ATTRIBUTE.pValue scalars)",
        flush=True,
    )
    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKey(sh, ctypes.byref(mech), attrs, len(attrs), ctypes.byref(key))
    print(f"TARGET_RV:C_GenerateKey:{rv}", flush=True)
    if rv == CKR_OK:
        raw.C_DestroyObject(sh, key)


def _run_misaligned_mechanism_ptr(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_EncryptInit with an unaligned CK_MECHANISM_PTR (hostile-caller observation)."""
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

    # Setup succeeded with valid typed storage; the EncryptInit below is
    # hostile by construction (misaligned CK_MECHANISM_PTR). Mark the wire
    # BEFORE it so the marker survives a child crash.
    print(
        f"{HOSTILE_CALLER_PREFIX}C_EncryptInit(misaligned CK_MECHANISM_PTR)",
        flush=True,
    )
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
