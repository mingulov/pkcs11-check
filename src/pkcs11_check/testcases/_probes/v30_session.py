"""Probe: C_SessionCancel clears a pending DigestInit on a v3.0-negotiated raw session.

Single child body ported verbatim from the legacy ``test_v30_session.py``
``test_cancel_after_digest_init_subprocess`` inline script.  It exercises the v3.0
``C_SessionCancel`` function through a manually v3.0-negotiated ``RawPKCS11`` session:
start a ``CKM_SHA256`` digest (``C_DigestInit``), call ``C_SessionCancel(flags=0)``, then
verify the session accepts a fresh ``C_DigestInit`` afterwards.

Runs through ``probe_main_raw`` (the raw ctypes CDLL path): ``probe_main_raw`` loads the
module and calls ``C_GetFunctionList`` (giving ``ctx.lib`` + ``ctx.func_list``).  The probe
then manually calls ``C_GetInterface`` with the exact transported version for explicit
``3.0``/``3.1``/``3.2`` selections and constructs ``RawPKCS11`` from the returned
``pFunctionList``.  With ``auto`` it preserves the legacy default request and fallback
behavior.  ``RawPKCS11.from_lib`` is not used because its auto path also tries an exact
3.2 interface first, which would change which ``C_SessionCancel`` pointer this legacy
probe exercises.  So the session-path ``probe_main`` is NOT used here.

The PIN travels ONLY via the ``_P11CHECK_PIN`` env var (Invariant I3): the probe opens a
session and, when the env var is set, logs in as ``CKU_USER`` -- exactly as the legacy
child did (which already read the PIN from the env, never embedding it in the script).

Output protocol (byte-identical to the legacy child, for the parent classifier):
  ``SKIP:C_DigestInit=0x{rv:08x}``  -- module rejected the initial DigestInit (capability gap)
  ``CANCEL:NOT_AVAILABLE``          -- C_SessionCancel absent from the negotiated function list
  ``CANCEL:OK``                     -- C_SessionCancel returned CKR_OK
  ``CANCEL:NOT_SUPPORTED``          -- C_SessionCancel returned CKR_FUNCTION_NOT_SUPPORTED
  ``CANCEL:0x{rv:08x}``             -- C_SessionCancel returned some other (non-conformant) CKR
  ``REDIGEST:OK``                   -- session accepted a fresh DigestInit after cancel
  ``REDIGEST:0x{rv:08x}``           -- session rejected the post-cancel DigestInit

Required ``extra`` keys:
  ``"probe"``       -- must be ``"cancel_after_digest_init"``.
  ``"slot_index"``  -- positional index into the discovered slot list (legacy ``p11_config.slot``).

Launch with ``coverage="raw"`` and ``pin=pin_from_config(p11_config)``.
"""

from __future__ import annotations

import ctypes
import os
from ctypes import POINTER, byref, c_ubyte, c_ulong, c_void_p, pointer
from typing import Any

from pkcs11_check.core.crash_codes import ctypes_access_violation_code
from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.bootstrap import get_slot_ids
from pkcs11_check.raw.types_std import (
    CK_INTERFACE_PTR,
    CK_INTERFACE_PTR_PTR,
    CK_MECHANISM,
    CK_NOTIFY,
    CK_VERSION,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKM_SHA256,
    CKR_CRYPTOKI_ALREADY_INITIALIZED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
    CKR_USER_ALREADY_LOGGED_IN,
    CKU_USER,
)
from pkcs11_check.testcases._probes.raw_session import RawCtypesContext, probe_main_raw


def _negotiate_v30(ctx: RawCtypesContext) -> RawPKCS11:
    """Build a RawPKCS11 with the requested v3 interface.

    This child intentionally retains the legacy manual construction (I5): the base v2.40
    function list from ``ctx.func_list`` plus the exact interface table returned by
    ``C_GetInterface``.  Unlike ``RawPKCS11.from_lib(interface="auto")``, an explicit
    selector is never upgraded to another table.  The ``auto`` path keeps the historical
    default-v3 request.
    """
    requested = ctx.interface
    if requested == "2.40":
        raise RuntimeError("v30_session requires a PKCS#11 v3 interface, got 2.40")
    if requested == "auto":
        requested_version: tuple[int, int] | None = None
    else:
        try:
            major, minor = (int(part) for part in requested.split("."))
        except (AttributeError, ValueError):
            raise ValueError(f"unknown PKCS#11 interface {requested!r}") from None
        if (major, minor) not in ((3, 0), (3, 1), (3, 2)):
            raise ValueError(f"v30_session requires a PKCS#11 v3 interface, got {requested!r}")
        requested_version = (major, minor)

    fl3_val = 0
    try:
        get_iface = ctx.lib.C_GetInterface
        get_iface.restype = c_ulong
        get_iface.argtypes = [c_void_p, POINTER(CK_VERSION), CK_INTERFACE_PTR_PTR, c_ulong]
    except AttributeError:
        if requested_version is not None:
            raise RuntimeError(
                f"requested PKCS#11 interface {requested!r} requires C_GetInterface"
            ) from None
        return RawPKCS11(ctx.func_list.value, funclist3_ptr=0)

    requested_version_obj: CK_VERSION | None = None
    if requested_version is not None:
        requested_version_obj = CK_VERSION()
        requested_version_obj.major, requested_version_obj.minor = requested_version
    iface_ptr = CK_INTERFACE_PTR()
    rv = get_iface(
        None,
        byref(requested_version_obj) if requested_version_obj is not None else None,
        byref(iface_ptr),
        0,
    )
    if rv != CKR_OK:
        if requested_version is None:
            return RawPKCS11(ctx.func_list.value, funclist3_ptr=0)
        raise RuntimeError(
            f"C_GetInterface for requested PKCS#11 interface {requested!r} "
            f"returned CK_RV 0x{int(rv):08x}"
        )
    if not bool(iface_ptr):
        if requested_version is None:
            return RawPKCS11(ctx.func_list.value, funclist3_ptr=0)
        raise RuntimeError(
            f"C_GetInterface for requested PKCS#11 interface {requested!r} returned NULL"
        )
    fl3_val = int(iface_ptr.contents.pFunctionList or 0)
    if not fl3_val:
        if requested_version is None:
            return RawPKCS11(ctx.func_list.value, funclist3_ptr=0)
        raise RuntimeError(
            f"C_GetInterface for requested PKCS#11 interface {requested!r} returned "
            "NULL pFunctionList"
        )

    if requested_version is not None:
        actual = ctypes.cast(fl3_val, POINTER(CK_VERSION)).contents
        actual_version = (int(actual.major), int(actual.minor))
        if actual_version != requested_version:
            raise RuntimeError(
                f"requested PKCS#11 interface {requested!r}, got "
                f"{actual_version[0]}.{actual_version[1]}"
            )
    return RawPKCS11(ctx.func_list.value, funclist3_ptr=fl3_val)


def _teardown(raw: RawPKCS11, session_handle: int) -> None:
    """Best-effort clean C_CloseSession + C_Finalize; provider faults propagate."""
    try:
        raw.C_CloseSession(session_handle)
    except OSError as exc:
        if ctypes_access_violation_code(exc) is not None:
            raise
    except (AttributeError, ctypes.ArgumentError):
        pass
    try:
        raw.C_Finalize(None)
    except OSError as exc:
        if ctypes_access_violation_code(exc) is not None:
            raise
    except (AttributeError, ctypes.ArgumentError):
        pass


def _cancel_after_digest_init(ctx: RawCtypesContext, extra: dict[str, Any]) -> None:
    """Digest -> SessionCancel -> re-Digest sequence; prints the CANCEL/REDIGEST markers."""
    slot_index = extra["slot_index"]
    raw = _negotiate_v30(ctx)

    rv = raw.C_Initialize(None)
    assert rv in (  # audit-ok: init idempotency
        CKR_OK,
        CKR_CRYPTOKI_ALREADY_INITIALIZED,
    ), f"C_Initialize: 0x{rv:08x}"

    session_handle = c_ulong(0)
    slot_ids = get_slot_ids(raw)
    assert len(slot_ids) > slot_index, (
        f"slot index {slot_index} unavailable; found {len(slot_ids)} slots"
    )
    rv = raw.C_OpenSession(
        slot_ids[slot_index],
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        None,
        CK_NOTIFY(),
        byref(session_handle),
    )
    assert rv == CKR_OK, f"C_OpenSession: 0x{rv:08x}"
    sh = session_handle.value

    _pin = os.environ.get("_P11CHECK_PIN")
    if _pin:
        pin = _pin.encode()
        pin_buf = (c_ubyte * len(pin))(*pin)
        rv = raw.C_Login(sh, CKU_USER, pin_buf, len(pin))
        assert rv in (  # audit-ok: login idempotency
            CKR_OK,
            CKR_USER_ALREADY_LOGGED_IN,
        ), f"C_Login: 0x{rv:08x}"

    mech = CK_MECHANISM(CKM_SHA256, None, 0)
    rv = raw.C_DigestInit(sh, pointer(mech))
    if rv != CKR_OK:
        print(f"SKIP:C_DigestInit=0x{rv:08x}")
        _teardown(raw, sh)
        return

    # Attempt C_SessionCancel via RawPKCS11.
    try:
        rv_cancel = raw.C_SessionCancel(sh, 0)
    except AttributeError:
        print("CANCEL:NOT_AVAILABLE")
        _teardown(raw, sh)
        return

    if rv_cancel == CKR_OK:
        print("CANCEL:OK")
    elif rv_cancel == CKR_FUNCTION_NOT_SUPPORTED:
        print("CANCEL:NOT_SUPPORTED")
    else:
        print(f"CANCEL:0x{rv_cancel:08x}")
        _teardown(raw, sh)
        return

    # Session should accept a new DigestInit after cancel.
    rv2 = raw.C_DigestInit(sh, pointer(mech))
    if rv2 == CKR_OK:
        print("REDIGEST:OK")
    else:
        print(f"REDIGEST:0x{rv2:08x}")

    _teardown(raw, sh)


_PROBES = {
    "cancel_after_digest_init": _cancel_after_digest_init,
}


def _run(ctx: RawCtypesContext, extra: dict[str, Any]) -> None:
    probe = extra["probe"]
    try:
        handler = _PROBES[probe]
    except KeyError:
        raise ValueError(f"unknown probe {probe!r}") from None
    handler(ctx, extra)


if __name__ == "__main__":
    probe_main_raw(_run)
