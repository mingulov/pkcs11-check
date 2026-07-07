"""Probe: safety of application-supplied ``CK_C_INITIALIZE_ARGS`` mutex callbacks.

Raw pre-auth ctypes path (no session, no login; Invariant I3): the child loads the
module via ``ctypes.CDLL`` and calls ``C_Initialize`` with a ``CK_C_INITIALIZE_ARGS``
whose four mutex callbacks are Python functions.  ``C_*`` functions are resolved
directly off the loaded ``CDLL`` (``lib.C_Initialize`` / ``lib.C_Finalize`` /
``lib.C_GetInfo``), exactly as the legacy inline subprocess bodies did -- no
``CK_FUNCTION_LIST`` pointer arithmetic is needed here.  Migrated verbatim from the
legacy ``test_mutex_callback_safety.py`` child scripts (the callback bodies, including
the deliberately buggy ``pp[0] = 0x1`` write and the exception-raising callback, are
preserved unchanged so the module sees byte-identical inputs).

Dispatch on ``extra["probe"]``:
  ``"create_returns_general_error"`` -- CreateMutex returns CKR_GENERAL_ERROR.
  ``"lock_returns_general_error"``   -- LockMutex returns CKR_GENERAL_ERROR, then C_GetInfo.
  ``"python_exception_in_create"``   -- CreateMutex raises a Python exception.

Output protocol (byte-identical to the legacy child):
  ``RV=0x{rv:08x}``       -- C_Initialize return value (create / python-exception probes).
  ``INIT_RV=0x{rv:08x}``  -- C_Initialize return value (lock probe).
  ``CALL_RV=0x{rv2:08x}`` -- C_GetInfo return value (lock probe, only when INIT_RV == CKR_OK).

Required ``extra`` keys:
  ``"probe"`` -- one of the three names above.

Launch with ``coverage="raw"`` (the raw CDLL path has no RawPKCS11 wrapper; I6).
"""

from __future__ import annotations

import ctypes
from ctypes import byref, c_void_p, cast
from typing import Any

from pkcs11_check.raw.types_std import (
    CK_C_INITIALIZE_ARGS,
    CK_CREATEMUTEX,
    CK_DESTROYMUTEX,
    CK_INFO,
    CK_LOCKMUTEX,
    CK_RV,
    CK_UNLOCKMUTEX,
    CKR_GENERAL_ERROR,
    CKR_OK,
)
from pkcs11_check.testcases._probes.raw_session import RawCtypesContext, probe_main_raw


def _create_returns_general_error(lib: ctypes.CDLL) -> None:
    def _create_fail(pp: Any) -> int:
        return int(CKR_GENERAL_ERROR)

    def _stub(p: Any) -> int:
        return int(CKR_OK)

    create_fn = CK_CREATEMUTEX(_create_fail)
    destroy_fn = CK_DESTROYMUTEX(_stub)
    lock_fn = CK_LOCKMUTEX(_stub)
    unlock_fn = CK_UNLOCKMUTEX(_stub)

    args = CK_C_INITIALIZE_ARGS()
    args.CreateMutex = create_fn
    args.DestroyMutex = destroy_fn
    args.LockMutex = lock_fn
    args.UnlockMutex = unlock_fn

    c_init = lib.C_Initialize
    c_init.restype = CK_RV
    c_init.argtypes = [c_void_p]
    rv = c_init(cast(byref(args), c_void_p))
    print(f"RV=0x{rv:08x}")

    # Cleanup best-effort.
    c_final = lib.C_Finalize
    c_final.restype = CK_RV
    c_final.argtypes = [c_void_p]
    c_final(None)


def _lock_returns_general_error(lib: ctypes.CDLL) -> None:
    def _create(pp: Any) -> int:
        # Allocate a unique sentinel for each mutex.
        # Module passes a void** -- we write a non-NULL value.
        pp[0] = 0x1
        return int(CKR_OK)

    def _destroy(p: Any) -> int:
        return int(CKR_OK)

    def _lock_fail(p: Any) -> int:
        return int(CKR_GENERAL_ERROR)

    def _unlock(p: Any) -> int:
        return int(CKR_OK)

    create_fn = CK_CREATEMUTEX(_create)
    destroy_fn = CK_DESTROYMUTEX(_destroy)
    lock_fn = CK_LOCKMUTEX(_lock_fail)
    unlock_fn = CK_UNLOCKMUTEX(_unlock)

    args = CK_C_INITIALIZE_ARGS()
    args.CreateMutex = create_fn
    args.DestroyMutex = destroy_fn
    args.LockMutex = lock_fn
    args.UnlockMutex = unlock_fn

    c_init = lib.C_Initialize
    c_init.restype = CK_RV
    c_init.argtypes = [c_void_p]
    rv = c_init(cast(byref(args), c_void_p))
    print(f"INIT_RV=0x{rv:08x}")

    if rv == CKR_OK:
        # Try a trivial call that should internally lock.
        # C_GetInfo is the safest probe.
        info = CK_INFO()
        c_getinfo = lib.C_GetInfo
        c_getinfo.restype = CK_RV
        c_getinfo.argtypes = [c_void_p]
        rv2 = c_getinfo(cast(byref(info), c_void_p))
        print(f"CALL_RV=0x{rv2:08x}")

        c_final = lib.C_Finalize
        c_final.restype = CK_RV
        c_final.argtypes = [c_void_p]
        c_final(None)


def _python_exception_in_create(lib: ctypes.CDLL) -> None:
    def _create_raise(pp: Any) -> int:
        raise RuntimeError("callback failure")

    def _stub(p: Any) -> int:
        return int(CKR_OK)

    create_fn = CK_CREATEMUTEX(_create_raise)
    destroy_fn = CK_DESTROYMUTEX(_stub)
    lock_fn = CK_LOCKMUTEX(_stub)
    unlock_fn = CK_UNLOCKMUTEX(_stub)

    args = CK_C_INITIALIZE_ARGS()
    args.CreateMutex = create_fn
    args.DestroyMutex = destroy_fn
    args.LockMutex = lock_fn
    args.UnlockMutex = unlock_fn

    c_init = lib.C_Initialize
    c_init.restype = CK_RV
    c_init.argtypes = [c_void_p]
    rv = c_init(cast(byref(args), c_void_p))
    print(f"RV=0x{rv:08x}")

    try:
        c_final = lib.C_Finalize
        c_final.restype = CK_RV
        c_final.argtypes = [c_void_p]
        c_final(None)
    except OSError:
        # Best-effort teardown after the raising callback: on Windows a faulting
        # C_Finalize surfaces as an OSError (structured exception); swallow it so the
        # child still exits 0 with the callback traceback on stderr, matching the legacy
        # body.  A POSIX fault is an uncatchable signal the parent records as a crash.
        pass


_PROBES = {
    "create_returns_general_error": _create_returns_general_error,
    "lock_returns_general_error": _lock_returns_general_error,
    "python_exception_in_create": _python_exception_in_create,
}


def _run(ctx: RawCtypesContext, extra: dict[str, Any]) -> None:
    probe = extra["probe"]
    try:
        run_fn = _PROBES[probe]
    except KeyError:
        raise ValueError(f"unknown probe {probe!r}") from None
    run_fn(ctx.lib)


if __name__ == "__main__":
    probe_main_raw(_run)
