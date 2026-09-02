"""Probe: ``CK_C_INITIALIZE_ARGS`` matrix + ``C_Finalize`` reserved-field validation.

Raw pre-auth ctypes path (no session, no login; Invariant I3): the child loads the
module via ``ctypes.CDLL`` and calls ``C_Initialize`` (or ``C_Finalize``) directly off
the loaded ``CDLL`` (``lib.C_Initialize`` / ``lib.C_Finalize``), exactly as the legacy
inline subprocess bodies did -- no ``CK_FUNCTION_LIST`` pointer arithmetic is needed.
Migrated verbatim from the legacy ``test_initialize_args.py`` child scripts (each
``args_setup`` snippet becomes one handler; the mutex-callback stubs and the deliberate
``pReserved`` non-NULL / partial-callback setups are preserved unchanged so the module
sees byte-identical inputs).

Dispatch on ``extra["probe"]``:
  ``"null_args"``                      -- C_Initialize(NULL).
  ``"empty_struct"``                   -- zeroed CK_C_INITIALIZE_ARGS.
  ``"os_locking_only"``                -- CKF_OS_LOCKING_OK set, no callbacks.
  ``"app_mutex_callbacks"``            -- all 4 mutex callbacks, no CKF_OS_LOCKING_OK.
  ``"both_callbacks_and_os_locking"``  -- all 4 callbacks AND CKF_OS_LOCKING_OK.
  ``"reserved_non_null"``              -- non-NULL pReserved.
  ``"partial_callbacks"``              -- 3-of-4 mutex callbacks (UnlockMutex NULL).
  ``"finalize_reserved_non_null"``     -- C_Initialize(NULL) then C_Finalize(non-NULL pReserved).

Output protocol (byte-identical to the legacy child):
  ``RV=0x{rv:08x}``  -- the return value of the C_Initialize call (or, for the finalize
                        probe, the C_Finalize call).

Required ``extra`` keys:
  ``"probe"`` -- one of the eight names above.

Launch with ``coverage="raw"`` (the raw CDLL path has no RawPKCS11 wrapper; I6).
"""

from __future__ import annotations

import ctypes
from ctypes import byref, c_void_p, cast
from typing import Any

from pkcs11_check.core.crash_codes import ctypes_access_violation_code
from pkcs11_check.raw.types_std import (
    CK_C_INITIALIZE_ARGS,
    CK_CREATEMUTEX,
    CK_DESTROYMUTEX,
    CK_LOCKMUTEX,
    CK_RV,
    CK_UNLOCKMUTEX,
    CKF_OS_LOCKING_OK,
    CKR_CRYPTOKI_ALREADY_INITIALIZED,
    CKR_OK,
)
from pkcs11_check.testcases._probes.raw_session import RawCtypesContext, probe_main_raw


def _call_initialize(lib: ctypes.CDLL, init_args_ptr: Any) -> None:
    """Call ``C_Initialize(init_args_ptr)``, print ``RV=0x<hex>``, then best-effort Finalize.

    Mirrors the shared tail of the legacy ``_run_init_args_script`` child body.
    """
    c_init = lib.C_Initialize
    c_init.restype = CK_RV
    c_init.argtypes = [c_void_p]

    rv = c_init(init_args_ptr)
    print(f"RV=0x{rv:08x}")

    # Best-effort Finalize so the module is left clean.
    try:
        c_final = lib.C_Finalize
        c_final.restype = CK_RV
        c_final.argtypes = [c_void_p]
        c_final(None)
    except OSError as exc:
        # A ctypes-translated Windows access violation is a provider crash finding,
        # not ordinary best-effort teardown noise.
        if ctypes_access_violation_code(exc) is not None:
            raise


def _null_args(lib: ctypes.CDLL) -> None:
    _call_initialize(lib, None)


def _empty_struct(lib: ctypes.CDLL) -> None:
    args = CK_C_INITIALIZE_ARGS()  # all fields zero-initialised
    _call_initialize(lib, cast(byref(args), c_void_p))


def _os_locking_only(lib: ctypes.CDLL) -> None:
    args = CK_C_INITIALIZE_ARGS()
    args.flags = int(CKF_OS_LOCKING_OK)
    _call_initialize(lib, cast(byref(args), c_void_p))


def _app_mutex_callbacks(lib: ctypes.CDLL) -> None:
    def _create(pp: Any) -> int:
        return int(CKR_OK)

    def _destroy(p: Any) -> int:
        return int(CKR_OK)

    def _lock(p: Any) -> int:
        return int(CKR_OK)

    def _unlock(p: Any) -> int:
        return int(CKR_OK)

    create_fn = CK_CREATEMUTEX(_create)
    destroy_fn = CK_DESTROYMUTEX(_destroy)
    lock_fn = CK_LOCKMUTEX(_lock)
    unlock_fn = CK_UNLOCKMUTEX(_unlock)

    args = CK_C_INITIALIZE_ARGS()
    args.CreateMutex = create_fn
    args.DestroyMutex = destroy_fn
    args.LockMutex = lock_fn
    args.UnlockMutex = unlock_fn
    _call_initialize(lib, cast(byref(args), c_void_p))


def _both_callbacks_and_os_locking(lib: ctypes.CDLL) -> None:
    def _create(pp: Any) -> int:
        return int(CKR_OK)

    def _destroy(p: Any) -> int:
        return int(CKR_OK)

    def _lock(p: Any) -> int:
        return int(CKR_OK)

    def _unlock(p: Any) -> int:
        return int(CKR_OK)

    create_fn = CK_CREATEMUTEX(_create)
    destroy_fn = CK_DESTROYMUTEX(_destroy)
    lock_fn = CK_LOCKMUTEX(_lock)
    unlock_fn = CK_UNLOCKMUTEX(_unlock)

    args = CK_C_INITIALIZE_ARGS()
    args.CreateMutex = create_fn
    args.DestroyMutex = destroy_fn
    args.LockMutex = lock_fn
    args.UnlockMutex = unlock_fn
    args.flags = int(CKF_OS_LOCKING_OK)
    _call_initialize(lib, cast(byref(args), c_void_p))


def _reserved_non_null(lib: ctypes.CDLL) -> None:
    args = CK_C_INITIALIZE_ARGS()
    args.pReserved = c_void_p(0xDEADBEEF)
    _call_initialize(lib, cast(byref(args), c_void_p))


def _partial_callbacks(lib: ctypes.CDLL) -> None:
    def _create(pp: Any) -> int:
        return int(CKR_OK)

    def _destroy(p: Any) -> int:
        return int(CKR_OK)

    def _lock(p: Any) -> int:
        return int(CKR_OK)

    create_fn = CK_CREATEMUTEX(_create)
    destroy_fn = CK_DESTROYMUTEX(_destroy)
    lock_fn = CK_LOCKMUTEX(_lock)

    args = CK_C_INITIALIZE_ARGS()
    args.CreateMutex = create_fn
    args.DestroyMutex = destroy_fn
    args.LockMutex = lock_fn
    # UnlockMutex left as NULL — deliberate
    _call_initialize(lib, cast(byref(args), c_void_p))


def _finalize_reserved_non_null(lib: ctypes.CDLL) -> None:
    # Initialize first (C_Initialize(NULL) is universally-accepted per spec §5.4).
    c_init = lib.C_Initialize
    c_init.restype = CK_RV
    c_init.argtypes = [c_void_p]
    rv_init = c_init(None)
    assert rv_init in (  # audit-ok: init idempotency; asserting setup success
        int(CKR_OK),
        int(CKR_CRYPTOKI_ALREADY_INITIALIZED),
    ), f"C_Initialize failed: 0x{rv_init:08x}"

    # Call C_Finalize with a non-NULL pReserved (spec §11.4 requires
    # CKR_ARGUMENTS_BAD; many modules tolerate it and return CKR_OK).
    c_final = lib.C_Finalize
    c_final.restype = CK_RV
    c_final.argtypes = [c_void_p]

    dummy = ctypes.c_ulong(0xDEADBEEF)
    rv = c_final(cast(byref(dummy), c_void_p))
    print(f"RV=0x{rv:08x}")


_PROBES = {
    "null_args": _null_args,
    "empty_struct": _empty_struct,
    "os_locking_only": _os_locking_only,
    "app_mutex_callbacks": _app_mutex_callbacks,
    "both_callbacks_and_os_locking": _both_callbacks_and_os_locking,
    "reserved_non_null": _reserved_non_null,
    "partial_callbacks": _partial_callbacks,
    "finalize_reserved_non_null": _finalize_reserved_non_null,
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
