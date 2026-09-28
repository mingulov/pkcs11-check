"""Probe: ``CK_C_INITIALIZE_ARGS`` matrix + ``C_Finalize`` reserved-field validation.

Raw pre-auth ctypes path (no session, no login; Invariant I3): the child loads the
module via ``ctypes.CDLL`` and calls ``C_Initialize`` (or ``C_Finalize``) directly off
the loaded ``CDLL`` (``lib.C_Initialize`` / ``lib.C_Finalize``), exactly as the legacy
inline subprocess bodies did -- no ``CK_FUNCTION_LIST`` pointer arithmetic is needed.
Migrated from the legacy ``test_initialize_args.py`` child scripts (each
``args_setup`` snippet becomes one handler); the deliberate ``pReserved`` non-NULL /
partial-callback setups are preserved so the module sees byte-identical inputs for
those probes. The mutex callbacks implement real mutex semantics (usable non-NULL
handles; misuse draws the specified mutex CKRs) so callback-using modules are
exercised rather than handed garbage handles.

Dispatch on ``extra["probe"]``:
  ``"null_args"``                      -- C_Initialize(NULL).
  ``"empty_struct"``                   -- zeroed CK_C_INITIALIZE_ARGS.
  ``"os_locking_only"``                -- CKF_OS_LOCKING_OK set, no callbacks.
  ``"app_mutex_callbacks"``            -- all 4 mutex callbacks, no CKF_OS_LOCKING_OK.
  ``"both_callbacks_and_os_locking"``  -- all 4 callbacks AND CKF_OS_LOCKING_OK.
  ``"reserved_non_null"``              -- non-NULL pReserved.
  ``"partial_callbacks"``              -- 3-of-4 mutex callbacks (UnlockMutex NULL).
  ``"finalize_reserved_non_null"``     -- C_Initialize(NULL) then C_Finalize(non-NULL pReserved).

Output protocol:
  ``SETUP_XFAIL:<reason>`` -- a clean bootstrap refusal before the requested operation.
  ``RV=0x{rv:08x}``        -- the return value of the C_Initialize call (or, for the
                              finalize probe, the C_Finalize call).

Exactly one setup refusal or RV result is emitted by each probe.

Required ``extra`` keys:
  ``"probe"`` -- one of the eight names above.

Launch with ``coverage="raw"`` (the raw CDLL path has no RawPKCS11 wrapper; I6).
"""

from __future__ import annotations

import ctypes
import threading
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
    CKR_ARGUMENTS_BAD,
    CKR_CRYPTOKI_ALREADY_INITIALIZED,
    CKR_MUTEX_BAD,
    CKR_MUTEX_NOT_LOCKED,
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
    print(f"RV=0x{rv:08x}", flush=True)

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


class _MutexSet:
    """Application mutex callbacks with real mutex semantics.

    Each created mutex is a ``threading.Lock`` plus an owned storage cell
    whose address is the opaque handle handed to the module. Storage is never
    freed, so a freed address can never be recycled into a stale but live
    handle. Unknown handles draw ``CKR_MUTEX_BAD``; unlocking a mutex that was
    never locked draws ``CKR_MUTEX_NOT_LOCKED``.
    """

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._mutexes: dict[int, threading.Lock] = {}
        self._storage: list[Any] = []
        self._wrappers: list[Any] = []

    @staticmethod
    def _address(value: Any) -> int:
        if isinstance(value, int):
            return value
        if value is None:
            return 0
        return int(ctypes.cast(value, c_void_p).value or 0)

    def create(self, pp: Any) -> int:
        slot = self._address(pp)
        if not slot:
            return int(CKR_ARGUMENTS_BAD)
        with self._guard:
            storage = ctypes.c_ulong(len(self._storage) + 1)
            handle = ctypes.addressof(storage)
            self._storage.append(storage)
            self._mutexes[handle] = threading.Lock()
        ctypes.cast(slot, ctypes.POINTER(c_void_p))[0] = handle
        return int(CKR_OK)

    def _lookup(self, p: Any) -> threading.Lock | None:
        handle = self._address(p)
        if not handle:
            return None
        with self._guard:
            return self._mutexes.get(handle)

    def destroy(self, p: Any) -> int:
        handle = self._address(p)
        if not handle:
            return int(CKR_MUTEX_BAD)
        with self._guard:
            if handle not in self._mutexes:
                return int(CKR_MUTEX_BAD)
            del self._mutexes[handle]
        return int(CKR_OK)

    def lock(self, p: Any) -> int:
        mutex = self._lookup(p)
        if mutex is None:
            return int(CKR_MUTEX_BAD)
        mutex.acquire()
        return int(CKR_OK)

    def unlock(self, p: Any) -> int:
        mutex = self._lookup(p)
        if mutex is None:
            return int(CKR_MUTEX_BAD)
        try:
            mutex.release()
        except RuntimeError:
            return int(CKR_MUTEX_NOT_LOCKED)
        return int(CKR_OK)


def _new_mutex_set() -> _MutexSet:
    """Return fresh application mutex callbacks with real mutex semantics."""
    return _MutexSet()


def _install_app_mutexes(args: CK_C_INITIALIZE_ARGS, *, with_unlock: bool = True) -> _MutexSet:
    """Install valid application mutex callbacks on init args.

    Returns the mutex set, which the caller must keep alive while the module
    may invoke the callbacks.
    """
    mutexes = _new_mutex_set()
    wrappers = [
        CK_CREATEMUTEX(mutexes.create),
        CK_DESTROYMUTEX(mutexes.destroy),
        CK_LOCKMUTEX(mutexes.lock),
    ]
    args.CreateMutex, args.DestroyMutex, args.LockMutex = wrappers
    if with_unlock:
        wrappers.append(CK_UNLOCKMUTEX(mutexes.unlock))
        args.UnlockMutex = wrappers[-1]
    mutexes._wrappers = wrappers
    return mutexes


def _app_mutex_callbacks(lib: ctypes.CDLL) -> None:
    args = CK_C_INITIALIZE_ARGS()
    _mutexes = _install_app_mutexes(args)
    _call_initialize(lib, cast(byref(args), c_void_p))


def _both_callbacks_and_os_locking(lib: ctypes.CDLL) -> None:
    args = CK_C_INITIALIZE_ARGS()
    _mutexes = _install_app_mutexes(args)
    args.flags = int(CKF_OS_LOCKING_OK)
    _call_initialize(lib, cast(byref(args), c_void_p))


def _reserved_non_null(lib: ctypes.CDLL) -> None:
    args = CK_C_INITIALIZE_ARGS()
    args.pReserved = c_void_p(0xDEADBEEF)
    _call_initialize(lib, cast(byref(args), c_void_p))


def _partial_callbacks(lib: ctypes.CDLL) -> None:
    args = CK_C_INITIALIZE_ARGS()
    _mutexes = _install_app_mutexes(args, with_unlock=False)
    # UnlockMutex left as NULL — deliberate
    _call_initialize(lib, cast(byref(args), c_void_p))


def _finalize_reserved_non_null(lib: ctypes.CDLL) -> None:
    # Initialize first (C_Initialize(NULL) is universally-accepted per spec §5.4).
    c_init = lib.C_Initialize
    c_init.restype = CK_RV
    c_init.argtypes = [c_void_p]
    rv_init = c_init(None)
    if rv_init not in (int(CKR_OK), int(CKR_CRYPTOKI_ALREADY_INITIALIZED)):
        # Finalize is not meaningful when the bootstrap initialize was refused.  Emit
        # one explicit setup state so the parent does not treat the missing finalize RV
        # as an incomplete protocol (the setup/result states are mutually exclusive).
        print(f"SETUP_XFAIL:C_Initialize refused with 0x{rv_init:08x}", flush=True)
        return

    # Call C_Finalize with a non-NULL pReserved (spec §11.4 requires
    # CKR_ARGUMENTS_BAD; many modules tolerate it and return CKR_OK).
    c_final = lib.C_Finalize
    c_final.restype = CK_RV
    c_final.argtypes = [c_void_p]

    dummy = ctypes.c_ulong(0xDEADBEEF)
    rv = c_final(cast(byref(dummy), c_void_p))
    print(f"RV=0x{rv:08x}", flush=True)


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
