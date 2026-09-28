"""ABI-contract regressions for the C_Initialize mutex-callback fixtures.

The ``app_mutex_callbacks`` / ``both_callbacks_and_os_locking`` / partial
probes hand the module application mutex callbacks and treat the resulting
RV as positive initialization evidence -- so the callbacks must implement
valid mutex semantics: CreateMutex returns a usable non-NULL handle, the
handle actually locks, and misuse draws the specified mutex CKRs instead of
dereferencing garbage.

Each test drives a real probe handler with a fake library that exercises
the callbacks the way a mutex-using module would, during C_Initialize.
"""

from __future__ import annotations

import ctypes
from ctypes import byref, c_void_p
from types import SimpleNamespace
from typing import Any

from pkcs11_check.raw.types_std import (
    CK_C_INITIALIZE_ARGS,
    CKF_OS_LOCKING_OK,
    CKR_ARGUMENTS_BAD,
    CKR_MUTEX_BAD,
    CKR_MUTEX_NOT_LOCKED,
    CKR_OK,
)
from pkcs11_check.testcases._probes import initialize_args as init_args


def _addr(ptr: Any) -> int:
    """Normalize an int address, byref object, or c_void_p to an int address."""
    if isinstance(ptr, int):
        return ptr
    return int(ctypes.cast(ptr, c_void_p).value or 0)


def _callback_addr(fn: Any) -> int | None:
    """Read the raw address of a decoded callback field (None when NULL)."""
    return ctypes.cast(fn, c_void_p).value


def _cycle_callbacks(args_addr: int) -> dict[str, Any]:
    """Run a create/lock/unlock/destroy cycle through decoded init args."""
    args = ctypes.cast(args_addr, ctypes.POINTER(CK_C_INITIALIZE_ARGS)).contents
    assert _callback_addr(args.CreateMutex), "CreateMutex must be non-NULL"
    assert _callback_addr(args.DestroyMutex), "DestroyMutex must be non-NULL"
    assert _callback_addr(args.LockMutex), "LockMutex must be non-NULL"
    assert _callback_addr(args.UnlockMutex), "UnlockMutex must be non-NULL"
    out = c_void_p()
    create_rv = int(args.CreateMutex(byref(out)))
    handle = out.value
    result: dict[str, Any] = {
        "flags": int(args.flags),
        "create_rv": create_rv,
        "handle": handle,
    }
    assert create_rv == int(CKR_OK)
    assert handle, "CreateMutex must return a non-NULL mutex handle"
    result["lock_rv"] = int(args.LockMutex(handle))
    result["unlock_rv"] = int(args.UnlockMutex(handle))
    result["destroy_rv"] = int(args.DestroyMutex(handle))
    return result


def _exercising_lib(captured: dict[str, Any]) -> SimpleNamespace:
    """Fake library that runs the mutex cycle during C_Initialize."""

    def _c_init(ptr: Any) -> int:
        captured.update(_cycle_callbacks(_addr(ptr)))
        return int(CKR_OK)

    def _c_finalize(_ptr: Any) -> int:
        captured["finalized"] = True
        return int(CKR_OK)

    return SimpleNamespace(C_Initialize=_c_init, C_Finalize=_c_finalize)


def test_app_mutex_callbacks_survive_full_mutex_cycle() -> None:
    """The app-callbacks fixture must yield a working non-NULL mutex."""
    captured: dict[str, Any] = {}
    init_args._app_mutex_callbacks(_exercising_lib(captured))

    assert captured["flags"] == 0
    assert captured["create_rv"] == int(CKR_OK)
    assert captured["lock_rv"] == int(CKR_OK)
    assert captured["unlock_rv"] == int(CKR_OK)
    assert captured["destroy_rv"] == int(CKR_OK)
    assert captured.get("finalized") is True


def test_both_callbacks_and_os_locking_survive_full_mutex_cycle() -> None:
    """The callbacks-plus-OS-locking fixture must set the flag and yield a
    working non-NULL mutex."""
    captured: dict[str, Any] = {}
    init_args._both_callbacks_and_os_locking(_exercising_lib(captured))

    assert captured["flags"] == int(CKF_OS_LOCKING_OK)
    assert captured["create_rv"] == int(CKR_OK)
    assert captured["lock_rv"] == int(CKR_OK)
    assert captured["unlock_rv"] == int(CKR_OK)
    assert captured["destroy_rv"] == int(CKR_OK)


def test_partial_callbacks_leave_unlock_null_but_create_valid_mutexes() -> None:
    """The deliberate partial setup keeps UnlockMutex NULL while the other
    three callbacks stay valid."""
    observed: dict[str, Any] = {}

    def _c_init(ptr: Any) -> int:
        args = ctypes.cast(_addr(ptr), ctypes.POINTER(CK_C_INITIALIZE_ARGS)).contents
        observed["unlock"] = _callback_addr(args.UnlockMutex)
        out = c_void_p()
        observed["create_rv"] = int(args.CreateMutex(byref(out)))
        observed["handle"] = out.value
        assert _callback_addr(args.DestroyMutex), "DestroyMutex must be non-NULL"
        assert _callback_addr(args.LockMutex), "LockMutex must be non-NULL"
        observed["destroy_rv"] = int(args.DestroyMutex(out.value))
        return int(CKR_OK)

    def _c_finalize(_ptr: Any) -> int:
        return int(CKR_OK)

    init_args._partial_callbacks(SimpleNamespace(C_Initialize=_c_init, C_Finalize=_c_finalize))

    assert not observed["unlock"], "UnlockMutex must stay NULL in the partial setup"
    assert observed["create_rv"] == int(CKR_OK)
    assert observed["handle"], "CreateMutex must return a non-NULL mutex handle"
    assert observed["destroy_rv"] == int(CKR_OK)


def test_mutex_create_rejects_null_out_pointer() -> None:
    """CreateMutex with a NULL ppMutex must fail cleanly, not crash."""
    callbacks = init_args._new_mutex_set()
    assert callbacks.create(0) == int(CKR_ARGUMENTS_BAD)
    assert callbacks.create(None) == int(CKR_ARGUMENTS_BAD)


def test_mutex_unknown_handle_draws_mutex_bad() -> None:
    """Lock/unlock/destroy of a never-created handle must draw CKR_MUTEX_BAD."""
    callbacks = init_args._new_mutex_set()
    assert callbacks.lock(0) == int(CKR_MUTEX_BAD)
    assert callbacks.unlock(0) == int(CKR_MUTEX_BAD)
    assert callbacks.destroy(0) == int(CKR_MUTEX_BAD)
    assert callbacks.lock(0xDEADBEEF) == int(CKR_MUTEX_BAD)


def test_mutex_double_destroy_draws_mutex_bad() -> None:
    """Destroying the same mutex twice must fail the second time."""
    callbacks = init_args._new_mutex_set()
    out = c_void_p()
    assert callbacks.create(byref(out)) == int(CKR_OK)
    handle = out.value
    assert handle
    assert callbacks.destroy(handle) == int(CKR_OK)
    assert callbacks.destroy(handle) == int(CKR_MUTEX_BAD)
    assert callbacks.lock(handle) == int(CKR_MUTEX_BAD)


def test_mutex_unlock_without_lock_draws_not_locked() -> None:
    """Unlocking a mutex that was never locked must draw CKR_MUTEX_NOT_LOCKED."""
    callbacks = init_args._new_mutex_set()
    out = c_void_p()
    assert callbacks.create(byref(out)) == int(CKR_OK)
    handle = out.value
    assert handle
    assert callbacks.unlock(handle) == int(CKR_MUTEX_NOT_LOCKED)
    assert callbacks.lock(handle) == int(CKR_OK)
    assert callbacks.unlock(handle) == int(CKR_OK)
    assert callbacks.destroy(handle) == int(CKR_OK)


def test_mutex_distinct_creates_yield_distinct_handles() -> None:
    """Two creations must yield two independently usable mutexes."""
    callbacks = init_args._new_mutex_set()
    first = c_void_p()
    second = c_void_p()
    assert callbacks.create(byref(first)) == int(CKR_OK)
    assert callbacks.create(byref(second)) == int(CKR_OK)
    assert first.value
    assert second.value
    assert first.value != second.value
    assert callbacks.lock(first.value) == int(CKR_OK)
    assert callbacks.lock(second.value) == int(CKR_OK)
    assert callbacks.unlock(first.value) == int(CKR_OK)
    assert callbacks.unlock(second.value) == int(CKR_OK)
    assert callbacks.destroy(first.value) == int(CKR_OK)
    assert callbacks.destroy(second.value) == int(CKR_OK)
