"""Probes: subprocess-safety scenarios (post-Finalize, reinit, fork, reload cycles).

Ported verbatim from the legacy inline child-scripts of
``testcases/test_subprocess_safety.py`` (``_run_script`` + ``_inject_rv_trace_emitter``).
Every probe runs at ``Level.LOAD`` -- the entry point does ``from_lib`` only and the probe
drives its own ``C_Initialize`` / ``C_Finalize`` (and, for the isolation/reload probes, its
own session + login), exactly like the legacy scripts.  rv-trace + coverage are handled by
``probe_main`` (I7/I6); ``_inject_rv_trace_emitter`` is intentionally NOT reproduced here.

Dispatch on ``extra["probe"]``:
  ``"post_finalize_get_slot_list"`` -> C_GetSlotList after C_Finalize must not crash
  ``"reinitialize_after_finalize"`` -> C_Initialize after C_Finalize must work
  ``"fork_after_initialize"``       -> fork after C_Initialize; child reinitializes (POSIX)
  ``"session_object_isolation"``    -> cross-process session-object isolation (fork; POSIX)
  ``"reload_cycle_5x"``             -> load->init->ops->finalize x5 in one process

os.fork nuance (``fork_after_initialize`` / ``session_object_isolation``): the forked
GRANDCHILD branch terminates with ``os._exit(<code>)`` (never return / sys.exit) so it does
NOT re-run ``probe_main``'s atexit handlers (coverage write + C_Finalize) a second time --
each of those must fire once, in the parent process only.  The exact fork sequence,
waitpid/status handling, and every printed marker are preserved byte-for-byte for the parent
classifiers in ``test_subprocess_safety.py`` (I5).

PIN handling (I3): the two probes that log in read the PIN from ``_P11CHECK_PIN`` (set by
``run_probe(pin=...)``) -- never from params/argv/source.  This CLOSES the two legacy leaks
that baked the PIN literal into the generated child script.

Launch with ``coverage="session"``.
"""

from __future__ import annotations

import os
import sys
import uuid
from ctypes import byref
from typing import Any

from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
    get_slot_ids,
    login_user,
    open_session,
)
from pkcs11_check.raw.pack import attr_bool, attr_bytes, attr_ulong, template
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_LABEL,
    CKA_PRIVATE,
    CKA_TOKEN,
    CKA_VALUE,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKO_DATA,
    CKR_OK,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _pin_bytes() -> bytes | None:
    """User PIN as bytes from ``_P11CHECK_PIN`` (I3), or None when unset."""
    pin = os.environ.get("_P11CHECK_PIN")
    return pin.encode() if pin is not None else None


def _post_finalize_get_slot_list(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_GetSlotList after C_Finalize must not crash."""
    raw = ctx.raw
    raw.C_Initialize(None)
    get_slot_ids(raw)
    raw.C_Finalize(None)
    try:
        count = CK_ULONG(0)
        raw.C_GetSlotList(1, None, byref(count))
        print("OK: returned after finalize")
    except Exception as e:  # noqa: BLE001 - crash-safety: a survivable post-finalize error is the finding, not a swallow
        print(f"OK: raised {type(e).__name__}")


def _reinitialize_after_finalize(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_Initialize after C_Finalize must work."""
    raw = ctx.raw
    raw.C_Initialize(None)
    raw.C_Finalize(None)
    raw.C_Initialize(None)
    slots = get_slot_ids(raw)
    print(f"OK: reinit, {len(slots)} slots")
    raw.C_Finalize(None)


def _fork_after_initialize(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """Fork after C_Initialize - child reinitializes (POSIX-only; parent test @requires_fork)."""
    raw = ctx.raw
    raw.C_Initialize(None)
    pid = os.fork()
    if pid == 0:
        # Grandchild: os._exit so probe_main's atexit handlers do NOT run a second time.
        try:
            raw.C_Finalize(None)
            raw.C_Initialize(None)
            get_slot_ids(raw)
            raw.C_Finalize(None)
            os._exit(0)
        except Exception as exc:  # noqa: BLE001 - crash-safety: report child exception, never swallow
            print(f"CHILD_EXC:{type(exc).__name__}:{exc}", flush=True)
            os._exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        raw.C_Finalize(None)
        if os.WIFSIGNALED(status):
            child_signal = os.WTERMSIG(status)
            print(f"CHILD_SIGNAL:{child_signal}")
            child_exit = -child_signal
        else:
            child_exit = os.WEXITSTATUS(status)
        print(f"CHILD_EXIT:{child_exit}")


# Login error swallow rule: catch only the two documented "already logged in / wrong user
# type" cases per the project login policy / PIN handling section. Other login failures
# must surface.
_LOGIN_OK_TO_IGNORE = ("CKR_USER_ALREADY_LOGGED_IN", "CKR_USER_TYPE_INVALID")


def _safe_login(raw_obj: RawPKCS11, sess_h: int, user_type: int, pin_bytes: bytes) -> None:
    try:
        login_user(raw_obj, sess_h, user_type, pin_bytes)
    except AssertionError as e:
        msg = str(e)
        if not any(code in msg for code in _LOGIN_OK_TO_IGNORE):
            raise


def _session_object_isolation(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """Cross-process session-object isolation (fork; POSIX-only; parent test @requires_fork).

    A session object created in the parent process must NOT be visible to a child process
    that re-Initializes the module (distinct applications per PKCS#11 v3.2).
    """
    pin = _pin_bytes()
    slot = ctx.slot_id if ctx.slot_id is not None else 0
    label = b"crossproc-" + uuid.uuid4().bytes.hex().encode()[:16]

    # --- Parent: initialize, create session object ---
    raw = ctx.raw
    rv = raw.C_Initialize(None)
    if rv != CKR_OK:
        print(f"FATAL:Parent_Init:0x{rv:08x}")
        sys.exit(1)
    slot_list = get_slot_ids(raw)
    if slot >= len(slot_list):
        print(f"FATAL:Slot:{slot}>={len(slot_list)}")
        raw.C_Finalize(None)
        sys.exit(1)
    slot_id = slot_list[slot]
    sh = open_session(raw, slot_id, CKF_RW_SESSION | CKF_SERIAL_SESSION)
    if pin is not None:
        try:
            _safe_login(raw, sh, 1, pin)
        except AssertionError as e:
            print(f"FATAL:Parent_Login:{e}")
            close_session_quietly(raw, sh)
            raw.C_Finalize(None)
            sys.exit(1)
    tmpl = template(
        attr_ulong(CKA_CLASS, CKO_DATA),
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_PRIVATE, False),
        attr_bytes(CKA_LABEL, label),
        attr_bytes(CKA_VALUE, b"parent-data"),
    )
    h = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(sh, tmpl.ptr, tmpl.count, byref(h))
    if rv != CKR_OK:
        print(f"FATAL:Parent_CreateObject:0x{rv:08x}")
        close_session_quietly(raw, sh)
        raw.C_Finalize(None)
        sys.exit(1)
    print(f"PARENT_LABEL:{label.decode()}")

    # --- Fork a child that re-Initializes (different application) ---
    pid = os.fork()
    if pid == 0:
        # Child: must Finalize the inherited handle before re-Initializing,
        # per PKCS#11 v3.2 fork semantics. Grandchild terminates with os._exit
        # so probe_main's atexit handlers do NOT run a second time.
        raw.C_Finalize(None)
        try:
            raw2 = RawPKCS11.from_lib(ctx.module_path)
            rv = raw2.C_Initialize(None)
            if rv != CKR_OK:
                print(f"CHILD_FATAL:Init:0x{rv:08x}")
                sys.stdout.flush()
                os._exit(2)
            slot_list2 = get_slot_ids(raw2)
            slot_id2 = slot_list2[slot]
            sh2 = open_session(raw2, slot_id2, CKF_RW_SESSION | CKF_SERIAL_SESSION)
            if pin is not None:
                try:
                    _safe_login(raw2, sh2, 1, pin)
                except AssertionError as e:
                    print(f"CHILD_FATAL:Login:{e}")
                    sys.stdout.flush()
                    os._exit(6)
            # Find-objects by the parent's label.
            find_tmpl = template(
                attr_bytes(CKA_LABEL, label),
                attr_ulong(CKA_CLASS, CKO_DATA),
            )
            rv = raw2.C_FindObjectsInit(sh2, find_tmpl.ptr, find_tmpl.count)
            if rv != CKR_OK:
                print(f"CHILD_FATAL:FindInit:0x{rv:08x}")
                sys.stdout.flush()
                os._exit(3)
            handles = (CK_OBJECT_HANDLE * 8)()
            count = CK_ULONG(0)
            rv = raw2.C_FindObjects(sh2, handles, 8, byref(count))
            raw2.C_FindObjectsFinal(sh2)
            if rv != CKR_OK:
                print(f"CHILD_FATAL:Find:0x{rv:08x}")
                sys.stdout.flush()
                os._exit(4)
            print(f"CHILD_FOUND:{count.value}")
            close_session_quietly(raw2, sh2)
            raw2.C_Finalize(None)
            sys.stdout.flush()
            os._exit(0)
        except Exception as exc:  # noqa: BLE001 - crash-safety: disambiguate in-process error from init failure, not a swallow
            # `except Exception` (not BaseException) so
            # KeyboardInterrupt / SystemExit / signal-raised exits
            # propagate normally. The exit-5 path is only for
            # in-process Python errors that the parent can use to
            # disambiguate "init worked but later step crashed"
            # from "init never started".
            print(f"CHILD_EXC:{type(exc).__name__}:{exc}")
            sys.stdout.flush()
            os._exit(5)
    else:
        _, status = os.waitpid(pid, 0)
        if os.WIFSIGNALED(status):
            child_signal = os.WTERMSIG(status)
            print(f"CHILD_SIGNAL:{child_signal}")
            child_exit = -child_signal
        else:
            child_exit = os.WEXITSTATUS(status)
        print(f"CHILD_EXIT:{child_exit}")
        # Parent cleanup
        raw.C_DestroyObject(sh, h)
        close_session_quietly(raw, sh)
        raw.C_Finalize(None)


def _reload_cycle_5x(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """Load -> init -> ops -> finalize, 5 times. No crash or leak."""
    pin = _pin_bytes()
    for _i in range(5):
        raw = RawPKCS11.from_lib(ctx.module_path)
        raw.C_Initialize(None)
        try:
            slots = get_slot_ids(raw, label="pkcs11-check")
            if not slots:
                slots = get_slot_ids(raw)
            sh = open_session(raw, slots[0], CKF_RW_SESSION | CKF_SERIAL_SESSION)
            if pin is not None:
                login_user(raw, sh, 1, pin)
            key = gen_aes_key(raw, sh, 128)
            destroy_quietly(raw, sh, key)
            raw.C_CloseSession(sh)
        finally:
            raw.C_Finalize(None)
    print("OK: 5 cycles")


_PROBES = {
    "post_finalize_get_slot_list": _post_finalize_get_slot_list,
    "reinitialize_after_finalize": _reinitialize_after_finalize,
    "fork_after_initialize": _fork_after_initialize,
    "session_object_isolation": _session_object_isolation,
    "reload_cycle_5x": _reload_cycle_5x,
}


def _run(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe = extra["probe"]
    try:
        handler = _PROBES[probe]
    except KeyError:
        raise ValueError(f"unknown probe {probe!r}") from None
    handler(ctx, extra)


if __name__ == "__main__":
    probe_main(_run, level=Level.LOAD)
