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
  ``"fork_after_initialize"``       -> fork after C_Initialize; inherited child is a
                                       bounded, phase-aware robustness observation (POSIX)
  ``"session_object_isolation"``    -> cross-process session-object isolation: parent
                                       setup plus a spawned fresh-interpreter child
  ``"session_object_isolation_child"`` -> the spawned isolation child (never forked)
  ``"reload_cycle_5x"``             -> load->init->ops->finalize x5 in one process

os.fork nuance (``fork_after_initialize`` only): the forked GRANDCHILD branch terminates
with ``os._exit(<code>)`` (never return / sys.exit) so it does NOT re-run ``probe_main``'s
atexit handlers (coverage write + C_Finalize) a second time -- each of those must fire
once, in the parent process only.  The exact fork sequence, waitpid/status handling, and
every printed marker are preserved byte-for-byte for the parent classifiers in
``test_subprocess_safety.py`` (I5).  P11C-0198-017: PKCS #11 gives no portability guarantee
for an inherited child after a multithreaded fork, so the parent bounds the wait and the
parent test treats every inherited-child disposition as an observation, never a verdict.

Spawn nuance (``session_object_isolation``): the child is a fresh interpreter launched via
``sys.executable -u -m ...subprocess_safety`` (argv list, no shell -- I11), so the
isolation premise holds on Windows too.  The parent relays the child's ``CHILD_*`` lines
and appends the terminal status itself, reconstructing the exact fork-era transcript shape
for the unchanged parent parser (I5).

PIN handling (I3): the probes that log in read the PIN from ``_P11CHECK_PIN`` (set by
``run_probe(pin=...)`` and inherited by the spawned child) -- never from params/argv/
source.  ``ProbeParams.dump`` structurally rejects PIN-bearing keys in the spawned child's
params.  This CLOSES the two legacy leaks that baked the PIN literal into the generated
child script.

Launch with ``coverage="session"``.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
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
from pkcs11_check.raw.rv import CkrAssertionError
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
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_TYPE_INVALID,
)
from pkcs11_check.testcases._probes._emit import HARNESS_ERROR_MARKER
from pkcs11_check.testcases._probes.params import ProbeParams
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main

#: Bound on the inherited fork child's lifetime; the outer probe timeout is 15 s.
_FORK_CHILD_TIMEOUT_S = 10.0
#: Bound on the spawned isolation child's lifetime; the outer probe timeout is 90 s.
_ISOLATION_CHILD_TIMEOUT_S = 60.0
_ISOLATION_CHILD_PROBE = "session_object_isolation_child"

#: Spawned-child stdout lines relayed verbatim to the parent transcript (I5/I7).
_CHILD_RELAY_PREFIXES = (
    "CHILD_FATAL:",
    "CHILD_EXC:",
    "CHILD_FOUND:",
    "CHILD_PHASE:",
    "P11_RV_TRACE_JSON:",
    HARNESS_ERROR_MARKER,
)


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


def _wait_child_bounded(pid: int, timeout_s: float) -> tuple[str, int | None]:
    """Reap a forked child, SIGKILLing it past *timeout_s* (POSIX-only).

    Returns ``("exit", code)``, ``("signal", sig)``, or ``("timeout", None)``. A child
    that exits in the race between the last poll and SIGKILL keeps its real disposition.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done != 0:
            if os.WIFSIGNALED(status):
                return ("signal", os.WTERMSIG(status))
            return ("exit", os.WEXITSTATUS(status))
        if time.monotonic() >= deadline:
            break
        time.sleep(0.05)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        _, status = os.waitpid(pid, 0)
        if os.WIFSIGNALED(status):
            return ("signal", os.WTERMSIG(status))
        return ("exit", os.WEXITSTATUS(status))
    # os.kill succeeds on a zombie, so a child that exited in the race between
    # the last poll and SIGKILL reaps here with its real disposition. Only death
    # by our own SIGKILL reports a timeout.
    _, status = os.waitpid(pid, 0)
    if os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL:
        return ("timeout", None)
    if os.WIFSIGNALED(status):
        return ("signal", os.WTERMSIG(status))
    return ("exit", os.WEXITSTATUS(status))


def _fork_after_initialize(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """Fork after C_Initialize - inherited child is a bounded observation (POSIX-only).

    P11C-0198-017: PKCS #11 gives no portability guarantee after a multithreaded fork,
    so the child reports flushed CHILD_PHASE progress lines and the parent bounds the
    wait at _FORK_CHILD_TIMEOUT_S (CHILD_TIMEOUT past it). An inherited-child deadlock
    therefore surfaces as a phase-aware observation, never as an outer-timeout crash.
    """
    raw = ctx.raw
    rv = raw.C_Initialize(None)
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:Parent_Init:0x{rv:08x}")
        return
    pid = os.fork()
    if pid == 0:
        # Grandchild: os._exit so probe_main's atexit handlers do NOT run a second time.
        try:
            print("CHILD_PHASE:FinalizeInherited", flush=True)
            raw.C_Finalize(None)
            print("CHILD_PHASE:Init", flush=True)
            rv = raw.C_Initialize(None)
            if rv != CKR_OK:
                print(f"CHILD_FATAL:Init:0x{rv:08x}", flush=True)
                os._exit(2)
            try:
                print("CHILD_PHASE:Slot", flush=True)
                get_slot_ids(raw)
            except CkrAssertionError as exc:
                print(f"CHILD_FATAL:Slot:0x{exc.rv:08x}", flush=True)
                os._exit(7)
            print("CHILD_PHASE:Finalize", flush=True)
            raw.C_Finalize(None)
            os._exit(0)
        except Exception as exc:  # noqa: BLE001 - crash-safety: report child exception, never swallow
            print(f"CHILD_EXC:{type(exc).__name__}:{exc}", flush=True)
            os._exit(1)
    else:
        disposition, value = _wait_child_bounded(pid, _FORK_CHILD_TIMEOUT_S)
        if disposition == "timeout":
            print("CHILD_TIMEOUT", flush=True)
        elif value is None:
            # Unreachable: the wait helper pairs every non-timeout disposition with a value.
            raise AssertionError(f"missing {disposition} value")
        elif disposition == "signal":
            print(f"CHILD_SIGNAL:{value}", flush=True)
        else:
            print(f"CHILD_EXIT:{value}", flush=True)
        raw.C_Finalize(None)


# Login error swallow rule: catch only the two documented "already logged in / wrong user
# type" cases per the project login policy / PIN handling section. Other login failures
# must surface.
_LOGIN_OK_TO_IGNORE = (CKR_USER_ALREADY_LOGGED_IN, CKR_USER_TYPE_INVALID)


def _safe_login(raw_obj: RawPKCS11, sess_h: int, user_type: int, pin_bytes: bytes) -> None:
    try:
        login_user(raw_obj, sess_h, user_type, pin_bytes)
    except CkrAssertionError as exc:
        if exc.rv not in _LOGIN_OK_TO_IGNORE:
            raise


def _isolation_child_params(
    module_path: str, interface: str, slot_index: int, label: str
) -> dict[str, Any]:
    """Build the spawned isolation child's params (I3: dump rejects PIN-bearing keys)."""
    return ProbeParams.dump(
        {
            "module_path": module_path,
            "interface": interface,
            "slot_id": slot_index,
            "extra": {"probe": _ISOLATION_CHILD_PROBE, "label": label},
        }
    )


def _isolation_child_argv(params_path: str) -> list[str]:
    """Fresh-interpreter argv for the isolation child (argv list, no shell -- I11)."""
    return [
        sys.executable,
        "-u",
        "-m",
        "pkcs11_check.testcases._probes.subprocess_safety",
        params_path,
    ]


def _stream_text(value: str | bytes | None) -> str:
    """Decode a possibly-bytes partial stream from ``TimeoutExpired`` to text."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def _isolation_child_env() -> dict[str, str]:
    """Child env: inherits ``_P11CHECK_PIN`` (I3) but not the parent coverage sentinel.

    The child must not write the parent's ``_P11CHECK_SUBPROCESS_COVERAGE`` file: a stale
    child write would make a later parent C-``exit()`` look like a clean Python death to
    the abrupt-exit detector. Coverage writers no-op when the variable is absent, and the
    fork-era child contributed no coverage either (``os._exit``), so nothing is lost.
    """
    env = dict(os.environ)
    env.pop("_P11CHECK_SUBPROCESS_COVERAGE", None)
    return env


def _session_object_isolation(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """Cross-process session-object isolation (spawned fresh-interpreter child).

    A session object created in the parent process must NOT be visible to a child process
    that Initializes the module from a clean image (distinct applications per PKCS#11
    v3.2). P11C-0198-017: the child is spawned, never forked, so the isolation premise
    holds on Windows too and no inherited post-fork state is involved.
    """
    pin = _pin_bytes()
    slot = ctx.slot_id if ctx.slot_id is not None else 0
    label = b"crossproc-" + uuid.uuid4().bytes.hex().encode()[:16]

    # --- Parent: initialize, create session object ---
    raw = ctx.raw
    rv = raw.C_Initialize(None)
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:Parent_Init:0x{rv:08x}")
        return
    try:
        slot_list = get_slot_ids(raw)
    except CkrAssertionError as exc:
        print(f"SETUP_XFAIL:Parent_GetSlotList:0x{exc.rv:08x}")
        raw.C_Finalize(None)
        return
    if slot >= len(slot_list):
        print(f"SETUP_EXC:Parent_Slot:{slot}>={len(slot_list)}", flush=True)
        raw.C_Finalize(None)
        return
    slot_id = slot_list[slot]
    try:
        sh = open_session(raw, slot_id, CKF_RW_SESSION | CKF_SERIAL_SESSION)
    except CkrAssertionError as exc:
        print(f"SETUP_XFAIL:Parent_OpenSession:0x{exc.rv:08x}")
        raw.C_Finalize(None)
        return
    if pin is not None:
        try:
            _safe_login(raw, sh, 1, pin)
        except CkrAssertionError as exc:
            print(f"SETUP_XFAIL:Parent_Login:0x{exc.rv:08x}")
            close_session_quietly(raw, sh)
            raw.C_Finalize(None)
            return
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
        print(f"SETUP_XFAIL:Parent_CreateObject:0x{rv:08x}")
        close_session_quietly(raw, sh)
        raw.C_Finalize(None)
        return
    print(f"PARENT_LABEL:{label.decode()}")

    # --- Spawn a fresh-interpreter child (a different application) ---
    child_params = _isolation_child_params(ctx.module_path, ctx.interface, slot, label.decode())
    params_fd, params_path = tempfile.mkstemp(suffix=".json", prefix="p11-isolation-child-")
    try:
        with os.fdopen(params_fd, "w", encoding="utf-8") as fh:
            json.dump(child_params, fh)
        proc = subprocess.Popen(
            _isolation_child_argv(params_path),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_isolation_child_env(),
        )
        try:
            out, err = proc.communicate(timeout=_ISOLATION_CHILD_TIMEOUT_S)
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            proc.kill()
            rest_out, rest_err = proc.communicate()
            out = _stream_text(exc.stdout) + (rest_out or "")
            err = _stream_text(exc.stderr) + (rest_err or "")
            timed_out = True
    finally:
        try:
            os.unlink(params_path)
        except OSError:
            pass
    for line in out.splitlines():
        if line.startswith(_CHILD_RELAY_PREFIXES):
            print(line, flush=True)
    if err:
        print(err, file=sys.stderr, end="")
    child_rc = proc.returncode
    if timed_out:
        print("CHILD_TIMEOUT", flush=True)
    elif child_rc is not None and child_rc < 0:
        print(f"CHILD_SIGNAL:{-child_rc}", flush=True)
    elif child_rc is not None and child_rc <= 255:
        print(f"CHILD_EXIT:{child_rc}", flush=True)
    # else: no terminal marker for an unrepresentable exit code (notably a Windows
    # crash code above 255). The parent then reports missing child status -- loud and
    # unresolved, never a fabricated signal number.
    # Parent cleanup
    raw.C_DestroyObject(sh, h)
    close_session_quietly(raw, sh)
    raw.C_Finalize(None)


def _session_object_isolation_child(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """Spawned isolation child: fresh image, find the parent's label, report, exit.

    Never forked: ``probe_main`` loaded the module cleanly at Level.LOAD and this handler
    drives its own Initialize/session/login/find over ``ctx.raw``. Every step reports a
    flushed CHILD_PHASE line first; refusal markers and exit codes match the fork-era
    child byte-for-byte so the parent transcript shape (I5) is unchanged. ``sys.exit``
    raises SystemExit (BaseException), so refusal exits are never caught by the
    in-process ``except Exception`` below.
    """
    pin = _pin_bytes()
    slot = ctx.slot_id if ctx.slot_id is not None else 0
    raw = ctx.raw
    try:
        label = extra["label"].encode()
        print("CHILD_PHASE:Init", flush=True)
        rv = raw.C_Initialize(None)
        if rv != CKR_OK:
            print(f"CHILD_FATAL:Init:0x{rv:08x}", flush=True)
            sys.exit(2)
        print("CHILD_PHASE:Slot", flush=True)
        try:
            slot_list = get_slot_ids(raw)
        except CkrAssertionError as exc:
            print(f"CHILD_FATAL:Slot:0x{exc.rv:08x}", flush=True)
            sys.exit(7)
        if slot >= len(slot_list):
            print(f"CHILD_EXC:SlotRange:{slot}>={len(slot_list)}", flush=True)
            sys.exit(5)
        slot_id = slot_list[slot]
        print("CHILD_PHASE:Open", flush=True)
        try:
            sh = open_session(raw, slot_id, CKF_RW_SESSION | CKF_SERIAL_SESSION)
        except CkrAssertionError as exc:
            print(f"CHILD_FATAL:Open:0x{exc.rv:08x}", flush=True)
            sys.exit(8)
        if pin is not None:
            print("CHILD_PHASE:Login", flush=True)
            try:
                _safe_login(raw, sh, 1, pin)
            except CkrAssertionError as exc:
                print(f"CHILD_FATAL:Login:0x{exc.rv:08x}", flush=True)
                sys.exit(6)
        # Find-objects by the parent's label.
        find_tmpl = template(
            attr_bytes(CKA_LABEL, label),
            attr_ulong(CKA_CLASS, CKO_DATA),
        )
        print("CHILD_PHASE:FindInit", flush=True)
        rv = raw.C_FindObjectsInit(sh, find_tmpl.ptr, find_tmpl.count)
        if rv != CKR_OK:
            print(f"CHILD_FATAL:FindInit:0x{rv:08x}", flush=True)
            sys.exit(3)
        print("CHILD_PHASE:Find", flush=True)
        handles = (CK_OBJECT_HANDLE * 8)()
        count = CK_ULONG(0)
        rv = raw.C_FindObjects(sh, handles, 8, byref(count))
        if rv != CKR_OK:
            print(f"CHILD_FATAL:Find:0x{rv:08x}", flush=True)
            sys.exit(4)
        print("CHILD_PHASE:FindFinal", flush=True)
        rv = raw.C_FindObjectsFinal(sh)
        if rv != CKR_OK:
            print(f"CHILD_FATAL:FindFinal:0x{rv:08x}", flush=True)
            sys.exit(9)
        print(f"CHILD_FOUND:{count.value}", flush=True)
        close_session_quietly(raw, sh)
        raw.C_Finalize(None)
        sys.exit(0)
    except Exception as exc:  # noqa: BLE001 - crash-safety: disambiguate in-process error from init failure, not a swallow
        # `except Exception` (not BaseException) so the sys.exit() refusal exits above
        # (SystemExit) and KeyboardInterrupt propagate normally. The exit-5 path is only
        # for in-process Python errors that the parent can use to disambiguate
        # "init worked but a later step broke" from "init never started".
        print(f"CHILD_EXC:{type(exc).__name__}:{exc}", flush=True)
        sys.exit(5)


def _reload_cycle_5x(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """Load -> init -> ops -> finalize, 5 times. No crash or leak."""
    pin = _pin_bytes()
    for _i in range(5):
        raw = RawPKCS11.from_lib(ctx.module_path, interface=ctx.interface)
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
    _ISOLATION_CHILD_PROBE: _session_object_isolation_child,
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
