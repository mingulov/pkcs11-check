"""Probe: destructive token-management CKR checks (C_InitToken / C_InitPIN / C_SetPIN).

Ported verbatim from the legacy ``ckr/test_ckr_destructive.py`` child scripts.  Each probe
runs against a *throwaway* token: the parent mints a disposable token, passes its module
path as ``module_path``, and points the module's config file at the child via the
``PKCS11_CHECK_TOKEN_CONF_ENV``-named env var (inherited from the parent's environment).

Runs through ``probe_main`` at ``Level.INIT``: the infra does C_Initialize only; each probe
body performs its own slot discovery and (where the legacy test body did) opens a session
and/or logs in with a HARDCODED TEST PIN.  Those SO/user PINs (``b"87654321"`` / ``b"1234"``)
are test *fixtures* baked into the throwaway-token probe -- they are NOT the configured
module PIN, so no PIN travels through params or env (Invariant I3: this file never reads the
configured p11_config PIN).  Session teardown + rv-trace are handled by ``probe_main`` atexit
(C_Finalize implicitly closes any session opened in the body), matching the legacy
``_p11check_cleanup_session`` / rv-trace setup.

Dispatch on ``extra["probe"]`` (one child body each):
  ``"init_token_session_exists"``      -> open session, then C_InitToken (SESSION_EXISTS)
  ``"init_token_wrong_so_pin"``        -> C_InitToken (no session) with a wrong SO PIN
  ``"set_pin_wrong_old"``              -> open session + user login, C_SetPIN wrong old PIN
  ``"init_pin_not_logged_in"``         -> open session (no login), C_InitPIN
  ``"init_pin_short_pin"``             -> open session + SO login, C_InitPIN 1-byte PIN
  ``"init_pin_token_not_initialized"`` -> uninitialized-token C_InitPIN flow (NO_SLOTS-aware)

Output protocol (byte-identical to the legacy child, for the parent
``_classify_destructive_ckr`` over the first ``CKR:0x...`` line):
  ``CKR:0x{rv:08x}``   -- return value of the destructive op under test
  ``OK``               -- probe reached its expected point
  ``NO_SLOTS``         -- uninitialized-token probe found no present slot (parent skips)

A wrong/failed setup ``assert`` trips (non-zero exit) -> the parent reports a child failure;
a crash (returncode < 0) is a provider crash finding.

Required ``extra`` keys:
  ``"probe"`` -- one of the dispatch keys above.

Launch with ``coverage="session"`` and no ``pin`` (destructive probes self-provision their
throwaway token; they never use the configured PIN).
"""

from __future__ import annotations

import ctypes
from collections.abc import Callable
from typing import Any

from pkcs11_check.raw.types_std import (
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKR_OK,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _discover_slot(ctx: ProbeContext) -> int:
    """Discover the first present slot (mirrors the legacy _run_destructive preamble)."""
    sc = ctypes.c_ulong(0)
    ctx.raw.C_GetSlotList(1, None, ctypes.byref(sc))
    sl = (ctypes.c_ulong * sc.value)()
    ctx.raw.C_GetSlotList(1, sl, ctypes.byref(sc))
    return int(sl[0])


def _init_token_session_exists(ctx: ProbeContext) -> None:
    slot = _discover_slot(ctx)
    # Open a session first
    sess = ctypes.c_ulong(0)
    rv = ctx.raw.C_OpenSession(
        slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(sess)
    )
    assert rv == CKR_OK, f"OpenSession: 0x{rv:08x}"

    # Try InitToken with session open
    so_pin = b"87654321"
    so_pin_buf = (ctypes.c_ubyte * len(so_pin))(*so_pin)
    label = b"reinit-test     "  # 32 bytes padded
    label_buf = (ctypes.c_ubyte * 32)(*label.ljust(32))
    rv = ctx.raw.C_InitToken(slot, so_pin_buf, len(so_pin), label_buf)
    print(f"CKR:0x{rv:08x}")
    print("OK")


def _init_token_wrong_so_pin(ctx: ProbeContext) -> None:
    slot = _discover_slot(ctx)
    wrong_pin = b"WRONGPIN"
    pin_buf = (ctypes.c_ubyte * len(wrong_pin))(*wrong_pin)
    label = b"reinit-test     "
    label_buf = (ctypes.c_ubyte * 32)(*label.ljust(32))
    rv = ctx.raw.C_InitToken(slot, pin_buf, len(wrong_pin), label_buf)
    print(f"CKR:0x{rv:08x}")
    print("OK")


def _set_pin_wrong_old(ctx: ProbeContext) -> None:
    slot = _discover_slot(ctx)
    sess = ctypes.c_ulong(0)
    rv = ctx.raw.C_OpenSession(
        slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(sess)
    )
    assert rv == CKR_OK
    sh = sess.value
    # Login with correct PIN first
    pin = b"1234"
    ctx.raw.C_Login(sh, 1, (ctypes.c_ubyte * 4)(*pin), 4)
    # Try SetPIN with wrong old PIN
    wrong = b"WRONG"
    new_pin = b"5678"
    rv = ctx.raw.C_SetPIN(sh, (ctypes.c_ubyte * 5)(*wrong), 5, (ctypes.c_ubyte * 4)(*new_pin), 4)
    print(f"CKR:0x{rv:08x}")
    print("OK")
    ctx.raw.C_Logout(sh)


def _init_pin_not_logged_in(ctx: ProbeContext) -> None:
    slot = _discover_slot(ctx)
    sess = ctypes.c_ulong(0)
    rv = ctx.raw.C_OpenSession(
        slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(sess)
    )
    assert rv == CKR_OK
    sh = sess.value
    # Don't login - try InitPIN
    new_pin = b"9999"
    rv = ctx.raw.C_InitPIN(sh, (ctypes.c_ubyte * 4)(*new_pin), 4)
    print(f"CKR:0x{rv:08x}")
    print("OK")


def _init_pin_short_pin(ctx: ProbeContext) -> None:
    slot = _discover_slot(ctx)
    sess = ctypes.c_ulong(0)
    rv = ctx.raw.C_OpenSession(
        slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(sess)
    )
    assert rv == CKR_OK
    sh = sess.value
    # Login as SO
    so_pin = b"87654321"
    rv = ctx.raw.C_Login(sh, 0, (ctypes.c_ubyte * len(so_pin))(*so_pin), len(so_pin))
    assert rv == CKR_OK, f"SO login failed: 0x{rv:08x}"
    # Try InitPIN with a 1-byte PIN
    short_pin = b"X"
    rv = ctx.raw.C_InitPIN(sh, (ctypes.c_ubyte * 1)(*short_pin), 1)
    print(f"CKR:0x{rv:08x}")
    print("OK")
    ctx.raw.C_Logout(sh)


def _init_pin_token_not_initialized(ctx: ProbeContext) -> None:
    # C_Initialize already done by probe_main (Level.INIT). Discover a slot on the
    # uninitialized token, then attempt C_InitPIN without prior InitToken/SO login.
    sc = ctypes.c_ulong(0)
    rv = ctx.raw.C_GetSlotList(1, None, ctypes.byref(sc))
    if rv != CKR_OK:
        print(f"CKR:0x{rv:08x}")
        return
    sl = (ctypes.c_ulong * sc.value)()
    ctx.raw.C_GetSlotList(1, sl, ctypes.byref(sc))
    if sc.value == 0:
        print("NO_SLOTS")
        return
    slot = sl[0]
    sess = ctypes.c_ulong(0)
    rv = ctx.raw.C_OpenSession(
        slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(sess)
    )
    if rv != CKR_OK:
        print(f"CKR:0x{rv:08x}")
        return
    sh = sess.value
    new_pin = b"1234"
    rv = ctx.raw.C_InitPIN(sh, (ctypes.c_ubyte * 4)(*new_pin), 4)
    print(f"CKR:0x{rv:08x}")
    print("OK")


_PROBES: dict[str, Callable[[ProbeContext], None]] = {
    "init_token_session_exists": _init_token_session_exists,
    "init_token_wrong_so_pin": _init_token_wrong_so_pin,
    "set_pin_wrong_old": _set_pin_wrong_old,
    "init_pin_not_logged_in": _init_pin_not_logged_in,
    "init_pin_short_pin": _init_pin_short_pin,
    "init_pin_token_not_initialized": _init_pin_token_not_initialized,
}


def _run(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe = extra["probe"]
    try:
        handler = _PROBES[probe]
    except KeyError:
        raise ValueError(f"unknown probe {probe!r}") from None
    handler(ctx)


if __name__ == "__main__":
    probe_main(_run, level=Level.INIT)
