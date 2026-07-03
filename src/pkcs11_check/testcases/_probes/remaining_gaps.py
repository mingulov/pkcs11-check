"""Probes: remaining OASIS-gap subprocess tests (legacy-parallel + dual-function update).

Ported from the inline child-scripts of ``testcases/test_remaining_gaps.py`` that ran under a
per-config session (the legacy ``_run_config_script`` / ``_build_preamble`` helper).  The probe
runs at ``Level.INIT`` -- ``probe_main`` does ``from_lib`` + ``C_Initialize`` (with the same
``rv in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED)`` accept) and finalizes at exit; this module
reproduces the rest of ``_build_preamble`` faithfully: it resolves the slot INDEX into
``get_slot_ids`` (``config.slot`` is an index, matching ``fixtures.py``), opens an RW session,
and logs in when a PIN is present.  rv-trace + coverage are handled by ``probe_main`` (I7/I6).

Dispatch on ``extra["probe"]``:
  ``"get_function_status"``    -> C_GetFunctionStatus + C_CancelFunction (legacy parallel, Sec.5.15)
  ``"cancel_function"``        -> C_CancelFunction
  ``"sign_encrypt_update"``    -> C_SignEncryptUpdate (dual-function, CK_FUNCTION_LIST index 56)
  ``"decrypt_verify_update"``  -> C_DecryptVerifyUpdate (dual-function, CK_FUNCTION_LIST index 57)

Every printed marker (``GFS:`` / ``CF:`` / ``SEU:`` / ``DVU:`` / ``SKIP:``) is byte-identical to
the legacy scripts for the parent classifiers in ``test_remaining_gaps.py`` (I5).

PIN handling (I3): login reads the PIN from ``_P11CHECK_PIN`` (set by ``run_probe(pin=...)``); it
is never embedded in params/argv/source.  The legacy already routed the PIN through this env var
(``subprocess_session_preamble``), so there was no source leak to close -- this preserves that.

Launch with ``coverage="session"``.
"""

from __future__ import annotations

import ctypes
import os
import sys
from collections.abc import Callable
from ctypes import byref
from typing import Any

from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
    get_slot_ids,
    login_user,
    open_session,
)
from pkcs11_check.raw.types_std import (
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKU_USER,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _get_function_status(raw: RawPKCS11, sh: int) -> None:
    """C_GetFunctionStatus then C_CancelFunction (legacy parallel, always NOT_PARALLEL)."""
    rv = raw.C_GetFunctionStatus(sh)
    print(f"GFS:0x{rv:08x}")
    rv2 = raw.C_CancelFunction(sh)
    print(f"CF:0x{rv2:08x}")


def _cancel_function(raw: RawPKCS11, sh: int) -> None:
    """C_CancelFunction (legacy parallel, always NOT_PARALLEL)."""
    rv = raw.C_CancelFunction(sh)
    print(f"CF:0x{rv:08x}")


def _sign_encrypt_update(raw: RawPKCS11, sh: int) -> None:
    """C_SignEncryptUpdate (index 56) exists and returns a defined CKR without crashing."""
    if "C_SignEncryptUpdate" not in raw.available_function_names():
        print("SKIP:C_SignEncryptUpdate not in function list")
        return
    part = (ctypes.c_ubyte * 4)(*b"test")
    out_len = ctypes.c_ulong()
    rv = raw.C_SignEncryptUpdate(sh, part, 4, None, byref(out_len))
    print(f"SEU:0x{rv:08x}")


def _decrypt_verify_update(raw: RawPKCS11, sh: int) -> None:
    """C_DecryptVerifyUpdate (index 57) exists and returns a defined CKR without crashing."""
    if "C_DecryptVerifyUpdate" not in raw.available_function_names():
        print("SKIP:C_DecryptVerifyUpdate not in function list")
        return
    part = (ctypes.c_ubyte * 4)(*b"test")
    out_len = ctypes.c_ulong()
    rv = raw.C_DecryptVerifyUpdate(sh, part, 4, None, byref(out_len))
    print(f"DVU:0x{rv:08x}")


_PROBES: dict[str, Callable[[RawPKCS11, int], None]] = {
    "get_function_status": _get_function_status,
    "cancel_function": _cancel_function,
    "sign_encrypt_update": _sign_encrypt_update,
    "decrypt_verify_update": _decrypt_verify_update,
}


def _run(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """Open the configured session (slot-index resolution + login-if-PIN), then dispatch.

    Reproduces ``_build_preamble``: ``ctx.slot_id`` is an INDEX into ``get_slot_ids`` (the
    ``config.slot`` index semantics used across the framework).  ``probe_main`` (Level.INIT)
    already did ``C_Initialize`` and finalizes at exit; here we only add session + login.
    """
    raw = ctx.raw
    slot = ctx.slot_id if ctx.slot_id is not None else 0
    slot_list = get_slot_ids(raw)
    if slot >= len(slot_list):
        # Dead path in the pool (slot 0 is always present); mirrors the legacy FATAL exit.
        print(f"FATAL:GetSlotList:index={slot}:count={len(slot_list)}")
        sys.exit(1)
    slot_id = slot_list[slot]
    sh = open_session(raw, slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION)
    try:
        # I3: PIN only via _P11CHECK_PIN (set by run_probe(pin=...)); never from params/source.
        pin = os.environ.get("_P11CHECK_PIN")
        if pin is not None:
            login_user(raw, sh, CKU_USER, pin.encode())

        probe = extra["probe"]
        try:
            handler = _PROBES[probe]
        except KeyError:
            raise ValueError(f"unknown probe {probe!r}") from None
        handler(raw, sh)
    finally:
        close_session_quietly(raw, sh)


if __name__ == "__main__":
    probe_main(_run, level=Level.INIT)
