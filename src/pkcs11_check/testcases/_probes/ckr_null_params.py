"""Probe: pre-auth ``C_*`` NULL-parameter checks driven through raw ctypes.

Pure pre-auth path -- no session, no login (Invariant I3): these ``C_*`` calls are
reachable without a token, so they run through ``probe_main_raw`` (loads the CDLL +
``C_GetFunctionList`` only) and this probe does ``C_Initialize`` itself, mirroring the
legacy ``ckr/_ctypes_raw.py`` bootstrap.  Function pointers are resolved through the
shared CK_FUNCTION_LIST caller (``_ckr_ctypes.make_caller``).

Dispatch on ``extra["probe"]``:
  ``"get_info"``      -> ``C_GetInfo(NULL)``
  ``"get_slot_list"`` -> ``C_GetSlotList(1, NULL, NULL)``

Output protocol (byte-identical to the legacy child, for ``_check_null_result``):
  ``CKR:0x{rv:08x}``                    -- the return value of the NULL call
  ``CKR:0x{rv:08x}:Initialize_failed``  -- C_Initialize returned a fatal CK_RV (exit 1)

Required ``extra`` keys:
  ``"probe"`` -- ``"get_info"`` or ``"get_slot_list"``

Launch with ``coverage="raw"`` (the raw CDLL path has no RawPKCS11 wrapper; I6).
"""

from __future__ import annotations

import ctypes
import sys
from typing import Any

from pkcs11_check.raw.types_std import CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_OK
from pkcs11_check.testcases._probes._ckr_ctypes import make_caller
from pkcs11_check.testcases._probes.raw_session import RawCtypesContext, probe_main_raw


def _run(ctx: RawCtypesContext, extra: dict[str, Any]) -> None:
    call_func, _get_func = make_caller(ctx.func_list)

    # Initialize the module first (mirror the legacy CKR_OK / ALREADY_INITIALIZED
    # acceptance and the :Initialize_failed sentinel + exit(1) path).
    rv = call_func("C_Initialize", ctypes.c_void_p(None))
    if rv != CKR_OK and rv != CKR_CRYPTOKI_ALREADY_INITIALIZED:
        print(f"CKR:0x{rv:08x}:Initialize_failed")
        sys.exit(1)

    probe = extra["probe"]
    if probe == "get_info":
        rv = call_func("C_GetInfo", ctypes.c_void_p(None))
    elif probe == "get_slot_list":
        rv = call_func(
            "C_GetSlotList", ctypes.c_ubyte(1), ctypes.c_void_p(None), ctypes.c_void_p(None)
        )
    else:
        raise ValueError(f"unknown probe {probe!r}")

    print(f"CKR:0x{rv:08x}")

    call_func("C_Finalize", ctypes.c_void_p(None))


if __name__ == "__main__":
    probe_main_raw(_run)
