"""Probe: general-purpose ``C_*`` error conditions driven through raw ctypes.

Pure pre-auth path -- no session, no login (Invariant I3): ``C_Initialize`` /
``C_Finalize`` / ``C_GetInterfaceList`` affect global library state and are reachable
without a token, so they run through ``probe_main_raw`` (loads the CDLL +
``C_GetFunctionList`` only) and this probe does ``C_Initialize`` itself, mirroring the
legacy ``ckr/test_ckr_general.py`` inline children.  The CK_FUNCTION_LIST members are
resolved through the shared caller (``_ckr_ctypes.make_caller``); ``C_GetInterfaceList``
(a v3.0 function absent from the 2.40 function list and from ``FUNC_INDICES``) is resolved
as a *direct* exported CDLL symbol via ``ctx.lib`` -- a module that does not export it
raises ``AttributeError`` and the probe emits ``CKR:NO_METHOD``.

Dispatch on ``extra["probe"]``:
  ``"double_initialize"``        -> ``C_Initialize`` twice, classify the 2nd CK_RV
  ``"finalize_not_initialized"`` -> Init, Finalize, Finalize again, classify the 2nd
  ``"get_interface_list"``       -> ``C_GetInterfaceList(NULL, &count)``

Output protocol (byte-identical to the legacy children, for ``assert_ckr_subprocess_ok``):
  double_initialize:
    ``CKR:already_init_accepted``        -- 2nd C_Initialize returned CKR_OK
    ``CKR:CRYPTOKI_ALREADY_INITIALIZED`` -- 2nd C_Initialize returned that CK_RV
    ``CKR:0x{rv:08x}``                   -- any other CK_RV
  finalize_not_initialized:
    ``CKR:finalize_accepted``            -- 2nd C_Finalize returned CKR_OK
    ``CKR:CRYPTOKI_NOT_INITIALIZED``     -- 2nd C_Finalize returned that CK_RV
    ``CKR:0x{rv:08x}``                   -- any other CK_RV
  get_interface_list:
    ``CKR:FUNCTION_NOT_SUPPORTED``       -- module returned CKR_FUNCTION_NOT_SUPPORTED
    ``CKR:OK:{count}_interfaces``        -- CKR_OK; count = advertised interface count
    ``CKR:0x{rv:08x}``                   -- any other CK_RV
    ``CKR:NO_METHOD``                    -- module does not export C_GetInterfaceList
  every path also prints the ``OK`` completion marker.

Required ``extra`` keys:
  ``"probe"`` -- ``"double_initialize"`` / ``"finalize_not_initialized"`` /
                 ``"get_interface_list"``

Launch with ``coverage="raw"`` (the raw CDLL path has no RawPKCS11 wrapper; I6).
"""

from __future__ import annotations

import ctypes
from collections.abc import Callable
from typing import Any

from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKR_CRYPTOKI_ALREADY_INITIALIZED,
    CKR_CRYPTOKI_NOT_INITIALIZED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
)
from pkcs11_check.testcases._probes._ckr_ctypes import make_caller
from pkcs11_check.testcases._probes.raw_session import RawCtypesContext, probe_main_raw


def _double_initialize(call_func: Callable[..., int]) -> None:
    """C_Initialize twice; classify the second CK_RV (Sec.5.4.1)."""
    call_func("C_Initialize", ctypes.c_void_p(None))
    rv2 = call_func("C_Initialize", ctypes.c_void_p(None))
    if rv2 == CKR_OK:
        print("CKR:already_init_accepted")
    elif rv2 == CKR_CRYPTOKI_ALREADY_INITIALIZED:
        print("CKR:CRYPTOKI_ALREADY_INITIALIZED")
    else:
        print(f"CKR:0x{rv2:08x}")
    print("OK")
    call_func("C_Finalize", ctypes.c_void_p(None))


def _finalize_not_initialized(call_func: Callable[..., int]) -> None:
    """Init, Finalize, then Finalize again; classify the second Finalize CK_RV."""
    call_func("C_Initialize", ctypes.c_void_p(None))
    call_func("C_Finalize", ctypes.c_void_p(None))
    # Now try finalize again - should get NOT_INITIALIZED
    rv = call_func("C_Finalize", ctypes.c_void_p(None))
    if rv == CKR_OK:
        print("CKR:finalize_accepted")
    elif rv == CKR_CRYPTOKI_NOT_INITIALIZED:
        print("CKR:CRYPTOKI_NOT_INITIALIZED")
    else:
        print(f"CKR:0x{rv:08x}")
    print("OK")


def _get_interface_list(ctx: RawCtypesContext, call_func: Callable[..., int]) -> None:
    """C_GetInterfaceList(NULL, &count) via the direct exported symbol.

    ``C_GetInterfaceList`` is a v3.0 function that is not present in the 2.40
    CK_FUNCTION_LIST resolved by ``make_caller``; it is resolved here as a direct
    exported CDLL symbol.  A v2.40 module that does not export it raises
    ``AttributeError`` -> ``CKR:NO_METHOD`` (mirrors the legacy RawPKCS11 path, which
    raised ``AttributeError`` when the function was absent from the negotiated list).
    """
    call_func("C_Initialize", ctypes.c_void_p(None))
    try:
        try:
            c_get_interface_list = ctx.lib.C_GetInterfaceList
        except AttributeError:
            print("CKR:NO_METHOD")  # v2.40 module, C_GetInterfaceList not available
            print("OK")
            return
        c_get_interface_list.restype = ctypes.c_ulong  # CK_RV
        c_get_interface_list.argtypes = [ctypes.c_void_p, ctypes.POINTER(CK_ULONG)]
        count = CK_ULONG(0)
        rv = c_get_interface_list(None, ctypes.byref(count))
        if rv == CKR_FUNCTION_NOT_SUPPORTED:
            print("CKR:FUNCTION_NOT_SUPPORTED")
        elif rv == CKR_OK:
            print(f"CKR:OK:{count.value}_interfaces")
        else:
            print(f"CKR:0x{rv:08x}")
        print("OK")
    finally:
        call_func("C_Finalize", ctypes.c_void_p(None))


def _run(ctx: RawCtypesContext, extra: dict[str, Any]) -> None:
    call_func, _get_func = make_caller(ctx.func_list)

    probe = extra["probe"]
    if probe == "double_initialize":
        _double_initialize(call_func)
    elif probe == "finalize_not_initialized":
        _finalize_not_initialized(call_func)
    elif probe == "get_interface_list":
        _get_interface_list(ctx, call_func)
    else:
        raise ValueError(f"unknown probe {probe!r}")


if __name__ == "__main__":
    probe_main_raw(_run)
