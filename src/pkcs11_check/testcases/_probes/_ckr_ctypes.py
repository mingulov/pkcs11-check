"""Shared CK_FUNCTION_LIST pointer-arithmetic bootstrap for raw-ctypes ``ckr`` probes.

This is a child-side helper, *not* a probe: it has no ``probe_main`` / ``probe_main_raw``
entry point and never loads a module by itself.  It ports the CK_FUNCTION_LIST walk from
the legacy ``ckr/_ctypes_raw.py`` f-string child script into real, importable functions so
every raw-ctypes ``ckr`` probe can resolve and call ``C_*`` functions directly through the
module's function-pointer table -- bypassing RawPKCS11's safety checks (needed to pass the
NULL / oversized arguments a wrapper would reject).

The whole Family-B raw-ctypes family reuses ``FUNC_INDICES`` + ``make_caller``:

    from pkcs11_check.testcases._probes._ckr_ctypes import make_caller
    call_func, get_func = make_caller(ctx.func_list)   # ctx: RawCtypesContext
    rv = call_func("C_GetInfo", ctypes.c_void_p(None))
"""

from __future__ import annotations

import ctypes
from collections.abc import Callable
from typing import Any, cast

# CK_RV is a CK_ULONG.
_CK_RV = ctypes.c_ulong

# Function indices into CK_FUNCTION_LIST (0-based, *after* the leading CK_VERSION field),
# in pkcs11f.h order.  Verbatim from the legacy ckr/_ctypes_raw.py bootstrap.
#
#   0=C_Initialize, 1=C_Finalize, 2=C_GetInfo, 3=C_GetFunctionList,
#   4=C_GetSlotList, 5=C_GetSlotInfo, 6=C_GetTokenInfo,
#   7=C_GetMechanismList, 8=C_GetMechanismInfo, 9=C_InitToken,
#   10=C_InitPIN, 11=C_SetPIN, 12=C_OpenSession, 13=C_CloseSession,
#   14=C_CloseAllSessions, 15=C_GetSessionInfo, 16=C_GetOperationState,
#   17=C_SetOperationState, 18=C_Login, 19=C_Logout, ... 42=C_SignInit, 43=C_Sign,
#   ..., 48=C_GenerateRandom.
FUNC_INDICES: dict[str, int] = {
    "C_Initialize": 0,
    "C_Finalize": 1,
    "C_GetInfo": 2,
    "C_GetSlotList": 4,
    "C_GetSlotInfo": 5,
    "C_GetTokenInfo": 6,
    "C_OpenSession": 12,
    "C_CloseSession": 13,
    "C_EncryptInit": 29,
    "C_Encrypt": 30,
    "C_DecryptInit": 33,
    "C_Decrypt": 34,
    "C_DigestInit": 37,
    "C_Digest": 38,
    "C_SignInit": 42,
    "C_Sign": 43,
    "C_GenerateRandom": 48,
}


def make_caller(func_list: Any) -> tuple[Callable[..., int], Callable[[int], int]]:
    """Build ``(call_func, get_func)`` bound to a CK_FUNCTION_LIST pointer.

    Args:
        func_list: The opaque ``ctypes.c_void_p`` returned by ``C_GetFunctionList``
            (i.e. ``RawCtypesContext.func_list``).  It points at a CK_FUNCTION_LIST
            whose first field is a CK_VERSION (2 bytes, padded to pointer alignment),
            followed by ``C_*`` function pointers one pointer-width apart in
            pkcs11f.h order.

    Returns:
        A ``(call_func, get_func)`` pair:

        * ``get_func(index)`` -> the raw function address (an ``int``) stored at
          ``index`` in the table (index counted *after* the CK_VERSION field), via
          pointer arithmetic.
        * ``call_func(name, *args)`` -> resolve ``FUNC_INDICES[name]``, build a
          ``CK_RV (*)(...)`` CFUNCTYPE from the runtime types of ``*args``, invoke it,
          and return the CK_RV as an ``int``.

    The returned callables perform no safety validation: they exist precisely so a
    probe can hand the module a NULL / malformed argument the RawPKCS11 wrapper would
    otherwise reject.  A crash from such a call is a finding (docs/probe-soundness.md).
    """
    ptr_size = ctypes.sizeof(ctypes.c_void_p)
    base = func_list.value

    def get_func(index: int) -> int:
        # The version field is a CK_VERSION (2 bytes) padded to pointer alignment;
        # the function pointers follow, one pointer-width apart.
        offset = ptr_size + (index * ptr_size)
        addr = ctypes.cast(base + offset, ctypes.POINTER(ctypes.c_void_p)).contents.value
        # Runtime value is an integer address for every implemented function; cast keeps
        # the ctypes `int | None` annotation off the public signature (behaviour verbatim
        # from the legacy get_func, which returned the address unchanged).
        return cast(int, addr)

    def call_func(name: str, *args: Any) -> int:
        idx = FUNC_INDICES[name]
        addr = get_func(idx)
        # Build a ctypes callable: CK_RV (*func)(arg_types...) from the actual arg types.
        arg_types = [type(a) for a in args]
        func_type = ctypes.CFUNCTYPE(_CK_RV, *arg_types)
        func = func_type(addr)
        return int(func(*args))

    return call_func, get_func
