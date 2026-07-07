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

from pkcs11_check.raw.api import function_list_header_size
from pkcs11_check.raw.metadata_std import FUNCTION_INDICES

# CK_RV is a CK_ULONG.
_CK_RV = ctypes.c_ulong

# Function indices come from the single generated source of truth (raw.metadata_std) so this
# by-hand bootstrap can never drift from the ABI the rest of the framework targets.  (A prior
# hand copy had drifted: C_GenerateRandom was 48, which is actually C_VerifyInit's slot.)
FUNC_INDICES: dict[str, int] = FUNCTION_INDICES

# Offset of the first C_* pointer after the CK_VERSION header, ABI-derived from raw.api -- NOT
# sizeof(c_void_p), which only coincides on natural-aligned ABIs and is wrong under the packed
# Windows ABI (where the first pointer sits at sizeof(CK_VERSION)).  The pointer *stride* between
# slots genuinely is sizeof(c_void_p) on every ABI.
_HEADER_SIZE = function_list_header_size()
_PTR_SIZE = ctypes.sizeof(ctypes.c_void_p)


def _slot_offset(index: int, *, header_size: int, ptr_size: int) -> int:
    """Byte offset of function-pointer slot ``index``, counted after the CK_VERSION header."""
    return header_size + index * ptr_size


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
    base = func_list.value

    def get_func(index: int) -> int:
        # First C_* pointer sits at the ABI-correct header offset (packed on Windows); the
        # pointers then follow one stride apart.
        offset = _slot_offset(index, header_size=_HEADER_SIZE, ptr_size=_PTR_SIZE)
        addr = ctypes.cast(base + offset, ctypes.POINTER(ctypes.c_void_p)).contents.value
        # Runtime value is an integer address for every implemented function; cast keeps
        # the ctypes `int | None` annotation off the public signature (behaviour verbatim
        # from the legacy get_func, which returned the address unchanged).
        return cast(int, addr)

    def call_func(name: str, *args: Any) -> int:
        idx = FUNC_INDICES[name]
        addr = get_func(idx)
        # Build the CK_RV (*)(arg_types...) signature from the caller's OWN ctypes objects.
        # This is deliberate: the whole point of this bootstrap is to hand the module the
        # exact (possibly NULL / malformed) arguments a probe constructs, which the RawPKCS11
        # wrapper would reject.  Do NOT switch to static argtypes -- that would coerce/reject
        # the fault arguments and defeat the probe.  A non-ctypes arg fails loud here.
        arg_types = [type(a) for a in args]
        func_type = ctypes.CFUNCTYPE(_CK_RV, *arg_types)
        func = func_type(addr)
        return int(func(*args))

    return call_func, get_func
