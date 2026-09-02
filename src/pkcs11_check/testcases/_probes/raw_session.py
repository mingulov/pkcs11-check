"""Child-side entry point for probes that drive the module via ctypes.CDLL directly.

Sibling of session.py for families that bypass RawPKCS11 and call C_* functions
through ctypes function-pointer arithmetic (test_mutex_callback_safety, ckr/_ctypes_raw,
test_initialize_args, ckr/test_ckr_null_params, etc.).

Invariants honoured:

I3  — PIN is never read or embedded here (no C_Login; the raw CDLL path is pre-auth).
I4  — a clean setup failure (CDLL load, C_GetFunctionList) prints SETUP_XFAIL:<reason>
      to stdout and exits 0; the child never raises or calls classify/fail_as/xfail_as.
I6  — atexit writes {"call_log": {}, "mechanism_counts": {}} to
      _P11CHECK_SUBPROCESS_COVERAGE.  The raw CDLL path has no RawPKCS11 wrapper so
      call_log is always empty; the parent's get_raw_subprocess_coverage() still
      accumulates the correct shape (an empty dict is a valid, zero-count log).
I7  — atexit emits P11_RV_TRACE_JSON:[] when PKCS11_CHECK_RV_TRACE is set.  The raw
      CDLL path has no automatic RV interceptor; the trace is always empty unless a
      probe explicitly records calls via its own mechanism outside this entry point.
I11 — on Windows, os.add_dll_directory is called with the module's own directory so a
      provider's bundled DLLs (e.g. OpenSSL) resolve correctly.

Real API names resolved from _raw_subprocess.py and ckr/_ctypes_raw.py:
  - lib.C_GetFunctionList(byref(funclist_ptr)) -- the only guaranteed exported symbol
  - funclist_ptr: ctypes.c_void_p (opaque pointer to CK_FUNCTION_LIST)
  - coverage shape: {"call_log": dict[str, int], "mechanism_counts": dict[str, int]}
"""

from __future__ import annotations

import atexit
import ctypes
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pkcs11_check.raw._platform import windows_dll_directory
from pkcs11_check.testcases._probes._emit import (
    emit_rv_trace,
    rv_trace_enabled,
    write_coverage,
)
from pkcs11_check.testcases._probes.params import ProbeParams


@dataclass
class RawCtypesContext:
    """State delivered to the run_fn in a probe_main_raw child.

    Attributes:
        lib:       The loaded ctypes.CDLL (raw module handle).
        func_list: Opaque c_void_p pointing at CK_FUNCTION_LIST, as returned by
                   C_GetFunctionList.  Probes that need individual function pointers
                   can index into this with pointer arithmetic (see ckr/_ctypes_raw.py
                   get_func() pattern).
        cleanup:   Idempotent cleanup callable; called automatically at atexit but
                   may also be invoked by the probe for early teardown.
    """

    lib: ctypes.CDLL
    func_list: Any  # ctypes.c_void_p (opaque; Any avoids ctypes generic-type noise)
    cleanup: Callable[[], None]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


# Windows DLL-search handles kept alive for the process (add_dll_directory returns a cookie
# that must outlive the CDLL; api.py keeps its own per-instance list).
_dll_dir_handles: list[Any] = []


def _load_cdll(lib_path: str) -> ctypes.CDLL:
    """Load a PKCS#11 .so / .dll, adding its directory to the Windows DLL search path (I11)."""
    dll_dir = windows_dll_directory(lib_path)
    if dll_dir is not None:
        _dll_dir_handles.append(os.add_dll_directory(dll_dir))  # type: ignore[attr-defined]
    return ctypes.CDLL(lib_path)


def _get_function_list(lib: ctypes.CDLL) -> ctypes.c_void_p | None:
    """Call C_GetFunctionList and return the opaque funclist pointer, or None on failure.

    Mirrors the ctypes boilerplate in ckr/_ctypes_raw.py and test_operation_state.py:
      C_GetFunctionList.restype  = CK_RV (c_ulong)
      C_GetFunctionList.argtypes = [POINTER(c_void_p)]
      rv = C_GetFunctionList(byref(funclist_ptr))
    """
    get_fn_list = lib.C_GetFunctionList
    get_fn_list.restype = ctypes.c_ulong  # CK_RV
    get_fn_list.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    funclist_ptr = ctypes.c_void_p()
    rv = get_fn_list(ctypes.byref(funclist_ptr))
    if rv != 0:  # CKR_OK = 0
        return None
    return funclist_ptr


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def probe_main_raw(run_fn: Callable[[RawCtypesContext, dict[str, Any]], None]) -> None:
    """Child-side entry point for raw ctypes.CDLL probes.

    Usage (child script):

        from pkcs11_check.testcases._probes.raw_session import probe_main_raw, RawCtypesContext

        def run(ctx: RawCtypesContext, extra: dict) -> None:
            ...  # call ctx.lib.C_* or index ctx.func_list directly

        if __name__ == "__main__":
            probe_main_raw(run)

    The child is invoked as:  python <script.py> <params.json>

    Coverage (I6): the atexit handler always writes the coverage file even though
    call_log is empty for the raw CDLL path -- the parent expects the file in every
    run where _P11CHECK_SUBPROCESS_COVERAGE is set.

    RV trace (I7): the atexit handler emits P11_RV_TRACE_JSON:[] when rv-trace is
    enabled.  The raw CDLL path has no automatic interceptor, so the list is always
    empty; record_subprocess_rv_trace ignores an empty trace.
    """
    params = ProbeParams.load(sys.argv[1])

    # Windows DLL-dir handling before CDLL load (I11).
    try:
        lib = _load_cdll(params.module_path)
    except OSError as exc:
        print(f"SETUP_XFAIL:cannot load CDLL {params.module_path!r}: {exc}")
        sys.exit(0)

    func_list = _get_function_list(lib)
    if func_list is None:
        print("SETUP_XFAIL:C_GetFunctionList failed (non-zero CK_RV)")
        sys.exit(0)

    _done: list[bool] = [False]

    def _cleanup() -> None:
        """Write coverage and emit rv-trace (idempotent; atexit-registered; I6, I7)."""
        if _done[0]:
            return
        _done[0] = True
        # Raw CDLL path: no RawPKCS11 to query, so call_log is always empty (I6).
        write_coverage({}, {})
        if rv_trace_enabled():
            # No automatic RV interceptor for ctypes calls; emit empty trace (I7).
            emit_rv_trace([])

    atexit.register(_cleanup)

    ctx = RawCtypesContext(lib=lib, func_list=func_list, cleanup=_cleanup)
    run_fn(ctx, params.extra)
