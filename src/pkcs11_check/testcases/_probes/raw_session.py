"""Child-side entry point for probes that drive the module via ctypes.CDLL directly.

Sibling of session.py for families that bypass RawPKCS11 and call C_* functions
through ctypes function-pointer arithmetic (test_mutex_callback_safety, ckr/_ctypes_raw,
test_initialize_args, ckr/test_ckr_null_params, etc.).

Invariants honoured:

Probe-invariant legend (I1–I12): bare ``(I#)`` cites across the framework resolve
here — NOT June-gap I1–I7 or FABLE I-1–I-5. I1 crash isolation (crash-is-a-finding);
I2 honeypot (demand-zero mmap) semantics; I3 no PIN leakage (child gets the PIN via
_P11CHECK_PIN only); I4 classification stays parent-side (child prints data, never
classify/fail_as/xfail_as); I5 each family's output protocol unchanged; I6 coverage
preserved; I7 rv-trace preserved; I8 hang → rc 124 + timeout marker (crash-class
finding); I9 pytest markers unchanged; I10 behavioral equivalence via
compare-results; I11 Windows ABI (argv list, no shell quoting); I12 vendor-neutral
probes.

I3  — PIN is never read or embedded here (no C_Login; the raw CDLL path is pre-auth).
I4  — a clean C_GetFunctionList setup refusal prints SETUP_XFAIL:<reason> to stdout
      and returns 0.  A non-SEH CDLL-load OSError emits HARNESS_ERROR instead; an
      access violation propagates for crash attribution.  The child never calls
      classify/fail_as/xfail_as.
I6  — atexit writes {"call_log": {}, "mechanism_counts": {}, ...} to
      _P11CHECK_SUBPROCESS_COVERAGE.  The raw CDLL path has no RawPKCS11 wrapper so
      call_log is always empty; the parent's get_raw_subprocess_coverage() still
      accumulates the correct shape (an empty dict is a valid, zero-count log).
      The fw#73 counters ride along under "call_counters".
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
from typing import Any, cast

from pkcs11_check.core.call_counters import (
    current_bucket,
    current_receipts,
    flatten_current,
    lost_probe_keys,
    note_own_probe_spawn,
    probes_lost,
    record_call,
    record_return,
)
from pkcs11_check.core.crash_codes import ctypes_access_violation_code
from pkcs11_check.raw._platform import windows_dll_directory
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.testcases._probes._emit import (
    emit_harness_error,
    emit_rv_trace,
    flush_probe_sidecar,
    mark_python_finalized,
    probe_coverage_receipt,
    rv_trace_enabled,
    write_coverage,
)
from pkcs11_check.testcases._probes.params import ProbeParams


@dataclass
class RawCtypesContext:
    """State delivered to the run_fn in a probe_main_raw child.

    Attributes:
        lib:       The loaded ctypes.CDLL (raw module handle), wrapped in the
                   counting proxy so every ``C_*`` call is recorded. The proxy
                   is duck-type compatible: attribute access, ``restype`` /
                   ``argtypes`` / ``errcheck`` configuration, calls, and
                   AttributeError for missing symbols all behave exactly as on
                   the raw library.
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
    interface: str = "auto"
    module_path: str = ""


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


def _get_function_list(lib: ctypes.CDLL, module: str = "") -> tuple[ctypes.c_void_p | None, int]:
    """Return the opaque function-list pointer and exact provider CKR.

    Mirrors the ctypes boilerplate in ckr/_ctypes_raw.py and test_operation_state.py:
      C_GetFunctionList.restype  = CK_RV (c_ulong)
      C_GetFunctionList.argtypes = [POINTER(c_void_p)]
      rv = C_GetFunctionList(byref(funclist_ptr))
    """
    get_fn_list = lib.C_GetFunctionList
    get_fn_list.restype = ctypes.c_ulong  # CK_RV
    get_fn_list.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    funclist_ptr = ctypes.c_void_p()
    # This runs on the raw CDLL before ctx.lib is wrapped, so the call is recorded
    # explicitly (mirrors the C_GetFunctionList site in raw/api.py). A raising
    # attempt counts entry-only (crash parity), not silence. The bucket is
    # captured once so a mid-call switch cannot split the pair.
    bucket = current_bucket()
    record_call("C_GetFunctionList", bucket=bucket, module=module)
    rv = get_fn_list(ctypes.byref(funclist_ptr))
    record_return("C_GetFunctionList", int(rv), bucket=bucket, module=module)
    if rv != 0:  # CKR_OK = 0
        return None, int(rv)
    return funclist_ptr, int(rv)


def _write_raw_coverage() -> None:
    """Write the raw-path coverage file: empty call_log plus flattened counters (I6).

    The raw CDLL path has no RawPKCS11 wrapper, so ``call_log`` is always empty;
    the fw#73 counters (fed by the counting CDLL proxy, ``call_func``, and the
    explicit ``C_GetFunctionList`` record above) ride along under ``call_counters``,
    with the echoed probe receipt plus propagated grandchild receipts; the same
    counters flush to the probe sidecar for the parent's torn-coverage fallback.
    """
    flattened = flatten_current()
    keys = lost_probe_keys()
    flush_probe_sidecar(flattened, lost_keys=keys or None, probes_lost=probes_lost())
    write_coverage(
        {},
        {},
        call_counters=flattened,
        probes_lost=probes_lost(),
        receipt=probe_coverage_receipt(),
        receipts=current_receipts() or None,
        lost_keys=keys or None,
    )


class _CountingFuncPtr:
    """One wrapped ``C_*`` symbol: counts entry+exit, forwards everything else.

    Attribute reads and writes (notably ``restype``/``argtypes``/``errcheck``)
    go straight to the real ctypes function object, so probes configure the
    wrapped symbol exactly as they would the raw one. The call's return value
    passes through unchanged; only the counters observe the call.
    """

    _name: str
    _func: Any
    _module: str

    def __init__(self, name: str, func: Any, module: str = "") -> None:
        # object.__setattr__: __setattr__ below forwards EVERYTHING to the real
        # func, so the wrapper's own state must bypass it.
        object.__setattr__(self, "_name", name)
        object.__setattr__(self, "_func", func)
        object.__setattr__(self, "_module", module)

    def __call__(self, *args: Any, bucket: str | None = None) -> Any:
        # Keyword-only: C arguments always arrive positionally through ctypes,
        # so this can never collide with a call argument. The bucket is
        # captured once so a mid-call switch cannot split the pair.
        target = bucket if bucket is not None else current_bucket()
        record_call(self._name, bucket=target, module=self._module)
        result = self._func(*args)
        try:
            rv = int(result)
        except (TypeError, ValueError):
            # An exotic restype (e.g. c_void_p answering None) has no integer
            # RV: the value still passes through and only the entry is counted,
            # exactly as if the call had not returned.
            return result
        record_return(self._name, rv, bucket=target, module=self._module)
        return result

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_func"), name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(object.__getattribute__(self, "_func"), name, value)


class _CountingCDLL:
    """Transparent ``ctypes.CDLL`` proxy that counts every ``C_*`` call (fw#73).

    ``C_*`` attribute access returns a counting wrapper (cached per symbol,
    mirroring CDLL's own caching); anything else passes through to the real
    library untouched. A missing symbol raises the real library's AttributeError
    unchanged, so probes keep their absent-export handling (e.g. CKR:NO_METHOD).
    Note: the proxy is not a ``ctypes.CDLL`` instance (``isinstance`` checks
    against CDLL fail); it is duck-type compatible only.
    """

    def __init__(self, lib: ctypes.CDLL, module: str = "") -> None:
        self._lib = lib
        self._module = module

    def __getattr__(self, name: str) -> Any:
        func = getattr(self._lib, name)
        if not name.startswith("C_"):
            return func
        wrapper = _CountingFuncPtr(name, func, self._module)
        setattr(self, name, wrapper)
        return wrapper


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def counting_cdll(lib: ctypes.CDLL, module: str = "") -> ctypes.CDLL:
    """Wrap a raw ``ctypes.CDLL`` so every ``C_*`` call through it is counted (fw#73).

    For probes that drive the module through a direct-symbol handle instead of
    ``ctx.lib`` (e.g. the CKR NULL-params probes): the proxy is duck-type
    compatible with the raw library (attribute access, ``restype``/``argtypes``
    configuration, calls, and AttributeError for missing symbols all behave the
    same), so call sites only change the construction line. ``module`` is the
    id every call through the proxy attributes to (the child's module path).
    """
    return cast(ctypes.CDLL, _CountingCDLL(lib, module))


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
    # FIRST, before anything can fail: proof that CPython finalization ran. atexit is
    # LIFO so this fires last and never clobbers the real coverage write. The parent
    # reads its absence as 'the module terminated the process from inside a PKCS#11
    # call', so a load failure here must not look the same as one.
    atexit.register(mark_python_finalized)
    # SECOND, before any provider call: the child's own launch record, so a
    # supervisor that dies before its parent-side note flushes still leaves
    # this launch attributable (#88R23-1). After the atexit registration so
    # a fail-closed spawn refusal still finalizes (Python-level death, not
    # a module termination).
    note_own_probe_spawn()
    params = ProbeParams.load(sys.argv[1])

    # Windows DLL-dir handling before CDLL load (I11).
    try:
        lib = _load_cdll(params.module_path)
    except OSError as exc:
        if ctypes_access_violation_code(exc) is not None:
            raise
        emit_harness_error(exc, phase=f"CDLL load {params.module_path!r}")
        return

    func_list, get_function_list_rv = _get_function_list(lib, module=params.module_path)
    if func_list is None:
        print(f"SETUP_XFAIL:C_GetFunctionList rejected with {ckr_name(get_function_list_rv)}")
        return

    _done: list[bool] = [False]

    def _cleanup() -> None:
        """Write coverage and emit rv-trace (idempotent; atexit-registered; I6, I7)."""
        if _done[0]:
            return
        _done[0] = True
        # Raw CDLL path: no RawPKCS11 to query, so call_log is always empty (I6).
        _write_raw_coverage()
        if rv_trace_enabled():
            # No automatic RV interceptor for ctypes calls; emit empty trace (I7).
            emit_rv_trace([])

    atexit.register(_cleanup)

    # Wrap the raw library AFTER _get_function_list (recorded explicitly there):
    # every C_* attribute access through ctx.lib now counts entry+exit. The cast
    # keeps the declared type (and all downstream probe signatures) as CDLL; the
    # proxy is duck-type compatible.
    ctx = RawCtypesContext(
        lib=cast(ctypes.CDLL, _CountingCDLL(lib, module=params.module_path)),
        func_list=func_list,
        cleanup=_cleanup,
        interface=params.interface or "auto",
        module_path=params.module_path,
    )
    run_fn(ctx, params.extra)
