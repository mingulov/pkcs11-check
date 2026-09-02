"""Child-side entry point for probes that drive the module via RawPKCS11.

Mirrors subprocess_session_preamble's runtime behaviour as real, typed code: load the
module, optionally init / open-session / login, hand control to run_fn, and on exit dump
coverage + the rv-trace line.  The PIN is read from _P11CHECK_PIN only (Invariant I3).

Real API names resolved from _subprocess_preamble.subprocess_session_preamble:
- open_session(raw, slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION) from bootstrap
- login_user(raw, sh, CKU_USER, pin.encode())                      from bootstrap
- close_session_quietly(raw, sh)                                    from bootstrap
- raw.call_log          -> dict[str, int]  (already str-keyed)
- raw.mechanism_counts  -> dict[int, int]  (must str()-convert keys for JSON, I6)
- raw.mechanism_rv_counts -> dict[int, dict[int, int]] (same JSON key normalization)
- raw.rv_trace          -> list[dict]      (I7)
- raw.enable_rv_trace(maxlen=...) to activate tracing
"""

from __future__ import annotations

import atexit
import ctypes
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pkcs11_check.core.crash_codes import ctypes_access_violation_code
from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
    get_slot_ids,
    login_user,
    open_session,
    resolve_slot_id,
)
from pkcs11_check.raw.types_std import (
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKR_CRYPTOKI_ALREADY_INITIALIZED,
    CKR_OK,
    CKU_USER,
)
from pkcs11_check.testcases._probes._emit import (
    emit_rv_trace,
    rv_trace_enabled,
    rv_trace_maxlen,
    write_coverage,
)
from pkcs11_check.testcases._probes.params import ProbeParams


class Level(StrEnum):
    LOAD = "load"  # from_lib only; no C_Initialize
    INIT = "init"  # + C_Initialize; no session
    SESSION = "session"  # + open session; no login
    LOGIN = "login"  # + C_Login (only when _P11CHECK_PIN is set; I3)


@dataclass
class ProbeContext:
    raw: RawPKCS11
    sh: int | None
    slot_id: int | None
    cleanup: Callable[[], None]
    module_path: str


# ---------------------------------------------------------------------------
# Internal helpers (thin wrappers over _emit.py; keep RawPKCS11-specific logic here)
# ---------------------------------------------------------------------------


def _emit_rv_trace(raw: RawPKCS11) -> None:
    """Emit the P11_RV_TRACE_JSON: marker to stdout (atexit-registered; I7)."""
    emit_rv_trace(raw.rv_trace)


def _write_coverage(raw: RawPKCS11) -> None:
    """Write function/mechanism counts and RV state to subprocess coverage (I6).

    Integer mechanism and return-value keys are converted to strings for JSON compatibility.
    """
    write_coverage(
        raw.call_log,
        {str(k): v for k, v in raw.mechanism_counts.items()},
        raw.call_log_ok,
        {
            str(mechanism): {str(rv): count for rv, count in counts.items()}
            for mechanism, counts in raw.mechanism_rv_counts.items()
        },
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


class _ProbeTeardown:
    """Idempotent child teardown: write coverage, close the session, C_Finalize -- at most once.

    Extracted from ``probe_main`` so the run-at-most-once contract is directly testable. It is
    both registered via ``atexit`` and exposed as ``ctx.cleanup`` (a probe may trigger it
    explicitly). ``probe_main`` also invokes it from normal control flow so an access violation
    cannot be hidden by Python's atexit exception handling. Double invocation is a no-op after
    the first run.
    """

    def __init__(self, raw: RawPKCS11) -> None:
        self.raw = raw
        self.sh: int | None = None
        self.initialized = False
        self._done = False

    def __call__(self) -> None:
        if self._done:
            return
        self._done = True
        _write_coverage(self.raw)
        if self.sh is not None:
            close_session_quietly(self.raw, self.sh)
        if self.initialized:
            try:
                self.raw.C_Finalize(None)
            except OSError as exc:
                if ctypes_access_violation_code(exc) is not None:
                    raise
            except (AttributeError, ctypes.ArgumentError):
                pass


def probe_main(
    run_fn: Callable[[ProbeContext, dict[str, Any]], None],
    *,
    level: Level = Level.LOGIN,
) -> None:
    """Child-side entry point: load module, set up to *level*, call *run_fn*, exit.

    Invariants honoured:

    I3 — PIN travels only via _P11CHECK_PIN env var; never serialised into params/argv.
         C_Login is skipped when the env var is absent.
    I4 — child never calls classify()/fail_as()/xfail_as(); a clean setup failure
         prints SETUP_XFAIL:<reason> to stdout and exits 0.
    I6 — atexit writes call, mechanism, OK, and mechanism-RV counts to
         _P11CHECK_SUBPROCESS_COVERAGE so the parent's get_preamble_subprocess_coverage()
         can aggregate it.
    I7 — atexit emits P11_RV_TRACE_JSON:<json> when PKCS11_CHECK_RV_TRACE is set,
         matching the format record_subprocess_rv_trace() expects.
    """
    params = ProbeParams.load(sys.argv[1])
    raw = RawPKCS11.from_lib(params.module_path)

    # Enable RV trace before any C_* calls so initialisation appears in the trace (I7).
    # The atexit handler is registered first; atexit is LIFO so it fires *after* the
    # coverage/cleanup handler below -- matching the preamble's registration order.
    if rv_trace_enabled():
        raw.enable_rv_trace(maxlen=rv_trace_maxlen())
        atexit.register(_emit_rv_trace, raw)

    teardown = _ProbeTeardown(raw)
    atexit.register(teardown)

    try:
        slot_id = params.slot_id
        ctx = ProbeContext(
            raw=raw, sh=None, slot_id=slot_id, cleanup=teardown, module_path=params.module_path
        )

        if level == Level.LOAD:
            run_fn(ctx, params.extra)
            return

        # --- C_Initialize (all levels above LOAD) ---
        rv = raw.C_Initialize(None)
        assert rv in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED), f"C_Initialize: 0x{rv:08x}"
        teardown.initialized = True

        if level == Level.INIT:
            run_fn(ctx, params.extra)
            return

        # --- Slot discovery (SESSION and LOGIN) ---
        # params.slot_id is a slot INDEX (config.slot semantics), not a raw slot ID: resolve it
        # through the present-token slot list exactly as fixtures.py does. Passing the raw index to
        # C_OpenSession crashes with CKR_SLOT_ID_INVALID on dynamic-slot modules (index != id).
        slots = get_slot_ids(raw)
        if not slots:
            print("SETUP_XFAIL:no slot with a present token")
            return
        slot_id = resolve_slot_id(slots, slot_id)
        ctx.slot_id = slot_id

        # --- Open session ---
        sh = open_session(raw, slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        teardown.sh = sh
        ctx.sh = sh

        # --- Login (I3: only when PIN env var is set; never call login with None PIN) ---
        if level == Level.LOGIN:
            pin = os.environ.get("_P11CHECK_PIN")
            if pin is not None:
                login_user(raw, sh, CKU_USER, pin.encode())

        run_fn(ctx, params.extra)
    finally:
        # Do teardown in ordinary control flow: exceptions raised by atexit handlers do not
        # affect the child exit code, which would otherwise hide a Windows provider fault.
        teardown()
