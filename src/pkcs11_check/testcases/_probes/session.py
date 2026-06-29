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
- raw.rv_trace          -> list[dict]      (I7)
- raw.enable_rv_trace(maxlen=...) to activate tracing
"""

from __future__ import annotations

import atexit
import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.bootstrap import close_session_quietly, get_slot_ids, login_user, open_session
from pkcs11_check.raw.types_std import (
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKR_CRYPTOKI_ALREADY_INITIALIZED,
    CKR_OK,
    CKU_USER,
)
from pkcs11_check.testcases._probes.params import ProbeParams

_RV_TRACE_MARKER = "P11_RV_TRACE_JSON:"


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


# ---------------------------------------------------------------------------
# Internal helpers (mirror the preamble's generated helper functions exactly)
# ---------------------------------------------------------------------------


def _rv_trace_enabled() -> bool:
    """True when rv-trace is requested via PKCS11_CHECK_RV_TRACE or the compact variant."""
    value = os.environ.get("PKCS11_CHECK_RV_TRACE", "").strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    return bool(os.environ.get("PKCS11_CHECK_RV_TRACE_COMPACT"))


def _rv_trace_maxlen() -> int | None:
    """Ring-buffer window size from PKCS11_CHECK_RV_TRACE_COMPACT, or None (full)."""
    value = os.environ.get("PKCS11_CHECK_RV_TRACE_COMPACT")
    if not value:
        return None
    try:
        maxlen = int(value)
    except ValueError:
        return None
    return maxlen if maxlen > 0 else None


def _emit_rv_trace(raw: RawPKCS11) -> None:
    """Print the P11_RV_TRACE_JSON: marker line to stdout (atexit-registered; I7)."""
    try:
        print(
            _RV_TRACE_MARKER + json.dumps(raw.rv_trace, separators=(",", ":")),
            flush=True,
        )
    except (OSError, TypeError, ValueError):
        pass


def _write_coverage(raw: RawPKCS11) -> None:
    """Write call_log + mechanism_counts to _P11CHECK_SUBPROCESS_COVERAGE (I6).

    Key shape matches what run_with_coverage / get_preamble_subprocess_coverage expects:
    - "call_log"          -> dict[str, int]
    - "mechanism_counts"  -> dict[str, int]  (CKM ints converted to str for JSON)
    """
    path = os.environ.get("_P11CHECK_SUBPROCESS_COVERAGE")
    if not path:
        return
    try:
        payload: dict[str, Any] = {
            "call_log": raw.call_log,
            "mechanism_counts": {str(k): v for k, v in raw.mechanism_counts.items()},
        }
        with open(path, "w") as fh:
            json.dump(payload, fh)
    except (OSError, TypeError, ValueError):
        pass


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


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
    I6 — atexit writes {"call_log": …, "mechanism_counts": …} to
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
    if _rv_trace_enabled():
        raw.enable_rv_trace(maxlen=_rv_trace_maxlen())
        atexit.register(_emit_rv_trace, raw)

    # Mutable state shared with the cleanup closure (Python closures capture by
    # reference; single-element lists work where nonlocal would require nested def).
    _initialized: list[bool] = [False]
    _sh_ref: list[int | None] = [None]
    _done: list[bool] = [False]

    def _cleanup() -> None:
        """Write coverage, close session, finalize (idempotent; atexit-registered)."""
        if _done[0]:
            return
        _done[0] = True
        _write_coverage(raw)
        if _sh_ref[0] is not None:
            close_session_quietly(raw, _sh_ref[0])
        if _initialized[0]:
            try:
                raw.C_Finalize(None)
            except Exception:  # noqa: BLE001 -- atexit; suppress all module errors
                pass

    atexit.register(_cleanup)

    slot_id = params.slot_id
    ctx = ProbeContext(raw=raw, sh=None, slot_id=slot_id, cleanup=_cleanup)

    if level == Level.LOAD:
        run_fn(ctx, params.extra)
        return

    # --- C_Initialize (all levels above LOAD) ---
    rv = raw.C_Initialize(None)
    assert rv in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED), f"C_Initialize: 0x{rv:08x}"
    _initialized[0] = True

    if level == Level.INIT:
        run_fn(ctx, params.extra)
        return

    # --- Slot discovery (SESSION and LOGIN) ---
    if slot_id is None:
        slots = get_slot_ids(raw)
        if not slots:
            print("SETUP_XFAIL:no slot with a present token")
            return
        slot_id = slots[0]
    ctx.slot_id = slot_id

    # --- Open session ---
    sh = open_session(raw, slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION)
    _sh_ref[0] = sh
    ctx.sh = sh

    # --- Login (I3: only when PIN env var is set; never call login with None PIN) ---
    if level == Level.LOGIN:
        pin = os.environ.get("_P11CHECK_PIN")
        if pin is not None:
            login_user(raw, sh, CKU_USER, pin.encode())

    run_fn(ctx, params.extra)
