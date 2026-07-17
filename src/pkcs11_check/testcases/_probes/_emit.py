"""Shared child-side emit helpers for coverage (I6) and rv-trace (I7).

Both RawPKCS11-backed (session.py) and ctypes.CDLL-backed (raw_session.py) entry
points write coverage and emit the rv-trace line using these functions so there is
ONE implementation of each protocol.

Coverage shape (I6):
    {"call_log": dict[str, int], "mechanism_counts": dict[str, int]}

RV-trace shape (I7):
    "P11_RV_TRACE_JSON:" + json.dumps(list[dict])
"""

from __future__ import annotations

import json
import os
from typing import Any

_RV_TRACE_MARKER = "P11_RV_TRACE_JSON:"


def rv_trace_enabled() -> bool:
    """True when rv-trace is requested via PKCS11_CHECK_RV_TRACE or the compact variant."""
    value = os.environ.get("PKCS11_CHECK_RV_TRACE", "").strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    return bool(os.environ.get("PKCS11_CHECK_RV_TRACE_COMPACT"))


def rv_trace_maxlen() -> int | None:
    """Ring-buffer window size from PKCS11_CHECK_RV_TRACE_COMPACT, or None (full)."""
    value = os.environ.get("PKCS11_CHECK_RV_TRACE_COMPACT")
    if not value:
        return None
    try:
        maxlen = int(value)
    except ValueError:
        return None
    return maxlen if maxlen > 0 else None


def write_coverage(
    call_log: dict[str, int],
    mechanism_counts: dict[str, int],
    call_log_ok: dict[str, int] | None = None,
) -> None:
    """Write call_log + mechanism_counts (+ optional call_log_ok) to the coverage file (I6).

    Key shape: {"call_log": dict, "mechanism_counts": dict, "call_log_ok": dict}. The parent's
    get_preamble_subprocess_coverage / get_raw_subprocess_coverage read exactly this shape;
    call_log_ok (per-function CKR_OK counts) feeds the hollow-pass oracle. No-op when the env
    var is absent.
    """
    path = os.environ.get("_P11CHECK_SUBPROCESS_COVERAGE")
    if not path:
        return
    try:
        payload: dict[str, Any] = {
            "call_log": call_log,
            "mechanism_counts": mechanism_counts,
            "call_log_ok": call_log_ok or {},
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
    except (OSError, TypeError, ValueError):
        pass


def emit_rv_trace(trace: list[dict[str, Any]]) -> None:
    """Print the P11_RV_TRACE_JSON: marker line to stdout (I7).

    Called from atexit when rv-trace is enabled.  Passing an empty list is fine;
    the parent's record_subprocess_rv_trace ignores an empty trace.
    """
    try:
        print(
            _RV_TRACE_MARKER + json.dumps(trace, separators=(",", ":")),
            flush=True,
        )
    except (OSError, TypeError, ValueError):
        pass
