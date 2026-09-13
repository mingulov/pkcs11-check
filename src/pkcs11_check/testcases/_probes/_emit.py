"""Shared child-side emit helpers for coverage (I6) and rv-trace (I7).

Both RawPKCS11-backed (session.py) and ctypes.CDLL-backed (raw_session.py) entry
points write coverage and emit the rv-trace line using these functions so there is
ONE implementation of each protocol.

Coverage shape (I6):
    {"call_log": dict[str, int], "mechanism_counts": dict[str, int],
     "call_log_ok": dict[str, int], "mechanism_rv_counts": dict[str, dict[str, int]]}

RV-trace shape (I7):
    "P11_RV_TRACE_JSON:" + json.dumps(list[dict])
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from re import fullmatch
from typing import Any

_RV_TRACE_MARKER = "P11_RV_TRACE_JSON:"

# Child -> parent sentinel for a failure in the HARNESS, not in the module (GH #9/#11).
# Only harness-side cleanup emits it. Everything else keeps its previous attribution, so
# a real module fault -- notably a Windows SEH fault, which surfaces as a catchable
# OSError and a positive exit code rather than a signal -- can never be hidden by it.
HARNESS_ERROR_MARKER = "HARNESS_ERROR:"

# Child -> parent sentinel for a provider observation that was made before a later
# Python-level cleanup/teardown failure.  The child only emits facts; the parent owns
# classification.  Keeping this protocol separate from HARNESS_ERROR is important:
# the latter deliberately removes a record from provider totals.
PROVIDER_FINDING_MARKER = "PROVIDER_FINDING:"
_PROVIDER_FINDING_SCHEMA = 1
_PROVIDER_FINDING_KEYS = frozenset({"schema", "reason", "kind", "operation", "mechanism", "detail"})
_PROVIDER_FINDING_REASONS = frozenset(
    {
        "wrong_result",
        "accepted_invalid",
        "self_contradiction",
        "oracle",
        "not_operational",
        "nonspec_reject",
        "honest_deviation",
        "undeclared_capability",
        "sanctioned_refusal",
    }
)
_PROVIDER_FINDING_KINDS = frozenset({"crypto", "policy", "lifecycle", "metadata"})

# Exceptions that mean "the module did something to us" and must therefore never be
# swallowed as harness noise: they stay findings. Everything else raised while releasing
# our own resources is our bug.
_MODULE_FAULT_EXCEPTIONS = (OSError, MemoryError, SystemError)


def _object_pairs_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Build a JSON object while rejecting duplicate keys."""
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError(f"duplicate provider-finding key: {key!r}")
        payload[key] = value
    return payload


def _validate_provider_finding(payload: object) -> tuple[dict[str, Any] | None, str | None]:
    """Validate the provider-observation wire payload without importing classification."""
    if not isinstance(payload, dict):
        return None, "payload is not an object"
    if set(payload) != _PROVIDER_FINDING_KEYS:
        return None, "payload keys do not match the provider-finding schema"
    if type(payload["schema"]) is not int or payload["schema"] != _PROVIDER_FINDING_SCHEMA:
        return None, "unsupported provider-finding schema"
    reason = payload["reason"]
    if not isinstance(reason, str) or reason not in _PROVIDER_FINDING_REASONS:
        return None, "invalid provider-finding reason"
    kind = payload["kind"]
    if not isinstance(kind, str) or kind not in _PROVIDER_FINDING_KINDS:
        return None, "invalid provider-finding kind"
    operation = payload["operation"]
    if not isinstance(operation, str) or fullmatch(r"C_[A-Za-z0-9_]+", operation) is None:
        return None, "invalid provider-finding operation"
    mechanism = payload["mechanism"]
    if mechanism is not None and (
        not isinstance(mechanism, str) or fullmatch(r"CKM_[A-Za-z0-9_]+", mechanism) is None
    ):
        return None, "invalid provider-finding mechanism"
    detail = payload["detail"]
    if not isinstance(detail, str) or not detail:
        return None, "invalid provider-finding detail"
    try:
        detail_bytes = detail.encode("utf-8")
    except UnicodeEncodeError:
        return None, "invalid provider-finding detail"
    if len(detail_bytes) > 2048 or any(not char.isprintable() for char in detail):
        return None, "invalid provider-finding detail"
    return dict(payload), None


def emit_provider_finding(
    *,
    reason: str,
    kind: str,
    operation: str,
    mechanism: str | None,
    detail: str,
) -> None:
    """Emit one validated provider observation for parent-side classification.

    This helper intentionally has no dependency on ``classification`` or pytest.  A
    child may be killed immediately after this line, so the marker is flushed before
    the probe raises the assertion that describes the provider observation.
    """
    payload: dict[str, Any] = {
        "schema": _PROVIDER_FINDING_SCHEMA,
        "reason": reason,
        "kind": kind,
        "operation": operation,
        "mechanism": mechanism,
        "detail": detail,
    }
    valid, error = _validate_provider_finding(payload)
    if valid is None:
        raise ValueError(error or "invalid provider-finding payload")
    print(PROVIDER_FINDING_MARKER + json.dumps(valid, separators=(",", ":")), flush=True)


def parse_provider_finding(
    stdout: str,
) -> tuple[dict[str, Any] | None, str | None]:
    """Parse at most one strict provider-finding marker from child stdout.

    Returns ``(payload, None)`` for a valid marker, ``(None, None)`` when no marker
    was emitted, and ``(None, error)`` for malformed/duplicate markers.  The latter
    deliberately remains a process-protocol failure at the parent, never a synthetic
    provider classification.
    """
    lines = [line for line in stdout.splitlines() if line.startswith(PROVIDER_FINDING_MARKER)]
    if not lines:
        return None, None
    if len(lines) != 1:
        return None, "duplicate provider-finding marker"
    raw_payload = lines[0].removeprefix(PROVIDER_FINDING_MARKER)
    try:
        payload: object = json.loads(
            raw_payload,
            object_pairs_hook=_object_pairs_without_duplicates,
        )
    except (ValueError, json.JSONDecodeError):
        return None, "provider-finding marker is not valid JSON"
    return _validate_provider_finding(payload)


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


def mark_python_finalized() -> None:
    """Leave proof that CPython finalization ran, if nothing else already has.

    Registered by ``probe_main``/``probe_main_raw`` as their FIRST action, before the
    params file or the module can fail to load. ``atexit`` is LIFO, so this runs last --
    after the real coverage write -- and it never clobbers it: it writes only when the
    coverage file is still empty or unparseable.

    The parent uses the presence of a parseable coverage file to tell "the module called
    exit() from inside a PKCS#11 call and took the process down" apart from "Python
    raised and died normally". Without this, a child that died BEFORE registering its
    teardown would leave the same empty file as a module-terminated process, and would be
    reported as a provider crash. Registering first closes that window.
    """
    path = os.environ.get("_P11CHECK_SUBPROCESS_COVERAGE")
    if not path:
        return
    try:
        with open(path, encoding="utf-8") as fh:
            if isinstance(json.load(fh), dict):
                return
    except (OSError, ValueError):
        pass
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"python_finalized": True}, fh)
    except OSError:
        pass


def write_coverage(
    call_log: dict[str, int],
    mechanism_counts: dict[str, int],
    call_log_ok: dict[str, int] | None = None,
    mechanism_rv_counts: dict[str, dict[str, int]] | None = None,
) -> None:
    """Write function/mechanism counts and their successful/return-value subsets (I6).

    The parent's subprocess coverage readers consume exactly this shape. ``call_log_ok`` feeds
    the hollow-pass oracle; ``mechanism_rv_counts`` feeds accepted/rejected mechanism state.
    No-op when the environment variable is absent.
    """
    path = os.environ.get("_P11CHECK_SUBPROCESS_COVERAGE")
    if not path:
        return
    try:
        payload: dict[str, Any] = {
            "call_log": call_log,
            "mechanism_counts": mechanism_counts,
            "call_log_ok": call_log_ok or {},
            "mechanism_rv_counts": mechanism_rv_counts or {},
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
    except (OSError, TypeError, ValueError):
        pass


def emit_harness_error(exc: BaseException, *, phase: str) -> None:
    """Print the HARNESS_ERROR: marker so the parent blames us, not the module.

    ``phase`` names the harness-side step that broke (e.g. "mmap release"), so the
    report says which of our own operations failed rather than only the exception type.
    """
    try:
        print(f"{HARNESS_ERROR_MARKER}{phase}: {type(exc).__name__}: {exc}", flush=True)
    except (OSError, ValueError):
        pass


@contextmanager
def cleanup_guard(phase: str) -> Iterator[None]:
    """Run harness-side cleanup so a failure in it cannot destroy an emitted verdict.

    A probe prints its measurement and *then* releases its resources. Before this guard,
    an exception in that release exited the child non-zero and the parent recorded a
    ``crash`` finding against the module -- for a measurement the module had answered
    correctly (GH #11: ctypes.cast on a from_buffer array left an mmap export
    outstanding, so every close() raised BufferError).

    Module faults (OSError and friends) still propagate: those are findings.
    """
    try:
        yield
    except _MODULE_FAULT_EXCEPTIONS:
        raise
    except Exception as exc:  # noqa: BLE001 - reported via the marker, never silent
        emit_harness_error(exc, phase=phase)


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
