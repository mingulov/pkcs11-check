"""Subprocess safety tests - post-Finalize, fork, library reload.

These tests drive the module in a fresh subprocess (via the ``subprocess_safety`` probe) to
avoid corrupting the main test session. They exercise crash scenarios safely.

References: rep11.md Iteration 3, fork detection and exit crash bugs found in some modules.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

import pytest

from pkcs11_check.classification import (
    Classification,
    derive_verdict,
    fail_as,
    raise_for_record,
    record,
)
from pkcs11_check.raw.rv import ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed

pytestmark = [pytest.mark.security, pytest.mark.stress]

# os.fork() is POSIX-only. On Windows/Wine `os.fork` does not exist, so a fork-based
# probe raises AttributeError and exits 1 - which the isolated runner would otherwise
# record as a (false) module crash. Skip such tests where fork is absent; fork-safety is
# a POSIX concept, so no coverage is lost on platforms that cannot fork.
requires_fork = pytest.mark.skipif(
    not hasattr(os, "fork"),
    reason="os.fork() is POSIX-only; fork-safety is inapplicable on this platform",
)


def _run_probe(
    p11_config: Any,
    probe: str,
    *,
    timeout: int,
    with_pin: bool = False,
    with_slot: bool = False,
) -> tuple[int, str, str]:
    """Run a ``subprocess_safety`` probe; return ``(returncode, stdout, stderr)``.

    Keep the streams separate so Windows access-violation diagnostics and timeout markers
    remain available to the shared process-disposition classifier. Callers combine them only
    for protocol parsing and summaries. When ``with_pin`` is set the PIN travels ONLY
    via ``run_probe(pin=...)`` -> ``_P11CHECK_PIN`` env (Invariant I3); it is never embedded
    in the probe params or source. Coverage routes to the session accumulator; rv-trace is
    recorded by ``run_probe`` (I7).
    """
    params: dict[str, Any] = {"module_path": str(p11_config.module), "probe": probe}
    if with_slot:
        params["slot_id"] = p11_config.slot
    result = run_probe(
        "subprocess_safety",
        params,
        pin=pin_from_config(p11_config) if with_pin else None,
        timeout=timeout,
        coverage="session",
    )
    return result.returncode, result.stdout, result.stderr


def _assert_probe_completed(rc: int, stdout: str, stderr: str, *, context: str) -> bool:
    """Apply the shared process disposition before inspecting a probe protocol."""
    _termination, explicit_harness = assert_subprocess_completed(
        rc, stdout, stderr, context=context
    )
    if explicit_harness:
        return False
    output = f"{stdout}\n{stderr}"
    if not any(line == "OK" or line.startswith("OK:") for line in output.splitlines()):
        fail_as(
            "harness_error",
            label=context,
            summary=f"{context}: child emitted no complete OK marker (incomplete protocol)",
            detail={"probe_incomplete": True, "protocol": "missing_terminal_marker"},
        )
    return True


def _harness_record(context: str, summary: str, protocol: str) -> Classification:
    return Classification(
        reason="harness_error",
        outcome="fail",
        severity="HIGH",
        label=context,
        summary=summary,
        detail={"probe_incomplete": True, "protocol": protocol},
    )


def _provider_record(
    *,
    context: str,
    reason: str,
    kind: str | None,
    summary: str,
    operation: str | None = None,
    detail: dict[str, object] | None = None,
    actual_ckr: str | None = None,
    expected_ckr: list[str] | None = None,
) -> Classification:
    outcome, severity = derive_verdict(reason, kind)
    return Classification(
        reason=reason,
        outcome=outcome,
        severity=severity,
        kind=kind,
        label=context,
        operation=operation,
        summary=summary,
        detail=detail,
        actual_ckr=actual_ckr,
        expected_ckr=expected_ckr,
    )


def _provider_refusal_record(
    *,
    context: str,
    phase: str,
    rv: int,
    operation: str,
    marker: str,
    summary: str,
    child_exit: int | None = None,
) -> Classification:
    """Classify a non-success CK_RV, rejecting undefined values as contradictions."""
    defined = rv <= 0xFFFFFFFF and (is_standard_ckr(rv) or is_vendor_defined_ckr(rv))
    reason = "not_operational" if defined else "self_contradiction"
    kind = None if defined else "metadata"
    detail: dict[str, object] = {
        "protocol_marker": marker,
        "phase": phase,
        "actual_rv": f"0x{rv:08x}",
    }
    if child_exit is not None:
        detail["child_exit"] = child_exit
    if not defined:
        summary = f"{context}: undefined CK_RV reported by provider ({summary})"
    return _provider_record(
        context=context,
        reason=reason,
        kind=kind,
        operation=operation,
        summary=summary,
        detail=detail,
        actual_ckr=ckr_name(rv),
        expected_ckr=["CKR_OK"],
    )


@dataclass
class _ParsedSafetyProtocol:
    """Parsed safety-probe effects, kept separate from outer process disposition."""

    provider: list[Classification]
    harness: list[Classification]
    child_signal: int | None = None
    child_exit: int | None = None
    outcome: str | None = None
    phase: str | None = None
    expected_exit: int | None = None
    found: int | None = None
    setup_valid: bool = False
    label_count: int = 0


_FATAL_MARKER = re.compile(r"^(?P<phase>[A-Za-z][A-Za-z0-9]*):0x(?P<rv>[0-9a-f]{8,16})$")
_CKR_MARKER = re.compile(r"^0x[0-9a-f]{8,16}$")
_SLOT_RANGE_MARKER = re.compile(r"^(?P<slot>[0-9]+)>=(?P<count>[0-9]+)$")
_EXCEPTION_MARKER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*:.*$")
_SETUP_PHASES = {
    "Parent_Init": "C_Initialize",
    "Parent_GetSlotList": "C_GetSlotList",
    "Parent_Slot": "C_GetSlotList",
    "Parent_OpenSession": "C_OpenSession",
    "Parent_Login": "C_Login",
    "Parent_CreateObject": "C_CreateObject",
}
_FORK_SETUP_PHASES = {"Parent_Init": "C_Initialize"}
_SETUP_EXCEPTION_PHASES = {"Parent_Slot"}

# Exit values are part of the child protocol.  A refusal marker is only provider
# evidence when it is paired with the exit value emitted by that phase.
_FORK_REFUSAL_EXITS = {"Init": 2, "Slot": 7}
_SESSION_REFUSAL_EXITS = {
    "Init": 2,
    "FindInit": 3,
    "Find": 4,
    "Login": 6,
    "Slot": 7,
    "Open": 8,
    "FindFinal": 9,
}
_FORK_EXCEPTION_EXIT = 1
_SESSION_EXCEPTION_EXIT = 5
_PROTOCOL_PREFIXES = (
    "SETUP_XFAIL:",
    "SETUP_EXC:",
    "PARENT_LABEL:",
    "CHILD_FATAL:",
    "CHILD_EXC:",
    "CHILD_FOUND:",
    "CHILD_SIGNAL:",
    "CHILD_EXIT:",
)
_FORK_MARKER_ORDERS = (
    ("SETUP_XFAIL",),
    ("CHILD_FATAL", "CHILD_EXIT"),
    ("CHILD_EXC", "CHILD_EXIT"),
    ("CHILD_SIGNAL",),
    ("CHILD_EXIT",),
)
_SESSION_MARKER_ORDERS = (
    ("SETUP_XFAIL",),
    ("SETUP_EXC",),
    ("PARENT_LABEL", "CHILD_FATAL", "CHILD_EXIT"),
    ("PARENT_LABEL", "CHILD_EXC", "CHILD_EXIT"),
    ("PARENT_LABEL", "CHILD_FOUND", "CHILD_EXIT"),
    ("PARENT_LABEL", "CHILD_SIGNAL"),
    ("PARENT_LABEL", "CHILD_FOUND", "CHILD_SIGNAL"),
    ("PARENT_LABEL", "CHILD_FOUND", "CHILD_EXC", "CHILD_EXIT"),
)


def _protocol_error(context: str, summary: str, protocol: str) -> Classification:
    return _harness_record(context, summary, protocol)


def _parse_status_marker(
    lines: list[str],
    *,
    prefix: str,
    context: str,
    kind: str,
) -> tuple[int | None, list[Classification]]:
    """Parse one numeric marker, rejecting duplicate/malformed values."""
    errors: list[Classification] = []
    if len(lines) > 1:
        errors.append(
            _protocol_error(
                context,
                f"{context}: duplicate child {kind} markers (incomplete protocol)",
                f"duplicate_child_{kind}",
            )
        )
        return None, errors
    if not lines:
        return None, errors
    try:
        text = lines[0].removeprefix(prefix)
        value = _parse_decimal_marker(text)
        if value is None:
            raise ValueError
        if value < 0 or (kind == "signal" and value == 0) or value > 255:
            raise ValueError
    except ValueError:
        errors.append(
            _protocol_error(
                context,
                f"{context}: malformed child {kind} marker (incomplete protocol)",
                f"malformed_child_{kind}",
            )
        )
        return None, errors
    return value, errors


def _parse_decimal_marker(text: str) -> int | None:
    """Parse producer-rendered decimal text without accepting alternate spellings."""
    if re.fullmatch(r"[0-9]+", text) is None:
        return None
    try:
        value = int(text)
    except ValueError:
        # Python limits decimal conversion length.  Oversized child output is
        # malformed protocol evidence, never grounds to bypass outer crash or
        # timeout classification with an uncaught parser exception.
        return None
    return value if text == str(value) else None


def _parse_ckr_marker(detail: str) -> int | None:
    """Parse a canonical non-success CK_RV marker emitted by the producer."""
    if _CKR_MARKER.fullmatch(detail) is None:
        return None
    value = int(detail, 16)
    if value == 0 or detail != f"0x{value:08x}":
        return None
    return value


def _valid_slot_range(detail: str) -> bool:
    """Return whether a parent slot range represents an actual out-of-range index."""
    match = _SLOT_RANGE_MARKER.fullmatch(detail)
    if match is None:
        return False
    slot = _parse_decimal_marker(match.group("slot"))
    count = _parse_decimal_marker(match.group("count"))
    if slot is None or count is None:
        return False
    return slot >= count


def _marker_order(lines: list[str]) -> list[str]:
    """Return protocol marker kinds in their producer-emitted order."""
    order: list[str] = []
    for line in lines:
        for prefix in _PROTOCOL_PREFIXES:
            if line.startswith(prefix):
                order.append(prefix.removesuffix(":"))
                break
    return order


def _is_order_prefix(order: list[str], valid_orders: tuple[tuple[str, ...], ...]) -> bool:
    """Accept complete producer orders and prefixes awaiting deferred fields."""
    return any(candidate[: len(order)] == tuple(order) for candidate in valid_orders)


def _parse_fork_status(stdout: str, *, context: str) -> _ParsedSafetyProtocol:
    """Parse the fork probe's exhaustive parent/child state table."""
    result = _ParsedSafetyProtocol(provider=[], harness=[])
    lines = stdout.splitlines()
    setup_lines = [line for line in lines if line.startswith("SETUP_XFAIL:")]
    setup_exc_lines = [line for line in lines if line.startswith("SETUP_EXC:")]
    fatal_lines = [line for line in lines if line.startswith("CHILD_FATAL:")]
    exception_lines = [line for line in lines if line.startswith("CHILD_EXC:")]
    found_lines = [line for line in lines if line.startswith("CHILD_FOUND:")]
    signal_lines = [line for line in lines if line.startswith("CHILD_SIGNAL:")]
    exit_lines = [line for line in lines if line.startswith("CHILD_EXIT:")]

    setup_markers = setup_lines + setup_exc_lines
    if len(setup_markers) > 1:
        result.harness.append(
            _protocol_error(
                context, f"{context}: duplicate setup refusal markers", "duplicate_setup"
            )
        )
    if len(setup_markers) == 1:
        if setup_exc_lines:
            result.harness.append(
                _protocol_error(
                    context,
                    f"{context}: setup exception marker is not valid for fork probe",
                    "fork_setup_exception",
                )
            )
            setup_payload = setup_exc_lines[0].removeprefix("SETUP_EXC:")
        else:
            setup_payload = setup_lines[0].removeprefix("SETUP_XFAIL:")
        payload = setup_payload
        setup_phase, _, detail = payload.partition(":")
        rv = None if setup_phase == "Parent_Slot" else _parse_ckr_marker(detail)
        if setup_phase not in _FORK_SETUP_PHASES or rv is None:
            result.harness.append(
                _protocol_error(context, f"{context}: malformed setup marker", "malformed_setup")
            )
        else:
            result.setup_valid = True
            result.provider.append(
                _provider_refusal_record(
                    context=context,
                    phase=setup_phase,
                    rv=rv,
                    operation=_FORK_SETUP_PHASES[setup_phase],
                    marker="SETUP_XFAIL",
                    summary=f"{context}: {payload}",
                )
            )

    # Fork has no object result marker. Seeing one is an impossible/mixed branch.
    nested_lines = fatal_lines + exception_lines + found_lines + signal_lines + exit_lines
    if setup_markers and nested_lines:
        result.harness.append(
            _protocol_error(
                context,
                f"{context}: parent setup refusal was mixed with child result markers",
                "setup_with_nested_result",
            )
        )
        result.provider.clear()
        result.setup_valid = False

    if (
        not setup_markers
        and sum(bool(group) for group in (fatal_lines, exception_lines, found_lines, signal_lines))
        > 1
    ):
        result.harness.append(
            _protocol_error(
                context, f"{context}: conflicting child result markers", "conflicting_child_result"
            )
        )

    child_signal, errors = _parse_status_marker(
        signal_lines, prefix="CHILD_SIGNAL:", context=context, kind="signal"
    )
    result.harness.extend(errors)
    child_exit, errors = _parse_status_marker(
        exit_lines, prefix="CHILD_EXIT:", context=context, kind="exit"
    )
    result.harness.extend(errors)
    result.child_signal = child_signal
    result.child_exit = child_exit

    if signal_lines and exit_lines:
        result.harness.append(
            _protocol_error(
                context,
                f"{context}: child emitted both signal and exit status",
                "conflicting_child_status",
            )
        )
        result.child_signal = None
        result.child_exit = None

    if len(fatal_lines) == 1 and not (exception_lines or found_lines or signal_lines):
        payload = fatal_lines[0].removeprefix("CHILD_FATAL:")
        match = _FATAL_MARKER.fullmatch(payload)
        rv = _parse_ckr_marker(f"0x{match.group('rv')}") if match is not None else None
        if match is None or match.group("phase") not in _FORK_REFUSAL_EXITS or rv is None:
            result.harness.append(
                _protocol_error(
                    context,
                    f"{context}: malformed or unknown child refusal",
                    "malformed_child_fatal",
                )
            )
        else:
            result.outcome = "fatal"
            result.phase = match.group("phase")
            result.expected_exit = _FORK_REFUSAL_EXITS[result.phase]
            if result.child_exit == result.expected_exit and result.child_signal is None:
                result.provider.append(
                    _provider_refusal_record(
                        context=context,
                        phase=result.phase,
                        rv=rv,
                        operation={"Init": "C_Initialize", "Slot": "C_GetSlotList"}[result.phase],
                        marker="CHILD_FATAL",
                        summary=f"{context}: child refused {payload}",
                        child_exit=result.child_exit,
                    )
                )
            elif result.child_exit is not None:
                result.harness.append(
                    _protocol_error(
                        context,
                        f"{context}: child refusal {result.phase} had status {result.child_exit}, "
                        f"expected {result.expected_exit}",
                        "child_refusal_exit_pair",
                    )
                )

    if len(exception_lines) == 1 and not (fatal_lines or found_lines or signal_lines):
        result.outcome = "exception"
        result.expected_exit = _FORK_EXCEPTION_EXIT
        if result.child_exit is not None and result.child_exit != result.expected_exit:
            result.harness.append(
                _protocol_error(
                    context,
                    f"{context}: child exception had status {result.child_exit}, "
                    f"expected {result.expected_exit}",
                    "child_exception_exit_pair",
                )
            )
        elif result.child_exit == result.expected_exit:
            result.harness.append(
                _protocol_error(
                    context,
                    f"{context}: child reported an in-process exception: {exception_lines[0]}",
                    "child_exception",
                )
            )
        elif result.child_exit is None:
            # Missing status is deferred until normal outer completion.
            pass

    if len(fatal_lines) > 1:
        result.harness.append(
            _protocol_error(
                context, f"{context}: duplicate child refusal markers", "duplicate_child_fatal"
            )
        )
    if len(exception_lines) > 1:
        result.harness.append(
            _protocol_error(
                context,
                f"{context}: duplicate child exception markers",
                "duplicate_child_exception",
            )
        )

    if found_lines:
        result.harness.append(
            _protocol_error(
                context, f"{context}: CHILD_FOUND is not valid for fork probe", "fork_child_found"
            )
        )

    if result.child_signal is not None and not setup_markers:
        if fatal_lines or exception_lines or found_lines or result.child_exit is not None:
            result.harness.append(
                _protocol_error(
                    context,
                    f"{context}: conflicting child signal result",
                    "conflicting_child_result",
                )
            )
            result.child_signal = None
        else:
            result.outcome = "signal"

    if (
        result.child_exit is not None
        and result.child_exit != 0
        and result.outcome is None
        and not (fatal_lines or exception_lines or found_lines or signal_lines)
    ):
        result.harness.append(
            _protocol_error(
                context,
                f"{context}: child exited with status {result.child_exit} without a result marker "
                "(incomplete protocol)",
                "child_exit_failure",
            )
        )

    marker_order = _marker_order(lines)
    if (
        not result.harness
        and marker_order
        and not _is_order_prefix(marker_order, _FORK_MARKER_ORDERS)
    ):
        result.harness.append(
            _protocol_error(
                context,
                f"{context}: protocol markers were emitted out of order (incomplete protocol)",
                "marker_order",
            )
        )

    if result.provider and result.harness:
        result.provider.clear()
        result.setup_valid = False
    if result.setup_valid and result.provider and result.outcome is not None:
        result.provider.clear()
        result.setup_valid = False
    for item in result.provider:
        record(item)
    return result


def _parse_isolation_protocol(
    stdout: str,
    *,
    context: str,
) -> _ParsedSafetyProtocol:
    """Parse session-isolation effects; process termination is handled by the caller."""
    result = _ParsedSafetyProtocol(provider=[], harness=[])
    lines = stdout.splitlines()
    setup_lines = [line for line in lines if line.startswith("SETUP_XFAIL:")]
    setup_exc_lines = [line for line in lines if line.startswith("SETUP_EXC:")]
    fatal_lines = [line for line in lines if line.startswith("CHILD_FATAL:")]
    exception_lines = [line for line in lines if line.startswith("CHILD_EXC:")]
    label_lines = [line for line in lines if line.startswith("PARENT_LABEL:")]
    found_lines = [line for line in lines if line.startswith("CHILD_FOUND:")]
    signal_lines = [line for line in lines if line.startswith("CHILD_SIGNAL:")]
    exit_lines = [line for line in lines if line.startswith("CHILD_EXIT:")]
    marker_order = _marker_order(lines)
    order_valid = _is_order_prefix(marker_order, _SESSION_MARKER_ORDERS)

    result.label_count = len(label_lines)
    label_payload = label_lines[0].removeprefix("PARENT_LABEL:") if len(label_lines) == 1 else ""
    label_valid = bool(label_payload) and label_payload == label_payload.strip()
    setup_markers = setup_lines + setup_exc_lines
    if len(setup_markers) > 1:
        result.harness.append(
            _protocol_error(
                context, f"{context}: duplicate setup refusal markers", "duplicate_setup"
            )
        )
    if len(setup_markers) == 1:
        if setup_exc_lines:
            payload = setup_exc_lines[0].removeprefix("SETUP_EXC:")
            setup_phase, _, detail = payload.partition(":")
            if setup_phase not in _SETUP_EXCEPTION_PHASES or not _valid_slot_range(detail):
                result.harness.append(
                    _protocol_error(
                        context,
                        f"{context}: malformed setup exception marker",
                        "malformed_setup_exception",
                    )
                )
            else:
                result.harness.append(
                    _protocol_error(
                        context,
                        f"{context}: slot configuration is out of range ({payload})",
                        "setup_slot_range",
                    )
                )
        else:
            payload = setup_lines[0].removeprefix("SETUP_XFAIL:")
            setup_phase, _, detail = payload.partition(":")
            rv = None if setup_phase == "Parent_Slot" else _parse_ckr_marker(detail)
            if setup_phase not in _SETUP_PHASES or rv is None:
                result.harness.append(
                    _protocol_error(
                        context, f"{context}: malformed setup marker", "malformed_setup"
                    )
                )
            else:
                result.setup_valid = True
                result.provider.append(
                    _provider_refusal_record(
                        context=context,
                        phase=setup_phase,
                        rv=rv,
                        operation=_SETUP_PHASES[setup_phase],
                        marker="SETUP_XFAIL",
                        summary=(
                            f"{context}: session-object setup rejected ({payload})"
                            if setup_phase == "Parent_CreateObject"
                            else f"{context}: {payload}"
                        ),
                    )
                )

    # Setup refusal terminates before the fork. Any nested marker therefore makes
    # the complete branch ambiguous and suppresses provider attribution.
    nested_lines = (
        fatal_lines + exception_lines + label_lines + found_lines + signal_lines + exit_lines
    )
    if setup_markers and nested_lines:
        result.harness.append(
            _protocol_error(
                context,
                f"{context}: parent setup refusal was mixed with child result markers",
                "setup_with_nested_result",
            )
        )
        result.provider.clear()
        result.setup_valid = False

    child_signal, errors = _parse_status_marker(
        signal_lines, prefix="CHILD_SIGNAL:", context=context, kind="signal"
    )
    result.harness.extend(errors)
    child_exit, errors = _parse_status_marker(
        exit_lines, prefix="CHILD_EXIT:", context=context, kind="exit"
    )
    result.harness.extend(errors)
    result.child_signal = child_signal
    result.child_exit = child_exit
    if signal_lines and exit_lines:
        result.harness.append(
            _protocol_error(
                context,
                f"{context}: child emitted both signal and exit status",
                "conflicting_child_status",
            )
        )
        result.child_signal = None
        result.child_exit = None

    if len(label_lines) > 1:
        result.harness.append(
            _protocol_error(
                context, f"{context}: duplicate parent label markers", "duplicate_parent_label"
            )
        )
    elif label_lines and not label_valid:
        result.harness.append(
            _protocol_error(
                context, f"{context}: malformed parent label marker", "malformed_parent_label"
            )
        )

    outcome_groups = sum(
        bool(group) for group in (fatal_lines, exception_lines, found_lines, signal_lines)
    )
    found_signal_transition = (
        len(found_lines) == 1 and len(signal_lines) == 1 and not (fatal_lines or exception_lines)
    )
    found_exception_transition = (
        len(found_lines) == 1 and len(exception_lines) == 1 and not (fatal_lines or signal_lines)
    )
    if (
        not setup_markers
        and outcome_groups > 1
        and not (found_signal_transition or found_exception_transition)
    ):
        result.harness.append(
            _protocol_error(
                context, f"{context}: conflicting child result markers", "conflicting_child_result"
            )
        )

    if len(fatal_lines) > 1:
        result.harness.append(
            _protocol_error(
                context, f"{context}: duplicate child refusal markers", "duplicate_child_fatal"
            )
        )
    if len(exception_lines) > 1:
        result.harness.append(
            _protocol_error(
                context,
                f"{context}: duplicate child exception markers",
                "duplicate_child_exception",
            )
        )
    if len(found_lines) > 1:
        result.harness.append(
            _protocol_error(
                context, f"{context}: duplicate child-found markers", "duplicate_child_found"
            )
        )
    if len(exception_lines) == 1:
        exception_payload = exception_lines[0].removeprefix("CHILD_EXC:")
        malformed_exception = _EXCEPTION_MARKER.fullmatch(exception_payload) is None
        if exception_payload.startswith("SlotRange:"):
            malformed_exception = not _valid_slot_range(
                exception_payload.removeprefix("SlotRange:")
            )
        if malformed_exception:
            result.harness.append(
                _protocol_error(
                    context,
                    f"{context}: malformed child exception marker",
                    "malformed_child_exception",
                )
            )

    if len(fatal_lines) == 1 and outcome_groups == 1:
        payload = fatal_lines[0].removeprefix("CHILD_FATAL:")
        match = _FATAL_MARKER.fullmatch(payload)
        phase: str | None = match.group("phase") if match is not None else None
        rv = _parse_ckr_marker(f"0x{match.group('rv')}") if match is not None else None
        if match is None or phase not in _SESSION_REFUSAL_EXITS or rv is None:
            result.harness.append(
                _protocol_error(
                    context,
                    f"{context}: malformed or unknown child refusal",
                    "malformed_child_fatal",
                )
            )
        else:
            result.outcome = "fatal"
            result.phase = phase
            result.expected_exit = _SESSION_REFUSAL_EXITS[phase]
            if (
                result.child_exit == result.expected_exit
                and result.child_signal is None
                and result.label_count == 1
            ):
                result.provider.append(
                    _provider_refusal_record(
                        context=context,
                        phase=phase,
                        rv=rv,
                        operation={
                            "Init": "C_Initialize",
                            "Slot": "C_GetSlotList",
                            "Open": "C_OpenSession",
                            "Login": "C_Login",
                            "FindInit": "C_FindObjectsInit",
                            "Find": "C_FindObjects",
                            "FindFinal": "C_FindObjectsFinal",
                        }[phase],
                        marker="CHILD_FATAL",
                        summary=f"{context}: child refused {payload}",
                        child_exit=result.child_exit,
                    )
                )
            elif result.child_exit is not None:
                result.harness.append(
                    _protocol_error(
                        context,
                        f"{context}: child refusal {phase} had status {result.child_exit}, "
                        f"expected {result.expected_exit}",
                        "child_refusal_exit_pair",
                    )
                )

    if len(exception_lines) == 1 and (outcome_groups == 1 or found_exception_transition):
        result.outcome = "exception"
        result.expected_exit = _SESSION_EXCEPTION_EXIT
        if result.child_exit is not None and result.child_exit != result.expected_exit:
            result.harness.append(
                _protocol_error(
                    context,
                    f"{context}: child exception had status {result.child_exit}, "
                    f"expected {result.expected_exit}",
                    "child_exception_exit_pair",
                )
            )
        elif result.child_exit == result.expected_exit:
            if not any(
                item.detail is not None
                and item.detail.get("protocol") == "malformed_child_exception"
                for item in result.harness
            ):
                result.harness.append(
                    _protocol_error(
                        context,
                        f"{context}: child reported an in-process exception: {exception_lines[0]}",
                        "child_exception",
                    )
                )

    if len(found_lines) == 1 and (
        outcome_groups == 1 or found_signal_transition or found_exception_transition
    ):
        found = _parse_decimal_marker(found_lines[0].removeprefix("CHILD_FOUND:"))
        if found is None:
            result.harness.append(
                _protocol_error(
                    context, f"{context}: malformed child-found marker", "malformed_child_found"
                )
            )
        else:
            result.found = found
            result.outcome = "found"
            result.expected_exit = 0
            if found > 0 and label_valid and order_valid:
                result.provider.append(
                    _provider_record(
                        context=context,
                        reason="self_contradiction",
                        kind="policy",
                        operation="C_FindObjects",
                        summary=(
                            f"{context}: child found {found} parent session object(s), "
                            "violating process isolation"
                        ),
                        detail={"protocol_marker": "CHILD_FOUND", "found": found},
                    )
                )
            if (
                result.child_exit is not None
                and result.child_exit != 0
                and not found_exception_transition
            ):
                result.harness.append(
                    _protocol_error(
                        context,
                        f"{context}: child-found result had status {result.child_exit}, expected 0",
                        "child_found_exit_pair",
                    )
                )

    if (
        result.child_signal is not None
        and (outcome_groups == 1 or found_signal_transition)
        and not setup_markers
    ):
        if result.child_exit is not None:
            result.harness.append(
                _protocol_error(
                    context,
                    f"{context}: conflicting child signal result",
                    "conflicting_child_result",
                )
            )
            result.child_signal = None
        else:
            result.outcome = "signal"
    elif signal_lines and outcome_groups == 1 and result.child_signal is None and not setup_markers:
        # malformed signal was already recorded; keep it from becoming a crash.
        result.outcome = "signal"

    if (
        result.child_exit is not None
        and result.child_exit != 0
        and result.outcome is None
        and not (fatal_lines or exception_lines or found_lines or signal_lines)
    ):
        result.harness.append(
            _protocol_error(
                context,
                f"{context}: child exited with status {result.child_exit} without a result marker "
                "(incomplete protocol)",
                "child_exit_failure",
            )
        )

    if label_lines and not order_valid and (not result.harness or result.provider):
        result.harness.append(
            _protocol_error(
                context,
                f"{context}: protocol markers were emitted out of order (incomplete protocol)",
                "marker_order",
            )
        )

    # FOUND policy evidence remains valid when a later, order-valid cleanup marker
    # contributes an independent harness result.  Reversed/conflicting/duplicate
    # marker order, malformed FOUND text, and invalid parent labels do not qualify.
    found_policy_valid = (
        result.found is not None and result.found > 0 and label_valid and order_valid
    )
    if result.provider and (
        (result.harness and not found_policy_valid)
        or (not result.setup_valid and result.label_count != 1)
    ):
        result.provider.clear()
    for item in result.provider:
        record(item)
    return result


class TestPostFinalize:
    """Test behavior after C_Finalize - must not crash (task 7.3)."""

    def test_post_finalize_get_slot_list(self, p11_config: Any) -> None:
        """C_GetSlotList after C_Finalize must not crash."""
        rc, stdout, stderr = _run_probe(p11_config, "post_finalize_get_slot_list", timeout=30)
        _assert_probe_completed(rc, stdout, stderr, context="post-finalize C_GetSlotList")

    def test_reinitialize_after_finalize(self, p11_config: Any) -> None:
        """C_Initialize after C_Finalize must work."""
        rc, stdout, stderr = _run_probe(p11_config, "reinitialize_after_finalize", timeout=30)
        _assert_probe_completed(rc, stdout, stderr, context="reinitialize after C_Finalize")


class TestForkSafety:
    """Test fork behavior - child must not crash or deadlock (task 7.4)."""

    @requires_fork
    @pytest.mark.slow
    def test_fork_after_initialize(self, p11_config: Any) -> None:
        """Fork after C_Initialize - child reinitializes."""
        rc, stdout, stderr = _run_probe(p11_config, "fork_after_initialize", timeout=15)
        output = f"{stdout}\n{stderr}"
        context = "fork-after-initialize"
        parsed = _parse_fork_status(stdout, context=context)
        for error in parsed.harness:
            record(error)
        nested_crash: Classification | None = None
        if parsed.outcome == "signal" and parsed.child_signal is not None:
            nested_crash = _provider_record(
                context=context,
                reason="crash",
                kind=None,
                summary=(
                    f"Fork child was killed by signal {parsed.child_signal} "
                    f"(CHILD_SIGNAL): {output}"
                ),
                detail={"child_signal": parsed.child_signal},
            )
            record(nested_crash)

        _termination, explicit_harness = assert_subprocess_completed(
            rc,
            stdout,
            stderr,
            context="fork-after-initialize (incomplete protocol)",
        )
        if nested_crash is not None:
            raise_for_record(nested_crash)
            return
        if explicit_harness:
            return
        if parsed.harness:
            raise_for_record(parsed.harness[0])
        if parsed.provider:
            raise_for_record(parsed.provider[0])
        if parsed.outcome == "exception":
            error = _harness_record(
                context,
                f"{context}: child reported an in-process exception "
                f"(incomplete protocol): {output}",
                "child_exception",
            )
            record(error)
            raise_for_record(error)
        if parsed.outcome == "fatal":
            # A refusal marker with no exit is incomplete; the parser deliberately
            # deferred this check so a real outer crash is never relabeled.
            if parsed.child_exit is None:
                error = _harness_record(
                    context,
                    f"{context}: child refusal missing child status "
                    f"(incomplete protocol): {output}",
                    "missing_child_status",
                )
                record(error)
                raise_for_record(error)
        if parsed.child_exit is None:
            error = _harness_record(
                context,
                f"{context}: child missing child status (incomplete protocol): {output}",
                "missing_child_status",
            )
            record(error)
            raise_for_record(error)
        if parsed.child_exit != 0 and parsed.outcome is None:
            error = _harness_record(
                context,
                f"{context}: child exited with status {parsed.child_exit} without a result marker "
                f"(incomplete protocol): {output}",
                "child_exit_failure",
            )
            record(error)
            raise_for_record(error)


class TestSessionObjectProcessIsolation:
    """Cross-process session-object isolation.

    PKCS#11 v3.2 says session objects belong to a session, and
    sessions belong to an "application". An application is whatever
    called C_Initialize — distinct processes are distinct applications.
    Session objects MUST NOT be visible to a different process even if
    the underlying module backend is shared (e.g. a SQLite DB on disk,
    a dbus broker, or a daemon socket for daemon-backed modules).

    The existing same-process cross-session tests in
    test_object_visibility.py validate that two sessions in the SAME
    process see each other's session objects (spec-mandated). This
    test validates the complementary security boundary: a different
    process MUST NOT see them.
    """

    @requires_fork
    def test_session_object_not_visible_to_other_process(self, p11_config: Any) -> None:
        """Parent creates a session object; subprocess MUST NOT find it.

        Steps:
        1. Subprocess A opens a session, creates a session-scope (CKA_TOKEN=False)
           data object with a unique label, prints the label, sleeps until
           told to exit (so the session — and thus the object — stays alive).
           Actually we can't easily coordinate two long-lived subprocesses
           from a single pytest, so instead use a single subprocess that
           verifies the negative property internally:
           - Initialize, open session, create session object with label X,
             then within the SAME process (different session — visible) and
             via a fork+re-Initialize child (different application — not
             visible).
        2. Compare results.

        Skips when the module doesn't support fork-after-initialize cleanly. Those modules
        need additional setup that the subprocess test framework already
        documents.
        """
        # 90s timeout: daemon-backed modules may need cold-start headroom
        # for post-fork re-Initialize. Real-world fork+TPM2_Startup
        # can exceed 30s on busy systems.
        rc, stdout, stderr = _run_probe(
            p11_config,
            "session_object_isolation",
            timeout=90,
            with_pin=True,
            with_slot=True,
        )
        output = f"{stdout}\n{stderr}"
        context = "cross-process session-object isolation"
        parsed = _parse_isolation_protocol(stdout, context=context)
        for item in parsed.harness:
            record(item)

        if (
            parsed.outcome == "signal"
            and parsed.child_signal is not None
            and parsed.label_count == 0
        ):
            error = _harness_record(
                context,
                f"{context}: missing parent label (incomplete protocol)",
                "missing_parent_label",
            )
            record(error)

        nested_signal: Classification | None = None
        if parsed.outcome == "signal" and parsed.child_signal is not None:
            nested_signal = _provider_record(
                context=context,
                reason="crash",
                kind=None,
                summary=(
                    "SECURITY: child process was killed by signal "
                    f"{parsed.child_signal} during cross-process isolation:\n{output}"
                ),
                detail={"child_signal": parsed.child_signal},
            )
            record(nested_signal)

        _termination, explicit_harness = assert_subprocess_completed(
            rc, stdout, stderr, context=context
        )
        if nested_signal is not None:
            raise_for_record(nested_signal)
            return

        if explicit_harness:
            return
        if parsed.harness:
            raise_for_record(parsed.harness[0])
        if not parsed.setup_valid and parsed.label_count == 0:
            error = _harness_record(
                context,
                f"{context}: missing parent label (incomplete protocol)",
                "missing_parent_label",
            )
            record(error)
            raise_for_record(error)
        if parsed.setup_valid:
            if parsed.provider:
                raise_for_record(parsed.provider[0])
            return
        if parsed.outcome == "exception":
            if parsed.child_exit is None:
                error = _harness_record(
                    context,
                    f"{context}: child exception missing child status (incomplete protocol)",
                    "missing_child_status",
                )
                record(error)
                raise_for_record(error)
            return
        if parsed.outcome == "fatal":
            if parsed.child_exit is None:
                error = _harness_record(
                    context,
                    f"{context}: child refusal missing child status (incomplete protocol)",
                    "missing_child_status",
                )
                record(error)
                raise_for_record(error)
            if parsed.provider:
                raise_for_record(parsed.provider[0])
            return
        if parsed.outcome == "found" and parsed.found is not None:
            if parsed.child_exit is None:
                error = _harness_record(
                    context,
                    f"{context}: child-found result missing child status (incomplete protocol)",
                    "missing_child_status",
                )
                record(error)
                raise_for_record(error)
            if parsed.found > 0 and parsed.provider:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "Cross-process session object was visible after child re-initialization; "
                    "PKCS#11 v3.2 requires process/application isolation.",
                    ComplianceLevel.CRITICAL,
                    reference="PKCS#11 v3.2",
                )
                raise_for_record(parsed.provider[0])
            return
        if parsed.child_exit is None:
            error = _harness_record(
                context,
                f"{context}: child missing child status (incomplete protocol)",
                "missing_child_status",
            )
            record(error)
            raise_for_record(error)
        if parsed.child_exit != 0:
            error = _harness_record(
                context,
                f"{context}: child exited with status {parsed.child_exit} without a result marker "
                "(incomplete protocol)",
                "child_exit_failure",
            )
            record(error)
            raise_for_record(error)
        # CHILD_EXIT:0 without CHILD_FOUND:0 is not a success branch.
        error = _harness_record(
            context,
            f"{context}: child exit 0 lacked an exact CHILD_FOUND:0 result (incomplete protocol)",
            "missing_child_found",
        )
        record(error)
        raise_for_record(error)


class TestLibraryReload:
    """Test library reload cycle (task 7.15)."""

    def test_reload_cycle_5x(self, p11_config: Any) -> None:
        """Load -> init -> ops -> finalize, 5 times. No crash or leak.

        A crash exit code (a negative POSIX signal, or a positive Windows NTSTATUS
        such as 0xC0000005) is a module bug and kept as a crash failure.
        A clean positive exit code without an explicit harness marker is an
        incomplete probe protocol, not a provider crash. The shared process
        observer reports it as a harness error so an environment limitation
        cannot be mislabeled as a crash.
        """
        rc, stdout, stderr = _run_probe(p11_config, "reload_cycle_5x", timeout=30, with_pin=True)
        _assert_probe_completed(rc, stdout, stderr, context="library reload cycle (5x)")
