"""Tests for C_GetOperationState and C_SetOperationState.

Happy-path functional tests exercising state save/restore for active operations.
Error-path CKR tests are in ckr/test_ckr_state.py.

Source: PKCS#11 v3.2 (C_GetOperationState, C_SetOperationState).

Most PKCS#11 modules return CKR_STATE_UNSAVEABLE for active operations - this is
spec-conformant behaviour (Sec.5.6.5: the token may return CKR_STATE_UNSAVEABLE if the
state cannot be saved). Tests that require a saveable state skip gracefully when the
module does not support it.

The actual state save/restore round-trip uses a ctypes subprocess to call
C_DigestInit / C_DigestUpdate / C_GetOperationState / C_SetOperationState /
C_DigestFinal directly, because the python-pkcs11 high-level API does not expose
init/update/final as individually callable Python steps for digest.
"""

from __future__ import annotations

import hashlib
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
from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED, CKR_OK
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._raw_subprocess import parse_output as _parse_output
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed
from pkcs11_check.testcases.conftest import classify_negative_rv

pytestmark = pytest.mark.operation_state

_CROSS_SESSION_PART1 = b"cross-session data"
_CROSS_SESSION_PART2 = b"cross-session continuation"
_SAME_SESSION_PART1 = b"Hello, "
_SAME_SESSION_PART2 = b"PKCS#11 state!"
_CROSS_FOLLOWUP_OPERATIONS = ("DigestUpdate_cross", "DigestFinal_cross")
_STATE_FUNCTION_MARKERS = {
    "GetState_len": "C_GetOperationState",
    "GetState_data": "C_GetOperationState",
    "SetOperationState": "C_SetOperationState",
}


def _is_digest(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdefABCDEF" for char in value)


def _protocol_records(stdout: str, context: str) -> tuple[list[Classification], bool]:
    """Collect terminal provider markers without raising before process inspection."""
    records: list[Classification] = []
    malformed = False
    for line in stdout.splitlines():
        if line.startswith("SETUP_XFAIL:"):
            reason, kind, prefix = "not_operational", None, "SETUP_XFAIL:"
        elif line.startswith("BREAK:"):
            reason, kind, prefix = "self_contradiction", "crypto", "BREAK:"
        elif line.startswith("DEVIATION_XFAIL:"):
            reason, kind, prefix = "honest_deviation", None, "DEVIATION_XFAIL:"
        else:
            continue
        payload = line.removeprefix(prefix).strip()
        if not payload:
            malformed = True
            continue
        outcome, severity = derive_verdict(reason, kind)
        records.append(
            Classification(
                reason=reason,
                outcome=outcome,
                severity=severity,
                kind=kind,
                label=context,
                summary=f"{context}: {payload}",
                detail={"protocol_marker": prefix.removesuffix(":")},
            )
        )
    return records, malformed


def _ckr_measurements(stdout: str, context: str) -> tuple[list[Classification], bool, bool]:
    """Parse complete CKR markers, returning records, malformed status, and any marker."""
    records: list[Classification] = []
    malformed = False
    found = False
    for line in stdout.splitlines():
        if not line.startswith("CKR:"):
            continue
        # Accepted cross-session follow-ups are parsed by _cross_session_protocol.  They
        # are lifecycle evidence, not generic provider-operation measurements.
        if any(line.startswith(f"CKR:{operation}:") for operation in _CROSS_FOLLOWUP_OPERATIONS):
            continue
        found = True
        parts = line.split(":")
        if len(parts) != 3 or not parts[1].strip():
            malformed = True
            continue
        try:
            rv = int(parts[2].strip(), 0)
        except ValueError:
            malformed = True
            continue
        if rv == CKR_OK:
            continue
        if rv == CKR_FUNCTION_NOT_SUPPORTED and parts[1].strip() in _STATE_FUNCTION_MARKERS:
            # A callable operation-state function explicitly refusing support is a
            # capability skip, not a provider xfail.  Keep ``found`` true so the
            # caller can decide after process-disposition inspection.
            continue
        outcome, severity = derive_verdict("not_operational", "crypto")
        records.append(
            Classification(
                reason="not_operational",
                outcome=outcome,
                severity=severity,
                kind="crypto",
                label=context,
                operation=parts[1].strip(),
                actual_ckr=ckr_name(rv),
                summary=(
                    f"{context}: advertised operation {parts[1].strip()} is not operational; "
                    f"rejected with {ckr_name(rv)}"
                ),
                detail={"protocol_marker": "CKR", "operation": parts[1].strip()},
            )
        )
    return records, malformed, found


@dataclass(frozen=True)
class _CrossSessionProtocol:
    """Parsed cross-session result markers collected before process disposition."""

    accepted: str | None
    rejected: str | None
    reference: str | None
    restored: str | None
    followup_failures: tuple[tuple[str, str], ...]
    terminal_malformed: bool
    followup_malformed: bool
    malformed: bool


def _cross_session_protocol(stdout: str, *, partial: bool = False) -> _CrossSessionProtocol | None:
    """Parse cross-session markers without raising on malformed output.

    ``partial`` is enabled only by the cross-session caller so a child REFERENCE
    emitted before an early provider call is retained without making REFERENCE a
    cross-session marker in generic/same-session inspection.
    """
    prefixes = {
        "accepted": "CROSS_SESSION_ACCEPTED:",
        "rejected": "CROSS_SESSION_REJECTED:",
        "reference": "REFERENCE:",
        "restored": "RESTORED:",
    }
    values: dict[str, list[str]] = {name: [] for name in prefixes}
    followup_values: dict[str, list[str]] = {
        operation: [] for operation in _CROSS_FOLLOWUP_OPERATIONS
    }
    marker_order: list[str] = []
    for line in stdout.splitlines():
        found_marker = False
        for name, prefix in prefixes.items():
            if line.startswith(prefix):
                values[name].append(line.removeprefix(prefix).strip())
                marker_order.append(name)
                found_marker = True
                break
        if found_marker:
            continue
        for operation in _CROSS_FOLLOWUP_OPERATIONS:
            prefix = f"CKR:{operation}:"
            if line.startswith(prefix):
                followup_values[operation].append(line.removeprefix(prefix).strip())
                marker_order.append(f"followup:{operation}")
                break

    has_terminal_or_followup = (
        bool(values["accepted"]) or bool(values["rejected"]) or any(followup_values.values())
    )
    if not has_terminal_or_followup and not values["reference"]:
        if not partial or not any(
            line == "OK" or line.startswith(("CKR:", "BREAK:", "DEVIATION_XFAIL:"))
            for line in stdout.splitlines()
        ):
            return None
        # In explicit cross context, a provider marker without the child's
        # mandatory REFERENCE is incomplete harness output.  Return a malformed
        # protocol so generic provider measurements can still be retained.
        return _CrossSessionProtocol(
            accepted=None,
            rejected=None,
            reference=None,
            restored=None,
            followup_failures=(),
            terminal_malformed=False,
            followup_malformed=False,
            malformed=True,
        )

    malformed = any(len(items) > 1 for items in values.values())
    terminal_malformed = any(len(values[name]) > 1 for name in ("accepted", "rejected"))

    def _one(name: str) -> str | None:
        items = values[name]
        if len(items) != 1:
            return None
        if name in {"reference", "restored"} and not _is_digest(items[0]):
            return None
        return items[0]

    accepted = _one("accepted")
    rejected = _one("rejected")
    reference = _one("reference")
    restored = _one("restored")
    if accepted is not None and accepted != "1":
        malformed = True
        terminal_malformed = True
    if accepted is not None and rejected is not None:
        malformed = True
        terminal_malformed = True
    if rejected is not None:
        try:
            int(rejected, 0)
        except ValueError:
            malformed = True
            terminal_malformed = True

    # The producer always emits REFERENCE before its terminal accepted/rejected
    # marker.  Keep a unique terminal result attributable even when an adjacent
    # REFERENCE is malformed or out of order; the caller emits the harness finding
    # separately and the provider result remains useful evidence.
    for terminal in ("accepted", "rejected"):
        if values[terminal]:
            if reference is None:
                malformed = True
            elif marker_order.index("reference") > marker_order.index(terminal):
                malformed = True
    if rejected is not None and restored is not None:
        malformed = True

    for name in ("reference", "restored"):
        if any(not _is_digest(value) for value in values[name]):
            malformed = True

    followup_failures: list[tuple[str, str]] = []
    followup_malformed = False
    followup_count = sum(len(items) for items in followup_values.values())
    for operation, items in followup_values.items():
        if len(items) > 1:
            malformed = True
            followup_malformed = True
        for raw_rv in items:
            try:
                rv = int(raw_rv, 0)
            except ValueError:
                malformed = True
                followup_malformed = True
                continue
            if rv == CKR_OK:
                # The child prints a follow-up marker only after a nonzero CK_RV.
                malformed = True
                followup_malformed = True
            else:
                followup_failures.append((operation, raw_rv))

    # The child returns immediately after either follow-up failure, so exactly one
    # nonzero follow-up marker is the only valid accepted-path failure protocol.
    # Likewise, a follow-up marker without an accepted restore, or alongside a
    # RESTORED value, is not provider follow-up evidence.
    if followup_count != 0 and followup_count != 1:
        malformed = True
        followup_malformed = True
    if any(followup_values.values()):
        # A follow-up is meaningful only for the one producer path that emits a
        # valid REFERENCE, then exactly one accepted marker, then one nonzero CK_RV.
        # In particular, do not turn an ambiguous child reference into a provider
        # lifecycle contradiction.
        reference_index = (
            marker_order.index("reference") if reference in values["reference"] else -1
        )
        accepted_index = marker_order.index("accepted") if accepted in values["accepted"] else -1
        followup_index = min(
            marker_order.index(f"followup:{operation}")
            for operation, items in followup_values.items()
            if items
        )
        if (
            len(values["reference"]) != 1
            or reference is None
            or len(values["accepted"]) != 1
            or accepted != "1"
            or reference_index < 0
            or accepted_index < 0
            or reference_index >= accepted_index
            or accepted_index >= followup_index
        ):
            malformed = True
            followup_malformed = True
    if any(followup_values.values()) and restored is not None:
        malformed = True
        followup_malformed = True

    if accepted == "1" and followup_count == 0:
        if reference is None or restored is None:
            malformed = True
    return _CrossSessionProtocol(
        accepted=accepted,
        rejected=rejected,
        reference=reference,
        restored=restored,
        followup_failures=tuple(followup_failures),
        terminal_malformed=terminal_malformed,
        followup_malformed=followup_malformed,
        malformed=malformed,
    )


@dataclass(frozen=True)
class _SameSessionProtocol:
    """Parsed same-session digest result markers."""

    reference: str | None
    restored: str | None
    singleshot: str | None
    singleshot_ok: str | None
    singleshot_ok_count: int
    malformed: bool


def _same_session_protocol(stdout: str) -> _SameSessionProtocol:
    """Parse same-session result fields and reject duplicate/malformed protocol."""
    prefixes = {
        "reference": "REFERENCE:",
        "restored": "RESTORED:",
        "singleshot": "SINGLESHOT:",
        "singleshot_ok": "SINGLESHOT_OK:",
    }
    values: dict[str, list[str]] = {name: [] for name in prefixes}
    marker_order: list[str] = []
    for line in stdout.splitlines():
        for name, prefix in prefixes.items():
            if line.startswith(prefix):
                values[name].append(line.removeprefix(prefix).strip())
                marker_order.append(name)
                break

    malformed = any(len(items) > 1 for items in values.values())

    def _one(name: str) -> str | None:
        items = values[name]
        if len(items) != 1 or not _is_digest(items[0]):
            return None
        return items[0]

    reference = _one("reference")
    restored = _one("restored")
    singleshot = _one("singleshot")
    singleshot_ok = _one("singleshot_ok")
    for items in values.values():
        if any(not _is_digest(value) for value in items):
            malformed = True
    if any(values[name] for name in ("singleshot", "singleshot_ok")):
        if reference is None:
            malformed = True
        elif marker_order.index("reference") > min(
            marker_order.index(name)
            for name in ("singleshot", "singleshot_ok")
            if name in marker_order
        ):
            malformed = True
    if singleshot is not None and singleshot_ok is not None:
        malformed = True
    if singleshot is not None and restored is not None:
        malformed = True
    if singleshot_ok is not None and reference is None:
        malformed = True
    if restored is not None and len(values["singleshot_ok"]) != 1:
        malformed = True
    return _SameSessionProtocol(
        reference=reference,
        restored=restored,
        singleshot=singleshot,
        singleshot_ok=singleshot_ok,
        singleshot_ok_count=len(values["singleshot_ok"]),
        malformed=malformed,
    )


def _cross_session_records(
    protocol: _CrossSessionProtocol | None, context: str
) -> list[Classification]:
    """Build findings from valid cross-session result markers.

    REFERENCE is produced by the child harness, so a mismatch belongs to the
    harness.  RESTORED is provider output and remains a crypto finding.  Build
    both records in protocol order before the parent inspects process disposition.
    """
    if protocol is None or protocol.terminal_malformed:
        return []
    expected = hashlib.sha256(_CROSS_SESSION_PART1 + _CROSS_SESSION_PART2).hexdigest()
    records: list[Classification] = []

    def _reference_record() -> Classification | None:
        if protocol.reference is None or protocol.reference.lower() == expected:
            return None
        outcome, severity = derive_verdict("harness_error", None)
        return Classification(
            reason="harness_error",
            outcome=outcome,
            severity=severity,
            label=context,
            summary=(
                f"{context}: REFERENCE digest mismatch in child harness; "
                f"expected {expected}, got {protocol.reference}"
            ),
            detail={
                "protocol_marker": "REFERENCE",
                "expected_digest": expected,
                "actual_digest": protocol.reference,
            },
        )

    reference_record = _reference_record()
    if reference_record is not None:
        records.append(reference_record)

    if protocol.rejected is not None:
        rejected_code = int(protocol.rejected, 0)
        if rejected_code == CKR_FUNCTION_NOT_SUPPORTED:
            return records
        if rejected_code == CKR_OK:
            reason, kind = "self_contradiction", "lifecycle"
            summary = f"{context}: rejection marker returned CKR_OK"
        elif is_standard_ckr(rejected_code) or is_vendor_defined_ckr(rejected_code):
            reason, kind = "not_operational", "lifecycle"
            summary = (
                f"{context}: C_SetOperationState cross-session restore is not operational; "
                f"rejected with {ckr_name(rejected_code)}"
            )
        else:
            reason, kind = "self_contradiction", "metadata"
            summary = (
                f"{context}: C_SetOperationState cross-session restore returned undefined "
                f"CK_RV {ckr_name(rejected_code)}"
            )
        outcome, severity = derive_verdict(reason, kind)
        records.append(
            Classification(
                reason=reason,
                outcome=outcome,
                severity=severity,
                kind=kind,
                label=context,
                operation="C_SetOperationState",
                mechanism="CKM_SHA256",
                actual_ckr=ckr_name(rejected_code),
                summary=summary,
                detail={"protocol_marker": "CROSS_SESSION_REJECTED"},
            )
        )
        return records
    if protocol.accepted == "1" and protocol.followup_failures and not protocol.followup_malformed:
        operation, raw_rv = protocol.followup_failures[0]
        rv = int(raw_rv, 0)
        outcome, severity = derive_verdict("self_contradiction", "lifecycle")
        records.append(
            Classification(
                reason="self_contradiction",
                outcome=outcome,
                severity=severity,
                kind="lifecycle",
                label=context,
                operation="C_SetOperationState",
                mechanism="CKM_SHA256",
                actual_ckr=ckr_name(rv),
                summary=(
                    f"{context}: CROSS_SESSION_ACCEPTED:1 claimed restore success, "
                    f"but {operation} rejected with {ckr_name(rv)}"
                ),
                detail={
                    "protocol_marker": "CKR",
                    "operation": operation,
                    "claimed_acceptance": True,
                },
            )
        )
        return records

    if protocol.accepted == "1":
        # A malformed follow-up suppresses only the impossible follow-up finding;
        # an independently present RESTORED value remains provider evidence.
        if protocol.restored is not None and protocol.restored.lower() != expected:
            outcome, severity = derive_verdict("wrong_result", "crypto")
            records.append(
                Classification(
                    reason="wrong_result",
                    outcome=outcome,
                    severity=severity,
                    kind="crypto",
                    label=context,
                    operation="C_SetOperationState",
                    mechanism="CKM_SHA256",
                    summary=(
                        f"{context}: restored digest mismatch; expected {expected}, "
                        f"got {protocol.restored}"
                    ),
                    detail={
                        "protocol_marker": "RESTORED",
                        "expected_digest": expected,
                        "actual_digest": protocol.restored,
                    },
                )
            )
        return records
    # In explicit partial-cross mode, a unique valid REFERENCE may be the only
    # semantic marker before an early provider call.  Preserve its harness oracle
    # mismatch without inventing a cross-session lifecycle result.
    return records


def _same_session_records(protocol: _SameSessionProtocol, context: str) -> list[Classification]:
    """Build same-session harness/provider records against a parent-owned oracle."""
    expected = hashlib.sha256(_SAME_SESSION_PART1 + _SAME_SESSION_PART2).hexdigest()
    records: list[Classification] = []
    if protocol.reference is not None and protocol.reference.lower() != expected:
        outcome, severity = derive_verdict("harness_error", None)
        records.append(
            Classification(
                reason="harness_error",
                outcome=outcome,
                severity=severity,
                label=context,
                summary=(
                    f"{context}: REFERENCE digest mismatch in child harness; "
                    f"expected {expected}, got {protocol.reference}"
                ),
                detail={
                    "protocol_marker": "REFERENCE",
                    "expected_digest": expected,
                    "actual_digest": protocol.reference,
                },
            )
        )
    if protocol.singleshot_ok is not None and protocol.singleshot_ok.lower() != expected:
        outcome, severity = derive_verdict("wrong_result", "crypto")
        records.append(
            Classification(
                reason="wrong_result",
                outcome=outcome,
                severity=severity,
                kind="crypto",
                label=context,
                operation="C_DigestFinal",
                mechanism="CKM_SHA256",
                summary=(
                    f"{context}: SINGLESHOT_OK digest mismatch; expected {expected}, "
                    f"got {protocol.singleshot_ok}"
                ),
                detail={
                    "protocol_marker": "SINGLESHOT_OK",
                    "expected_digest": expected,
                    "actual_digest": protocol.singleshot_ok,
                },
            )
        )
    if protocol.singleshot is not None and protocol.singleshot.lower() != expected:
        outcome, severity = derive_verdict("wrong_result", "crypto")
        records.append(
            Classification(
                reason="wrong_result",
                outcome=outcome,
                severity=severity,
                kind="crypto",
                label=context,
                operation="C_DigestFinal",
                mechanism="CKM_SHA256",
                summary=(
                    f"{context}: SINGLESHOT digest mismatch; expected {expected}, "
                    f"got {protocol.singleshot}"
                ),
                detail={
                    "protocol_marker": "SINGLESHOT",
                    "expected_digest": expected,
                    "actual_digest": protocol.singleshot,
                },
            )
        )
    elif protocol.singleshot is not None:
        outcome, severity = derive_verdict("harness_error", None)
        records.append(
            Classification(
                reason="harness_error",
                outcome=outcome,
                severity=severity,
                label=context,
                summary=(
                    f"{context}: SINGLESHOT marker was emitted for a correct digest; "
                    "the child emits SINGLESHOT only for a provider mismatch"
                ),
                detail={
                    "protocol_marker": "SINGLESHOT",
                    "expected_digest": expected,
                    "actual_digest": protocol.singleshot,
                    "probe_incomplete": True,
                },
            )
        )
    if protocol.restored is not None and protocol.restored.lower() != expected:
        outcome, severity = derive_verdict("wrong_result", "crypto")
        records.append(
            Classification(
                reason="wrong_result",
                outcome=outcome,
                severity=severity,
                kind="crypto",
                label=context,
                operation="C_SetOperationState",
                mechanism="CKM_SHA256",
                summary=(
                    f"{context}: RESTORED digest mismatch; expected {expected}, "
                    f"got {protocol.restored}"
                ),
                detail={
                    "protocol_marker": "RESTORED",
                    "expected_digest": expected,
                    "actual_digest": protocol.restored,
                },
            )
        )
    return records


def _inspect_probe(
    returncode: int,
    stdout: str,
    stderr: str,
    *,
    context: str,
    protocol_records: list[Classification] | None = None,
    protocol_malformed: bool = False,
    cross_protocol: _CrossSessionProtocol | None = None,
) -> tuple[list[Classification], list[Classification], bool, bool]:
    """Record provider markers, then apply shared process disposition."""
    semantic, malformed_semantic = _protocol_records(stdout, context)
    measurements, malformed_ckr, has_ckr = _ckr_measurements(stdout, context)
    if protocol_records:
        semantic.extend(protocol_records)
    if cross_protocol is not None:
        semantic.extend(_cross_session_records(cross_protocol, context))
    malformed = (
        malformed_semantic
        or malformed_ckr
        or protocol_malformed
        or (cross_protocol is not None and cross_protocol.malformed)
    )
    malformed_record: Classification | None = None
    if malformed:
        # A malformed marker is a harness finding, but independently valid provider
        # observations remain trustworthy.  Emit the harness record first so a later
        # crash remains controlling without erasing sibling measurements.
        summary = (
            f"{context}: Malformed cross-session CKR result"
            if cross_protocol is not None
            and (cross_protocol.rejected is not None or any(cross_protocol.followup_failures))
            else (
                f"{context}: Malformed cross-session REFERENCE/RESTORED result"
                if cross_protocol is not None and cross_protocol.accepted == "1"
                else f"{context}: Malformed CKR or semantic protocol marker"
            )
        )
        outcome, severity = derive_verdict("harness_error", None)
        malformed_record = Classification(
            reason="harness_error",
            outcome=outcome,
            severity=severity,
            label=context,
            summary=summary,
            detail={"probe_incomplete": True, "protocol": "malformed_marker"},
        )
        record(malformed_record)
    for item in (*semantic, *measurements):
        record(item)
    _termination, explicit_harness = assert_subprocess_completed(
        returncode, stdout, stderr, context=context
    )
    if explicit_harness:
        return (
            semantic,
            measurements,
            malformed,
            has_ckr,
        )
    if malformed_record is not None:
        raise_for_record(malformed_record)
    return semantic, measurements, False, has_ckr


def _require_complete(
    stdout: str,
    *,
    context: str,
    semantic: list[Classification],
    measurements: list[Classification],
) -> None:
    """Require an OK/result protocol unless a terminal provider disposition exists."""
    if measurements or semantic:
        return
    if any(line == "OK" or line.startswith("OK:") for line in stdout.splitlines()):
        return
    fail_as(
        "harness_error",
        label=context,
        summary=f"{context}: child subprocess did not emit a complete result",
        detail={"probe_incomplete": True, "protocol": "missing_result"},
    )


def _raise_provider_disposition(
    semantic: list[Classification], measurements: list[Classification]
) -> None:
    """Raise the strongest already-recorded provider disposition, if any."""
    for item in (*measurements, *semantic):
        if item.outcome == "fail":
            raise_for_record(item)
    if measurements:
        raise_for_record(measurements[0])
    if semantic:
        raise_for_record(semantic[0])


def _state_function_not_supported(stdout: str) -> str | None:
    """Return the operation-state function named by a valid FNS CKR marker."""
    for line in stdout.splitlines():
        if not line.startswith("CKR:"):
            continue
        parts = line.split(":")
        if len(parts) != 3:
            continue
        operation = parts[1].strip()
        function_name = _STATE_FUNCTION_MARKERS.get(operation)
        if function_name is None:
            continue
        try:
            rv = int(parts[2].strip(), 0)
        except ValueError:
            continue
        if rv == CKR_FUNCTION_NOT_SUPPORTED:
            return function_name
    return None


def _cross_session_function_not_supported(
    protocol: _CrossSessionProtocol | None,
) -> bool:
    """Whether cross-session restore cleanly reported C_SetOperationState FNS."""
    if protocol is None or protocol.rejected is None:
        return False
    return int(protocol.rejected, 0) == CKR_FUNCTION_NOT_SUPPORTED


# ---------------------------------------------------------------------------
# Tests: high-level API availability
# ---------------------------------------------------------------------------


class TestGetOperationStateAPI:
    """Verify C_GetOperationState / C_SetOperationState are present and respond correctly."""

    def test_api_exists(self, p11_raw_session: Any) -> None:
        """Raw session exposes C_GetOperationState and C_SetOperationState."""
        rs = p11_raw_session
        available_fn = getattr(rs.raw, "available_function_names", None)
        if callable(available_fn):
            available = set(available_fn())
            if not available.intersection({"C_GetOperationState", "C_SetOperationState"}):
                pytest.skip("C_GetOperationState and C_SetOperationState are not available")
            if "C_GetOperationState" in available:
                assert hasattr(rs.raw, "C_GetOperationState")
            if "C_SetOperationState" in available:
                assert hasattr(rs.raw, "C_SetOperationState")
            return
        assert hasattr(rs.raw, "C_GetOperationState") or hasattr(rs.raw, "C_SetOperationState")

    def test_no_active_operation(self, p11_raw_session: Any) -> None:
        """C_GetOperationState with no active operation returns known CKR.

        Spec Sec.5.6.5: if no operation is active the token must return
        CKR_OPERATION_NOT_INITIALIZED. Some modules also return
        CKR_STATE_UNSAVEABLE or CKR_FUNCTION_NOT_SUPPORTED.
        """
        import ctypes

        from pkcs11_check.raw.types_std import (
            CKR_FUNCTION_NOT_SUPPORTED,
            CKR_OPERATION_NOT_INITIALIZED,
            CKR_STATE_UNSAVEABLE,
        )

        rs = p11_raw_session
        _skip_missing_functions(rs, ("C_GetOperationState",))
        state_len = ctypes.c_ulong(0)
        rv = rs.raw.C_GetOperationState(rs.sh, None, ctypes.byref(state_len))
        if rv == CKR_FUNCTION_NOT_SUPPORTED:
            pytest.skip("C_GetOperationState is not supported")
        classify_negative_rv(
            rv,
            (CKR_OPERATION_NOT_INITIALIZED, CKR_STATE_UNSAVEABLE, CKR_FUNCTION_NOT_SUPPORTED),
            label="C_GetOperationState:no active operation",
            allow_ok=True,
        )

    def test_garbage_state_raises_saved_state_invalid(
        self,
        p11_raw_session: Any,
    ) -> None:
        """C_SetOperationState with garbage -> CKR_SAVED_STATE_INVALID.

        Spec Sec.5.6.6: the token must return CKR_SAVED_STATE_INVALID if
        the supplied state blob is unrecognisable.
        """
        import ctypes

        from pkcs11_check.raw.types_std import (
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_NOT_SUPPORTED,
            CKR_SAVED_STATE_INVALID,
            CKR_STATE_UNSAVEABLE,
        )

        rs = p11_raw_session
        _skip_missing_functions(rs, ("C_SetOperationState",))
        garbage = b"\xde\xad\xbe\xef" * 16
        buf = (ctypes.c_ubyte * len(garbage))(*garbage)
        rv = rs.raw.C_SetOperationState(rs.sh, buf, len(garbage), 0, 0)
        if rv in (
            CKR_FUNCTION_NOT_SUPPORTED,
            CKR_STATE_UNSAVEABLE,
        ):
            pytest.skip("Module does not support C_SetOperationState")
        if rv == CKR_ARGUMENTS_BAD:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "C_SetOperationState rejected a garbage state blob with "
                "CKR_ARGUMENTS_BAD instead of the more specific "
                "CKR_SAVED_STATE_INVALID",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 v3.2 C_SetOperationState return values",
            )
        # 3-way: accepting a garbage state blob (CKR_OK) -> fail; the spec code
        # CKR_SAVED_STATE_INVALID -> pass; another clean reject (e.g.
        # CKR_OPERATION_NOT_INITIALIZED, CKR_ARGUMENTS_BAD) -> xfail.
        classify_negative_rv(
            rv,
            (CKR_SAVED_STATE_INVALID,),
            label="C_SetOperationState with a garbage state blob (PKCS#11 v3.2)",
        )


# ---------------------------------------------------------------------------
# Tests: digest state round-trip via ctypes subprocess
# ---------------------------------------------------------------------------


def _skip_missing_mechanisms(rs: Any, names: tuple[str, ...]) -> None:
    for name in names:
        if not rs.has_mechanism(name):
            pytest.skip(f"{name} not supported by module")


def _skip_missing_functions(rs: Any, names: tuple[str, ...]) -> None:
    """Gate raw function capabilities independently from mechanism support."""
    available_fn = getattr(rs.raw, "available_function_names", None)
    if not callable(available_fn):
        return
    available = set(available_fn())
    missing = [name for name in names if name not in available]
    if missing:
        pytest.skip(f"required PKCS#11 function(s) not available: {', '.join(missing)}")


@pytest.mark.usefixtures("p11_module")
class TestDigestStateRoundTrip:
    """State save/restore round-trip for a SHA-256 multi-part digest.

    The python-pkcs11 high-level digest API does not expose C_DigestInit /
    C_DigestUpdate / C_DigestFinal as individually callable Python steps, so
    these tests use a ctypes subprocess to exercise the C-level functions
    directly.  This also mirrors how real applications use state save/restore.
    """

    def test_digest_state_same_session(
        self,
        p11_config: Any,
        p11_raw_session: Any,
    ) -> None:
        """SHA-256 state save/restore on the same session produces the correct digest.

        Steps:
        1. Compute reference = SHA-256(part1 + part2) via hashlib.
        2. PKCS#11: DigestInit(SHA-256) -> DigestUpdate(part1) -> GetOperationState.
        3. SetOperationState (restore) -> DigestUpdate(part2) -> DigestFinal.
        4. Assert final digest equals reference.

        Skips when the module returns CKR_STATE_UNSAVEABLE (most software tokens
        and many hardware tokens do not support state save).
        """
        _skip_missing_mechanisms(p11_raw_session, ("SHA256",))
        _skip_missing_functions(
            p11_raw_session,
            (
                "C_DigestInit",
                "C_DigestUpdate",
                "C_DigestFinal",
                "C_GetOperationState",
                "C_SetOperationState",
            ),
        )

        result = run_probe(
            "operation_state",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "digest_same_session",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        returncode, stdout, stderr = result.returncode, result.stdout, result.stderr

        lines_map = _parse_output(stdout)
        same_protocol = _same_session_protocol(stdout)
        same_records = _same_session_records(same_protocol, "digest-state-roundtrip")
        semantic, measurements, _malformed, has_ckr = _inspect_probe(
            returncode,
            stdout,
            stderr,
            context="digest-state-roundtrip",
            protocol_records=same_records,
            protocol_malformed=same_protocol.malformed,
        )

        # A valid clean CKR is a complete advertised-operation refusal.  It is
        # intentionally raised only after process disposition so a later crash
        # cannot be hidden by an earlier setup measurement.
        if has_ckr and measurements:
            _raise_provider_disposition(semantic, measurements)
        if semantic:
            _raise_provider_disposition(semantic, measurements)
        state_function = _state_function_not_supported(stdout)
        if state_function is not None:
            pytest.skip(f"{state_function} is not supported")
        if "SKIP" in lines_map:
            pytest.skip(f"Module skipped state test: {lines_map['SKIP']}")
        if same_protocol.singleshot is not None:
            if same_protocol.reference is None:
                fail_as(
                    "harness_error",
                    label="digest-state-roundtrip",
                    summary=f"Missing REFERENCE in output: {stdout!r}",
                    detail={"probe_incomplete": True, "protocol": "missing_result"},
                )
            return
        if same_protocol.restored is not None and same_protocol.singleshot_ok_count == 0:
            fail_as(
                "harness_error",
                label="digest-state-roundtrip",
                summary=(
                    "digest-state-roundtrip: Malformed result; restored digest "
                    "is missing SINGLESHOT_OK"
                ),
                detail={"probe_incomplete": True, "protocol": "missing_singleshot_ok"},
            )
        _require_complete(
            stdout,
            context="digest-state-roundtrip",
            semantic=semantic,
            measurements=measurements,
        )

        if same_protocol.reference is None:
            fail_as(
                "harness_error",
                label="digest-state-roundtrip",
                summary=f"Missing REFERENCE in output: {stdout!r}",
                detail={"probe_incomplete": True, "protocol": "missing_result"},
            )
        if same_protocol.restored is None:
            fail_as(
                "harness_error",
                label="digest-state-roundtrip",
                summary=f"Missing RESTORED in output: {stdout!r}",
                detail={"probe_incomplete": True, "protocol": "missing_result"},
            )

        # The parent-owned oracle and _same_session_records() above already checked all
        # child fields.  Do not compare provider RESTORED to child REFERENCE.

    def test_digest_state_cross_session(
        self, p11_config: Any, p11_raw_session: Any | None = None
    ) -> None:
        """Restore digest state on a second same-token session when supported.

        Cross-session restore is a positive common-state capability probe.  A
        clean provider refusal is recorded as not operational, while accepted
        state must continue through DigestUpdate and DigestFinal and match the
        independent SHA-256 reference.

        Skips when the module returns CKR_STATE_UNSAVEABLE at the save step.
        """
        if p11_raw_session is not None:
            _skip_missing_mechanisms(p11_raw_session, ("SHA256",))
            _skip_missing_functions(
                p11_raw_session,
                (
                    "C_DigestInit",
                    "C_DigestUpdate",
                    "C_GetOperationState",
                    "C_SetOperationState",
                    "C_DigestFinal",
                    "C_OpenSession",
                ),
            )
        result = run_probe(
            "operation_state",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "digest_cross_session",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        returncode, stdout, stderr = result.returncode, result.stdout, result.stderr

        lines_map = _parse_output(stdout)
        cross_protocol = _cross_session_protocol(stdout, partial=True)
        semantic, measurements, _malformed, has_ckr = _inspect_probe(
            returncode,
            stdout,
            stderr,
            context="cross-session-state",
            cross_protocol=cross_protocol,
        )
        if has_ckr and measurements:
            _raise_provider_disposition(semantic, measurements)
        if semantic:
            _raise_provider_disposition(semantic, measurements)
        if _cross_session_function_not_supported(cross_protocol):
            pytest.skip("C_SetOperationState is not supported")
        # _cross_session_function_not_supported only inspects CROSS_SESSION_REJECTED:,
        # i.e. C_SetOperationState. A module that declines C_GetOperationState never
        # reaches that marker at all, so without this the FNS fell through to the
        # missing-result branch below and was reported as a HIGH failure. Function-level
        # capability absence is a skip -- the same guard the same-session tests use.
        state_function = _state_function_not_supported(stdout)
        if state_function is not None:
            pytest.skip(f"{state_function} is not supported")
        if "SKIP" in lines_map:
            pytest.skip(f"Module skipped cross-session test: {lines_map['SKIP']}")
        if cross_protocol is None:
            fail_as(
                "harness_error",
                label="cross-session-state",
                summary=f"Missing cross-session result in output: {stdout!r}",
                detail={"probe_incomplete": True, "protocol": "missing_result"},
            )
        if (
            cross_protocol.accepted is None
            and cross_protocol.rejected is None
            and not semantic
            and not measurements
        ):
            fail_as(
                "harness_error",
                label="cross-session-state",
                summary=(
                    "cross-session-state: child emitted REFERENCE without a terminal "
                    f"cross-session result or provider measurement: {stdout!r}"
                ),
                detail={"probe_incomplete": True, "protocol": "missing_result"},
            )


# ---------------------------------------------------------------------------
# Tests: encrypt state round-trip via ctypes subprocess
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("p11_module")
class TestEncryptStateRoundTrip:
    """State save/restore round-trip for an AES-CBC multi-part encrypt operation.

    The python-pkcs11 high-level encrypt API does not expose C_EncryptInit /
    C_EncryptUpdate / C_EncryptFinal as individually callable Python steps, so
    these tests use a ctypes subprocess to exercise the C-level functions
    directly.

    Most modules return CKR_STATE_UNSAVEABLE for active encrypt operations - the
    tests skip gracefully when the module does not support saving encrypt state.
    """

    def test_encrypt_state_same_session(
        self,
        p11_config: Any,
        p11_raw_session: Any,
    ) -> None:
        """AES-CBC state save/restore on the same session produces correct ciphertext.

        Steps:
        1. Generate an AES-256 key via C_GenerateKey.
        2. C_EncryptInit(AES-CBC, IV) -> C_EncryptUpdate(part1) -> C_GetOperationState.
        3. C_SetOperationState (restore, passing the key handle) -> C_EncryptUpdate(part2)
           -> C_EncryptFinal.
        4. Compare with a reference encryption that does not use state save/restore.

        Skips when the module returns CKR_STATE_UNSAVEABLE or
        CKR_FUNCTION_NOT_SUPPORTED (most software tokens do not save encrypt state).

        Source: PKCS#11 v3.2.
        """
        _skip_missing_mechanisms(p11_raw_session, ("AES_KEY_GEN", "AES_CBC"))
        _skip_missing_functions(
            p11_raw_session,
            (
                "C_GenerateKey",
                "C_EncryptInit",
                "C_EncryptUpdate",
                "C_EncryptFinal",
                "C_GetOperationState",
                "C_SetOperationState",
            ),
        )

        result = run_probe(
            "operation_state",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "encrypt_same_session",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        returncode, stdout, stderr = result.returncode, result.stdout, result.stderr

        lines_map = _parse_output(stdout)
        semantic, measurements, _malformed, has_ckr = _inspect_probe(
            returncode,
            stdout,
            stderr,
            context="encrypt-state-roundtrip",
        )
        if has_ckr and measurements:
            _raise_provider_disposition(semantic, measurements)
        if semantic:
            _raise_provider_disposition(semantic, measurements)
        state_function = _state_function_not_supported(stdout)
        if state_function is not None:
            pytest.skip(f"{state_function} is not supported")
        if "SKIP" in lines_map:
            pytest.skip(f"Module skipped encrypt state test: {lines_map['SKIP']}")
        _require_complete(
            stdout,
            context="encrypt-state-roundtrip",
            semantic=semantic,
            measurements=measurements,
        )
        if "REFERENCE" not in lines_map:
            fail_as(
                "harness_error",
                label="encrypt-state-roundtrip",
                summary=f"Missing REFERENCE in output: {stdout!r}",
                detail={"probe_incomplete": True, "protocol": "missing_result"},
            )
        if "RESTORED" not in lines_map:
            fail_as(
                "harness_error",
                label="encrypt-state-roundtrip",
                summary=f"Missing RESTORED in output: {stdout!r}",
                detail={"probe_incomplete": True, "protocol": "missing_result"},
            )

        ref = lines_map["REFERENCE"]
        restored = lines_map["RESTORED"]
        from pkcs11_check.testcases.conftest import assert_correct

        assert_correct(
            actual=restored,
            expected=ref,
            label="C_SetOperationState:encrypt state round-trip",
            operation="C_SetOperationState",
            mechanism="CKM_AES_CBC",
        )
