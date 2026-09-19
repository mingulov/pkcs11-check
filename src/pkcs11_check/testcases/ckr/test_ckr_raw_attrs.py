"""CKR attribute permission tests via raw ctypes calls.

Tests CKR_KEY_FUNCTION_NOT_PERMITTED by creating keys with specific
CKA_* attributes set to False, then using raw C_*Init calls that
bypass the python-pkcs11 wrapper's attribute checks.

Each test launches the ``ckr_raw_attrs`` probe module (``_probes/ckr_raw_attrs.py``)
via ``run_probe`` at ``Level.LOGIN``: the probe infra opens a session and -- only when a
PIN is configured -- logs in, with the PIN travelling solely through the ``_P11CHECK_PIN``
env var (never embedded in source or params -- Invariant I3).
"""

from __future__ import annotations

import ctypes
import json
import re
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.metadata_std import ATTR_NAMES
from pkcs11_check.raw.rv import ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_SIGN,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_OK,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import SUBPROCESS_TIMEOUT_MARKER, pin_from_config
from pkcs11_check.testcases.ckr._subprocess import assert_ckr_subprocess_ok

pytestmark = [pytest.mark.access, pytest.mark.subprocess]


_EVENT_PREFIX = "ATTRIBUTE_EVENT:"
_CKR_LINE_RE = re.compile(r"^CKR:0x([0-9a-fA-F]+)$")
_CKR_HEX_WIDTH = ctypes.sizeof(CK_ULONG) * 2
_CKR_MAX = (1 << (ctypes.sizeof(CK_ULONG) * 8)) - 1
_MAX_VALUE_TYPE = 64
_MAX_VALUE_REPR = 256


def _raise_strongest(records: list[C.Classification]) -> None:
    strongest = next((item for item in records if item.outcome == "fail"), None)
    if strongest is None:
        strongest = next((item for item in records if item.outcome == "xfail"), None)
    if strongest is not None:
        C.raise_for_record(strongest)


def _protocol_error(
    label: str,
    summary: str,
    *,
    detail: dict[str, Any],
    reason: str = "harness_error",
) -> C.Classification:
    # reason is "probe_incomplete" only for pure absence (a marker never arrived):
    # unresolved attribution stays a loud provider-side fail. Malformed, mismatched,
    # or duplicated emissions keep "harness_error": the child observably emitted wire
    # bytes our own protocol forbids.
    return C.record_as(reason, label=label, summary=f"{label}: {summary}", detail=detail)


def _parse_event(
    line: str,
    *,
    label: str,
    expected_operation: str,
    expected_attribute: int,
) -> tuple[dict[str, Any] | None, C.Classification | None]:
    try:
        payload = json.loads(line.removeprefix(_EVENT_PREFIX))
    except json.JSONDecodeError as exc:
        return None, _protocol_error(
            label,
            f"malformed ATTRIBUTE_EVENT marker: {exc.msg}",
            detail={"protocol": "permission_claim", "marker": "ATTRIBUTE_EVENT"},
        )
    if not isinstance(payload, dict):
        return None, _protocol_error(
            label,
            "ATTRIBUTE_EVENT payload is not an object",
            detail={"protocol": "permission_claim", "marker": "ATTRIBUTE_EVENT"},
        )

    event = payload.get("event")
    expected_name = ATTR_NAMES.get(expected_attribute, str(expected_attribute))
    attr = payload.get("attribute")
    base_keys = {"operation", "event", "attribute"}
    if payload.get("operation") != expected_operation:
        return None, _protocol_error(
            label,
            "ATTRIBUTE_EVENT operation does not match selected probe",
            detail={"protocol": "permission_claim", "expected_operation": expected_operation},
        )
    if (
        not isinstance(attr, dict)
        or set(attr) != {"name", "id"}
        or attr.get("name") != expected_name
        or isinstance(attr.get("id"), bool)
        or not isinstance(attr.get("id"), int)
        or attr["id"] != expected_attribute
    ):
        return None, _protocol_error(
            label,
            "ATTRIBUTE_EVENT attribute descriptor does not match selected probe",
            detail={
                "protocol": "permission_claim",
                "expected_attribute": {"name": expected_name, "id": expected_attribute},
            },
        )
    if event == "omitted" and set(payload) == base_keys:
        return payload, None
    if event == "boolean" and set(payload) == base_keys | {"value"}:
        if isinstance(payload.get("value"), bool):
            return payload, None
        return None, _protocol_error(
            label,
            "boolean ATTRIBUTE_EVENT value is not bool",
            detail={"protocol": "permission_claim", "event": "boolean"},
        )
    if event == "malformed":
        if set(payload) != base_keys | {"value_type", "value_repr"}:
            return None, _protocol_error(
                label,
                (
                    "malformed ATTRIBUTE_EVENT value_type/value_repr evidence is missing "
                    "or has extra fields"
                ),
                detail={"protocol": "permission_claim", "event": "malformed"},
            )
        value_type = payload.get("value_type")
        value_repr = payload.get("value_repr")
        if (
            isinstance(value_type, str)
            and 0 < len(value_type) <= _MAX_VALUE_TYPE
            and isinstance(value_repr, str)
            and 0 < len(value_repr) <= _MAX_VALUE_REPR
        ):
            return payload, None
        return None, _protocol_error(
            label,
            "malformed ATTRIBUTE_EVENT value evidence is missing or unbounded",
            detail={"protocol": "permission_claim", "event": "malformed"},
        )
    return None, _protocol_error(
        label,
        "ATTRIBUTE_EVENT has an invalid event kind or payload shape",
        detail={"protocol": "permission_claim", "event": event},
    )


def _parse_ckr(
    lines: list[str], *, label: str, completed: bool
) -> tuple[int | None, C.Classification | None]:
    ckr_lines = [line for line in lines if line.startswith("CKR:")]
    if not ckr_lines and not completed:
        return None, None
    if not ckr_lines:
        return None, _protocol_error(
            label,
            "CKR marker is missing",
            detail={"protocol": "permission_claim", "ckr_markers": 0},
            reason="probe_incomplete",
        )
    if len(ckr_lines) != 1:
        return None, _protocol_error(
            label,
            "CKR marker is duplicated",
            detail={"protocol": "permission_claim", "ckr_markers": len(ckr_lines)},
        )
    match = _CKR_LINE_RE.fullmatch(ckr_lines[0])
    if match is None or len(match.group(1)) > _CKR_HEX_WIDTH:
        return None, _protocol_error(
            label,
            "CKR marker has invalid syntax or range",
            detail={"protocol": "permission_claim", "marker": ckr_lines[0]},
        )
    rv = int(match.group(1), 16)
    if rv > _CKR_MAX:
        return None, _protocol_error(
            label,
            "CKR marker is outside native CK_ULONG range",
            detail={"protocol": "permission_claim", "marker": ckr_lines[0]},
        )
    return rv, None


def _record_ckr_deviation(
    *,
    label: str,
    operation: str,
    rv: int,
    detail: dict[str, Any],
) -> C.Classification | None:
    expected = (CKR_KEY_FUNCTION_NOT_PERMITTED,)
    if rv in (int(CKR_OK), int(CKR_KEY_FUNCTION_NOT_PERMITTED)):
        return None
    if is_standard_ckr(rv) or is_vendor_defined_ckr(rv):
        return C.record_as(
            "nonspec_reject",
            kind="policy",
            label=label,
            operation=operation,
            expected=expected,
            actual=rv,
            summary=f"{label}: permission operation returned a defined non-spec CKR",
            detail=detail,
        )
    return C.record_as(
        "wrong_result",
        kind="metadata",
        label=label,
        operation=operation,
        expected=expected,
        actual=rv,
        summary=f"{label}: permission operation returned an undefined CKR",
        detail=detail,
    )


def _collect_permission_observations(
    out: str,
    *,
    label: str,
    operation: str,
    attribute: int,
    completed: bool = True,
) -> list[C.Classification]:
    """Parse and record child evidence before process disposition is inspected."""
    lines = out.splitlines()
    semantic: list[C.Classification] = []
    event_lines = [line for line in lines if line.startswith(_EVENT_PREFIX)]
    event: dict[str, Any] | None
    if not event_lines and not completed:
        event = None
    elif not event_lines:
        semantic.append(
            _protocol_error(
                label,
                "ATTRIBUTE_EVENT marker is missing",
                detail={"protocol": "permission_claim", "event_markers": 0},
                reason="probe_incomplete",
            )
        )
        event = None
    elif len(event_lines) != 1:
        semantic.append(
            _protocol_error(
                label,
                "ATTRIBUTE_EVENT marker is duplicated",
                detail={"protocol": "permission_claim", "event_markers": len(event_lines)},
            )
        )
        event = None
    else:
        event, event_error = _parse_event(
            event_lines[0],
            label=label,
            expected_operation=operation,
            expected_attribute=attribute,
        )
        if event_error is not None:
            semantic.append(event_error)

    rv, ckr_error = _parse_ckr(lines, label=label, completed=completed)
    if ckr_error is not None:
        semantic.append(ckr_error)
    if event is None:
        if rv is not None:
            deviation = _record_ckr_deviation(
                label=label,
                operation=operation,
                rv=rv,
                detail={
                    "protocol": "permission_claim",
                    "event": "invalid_or_missing",
                    "operation": operation,
                    "actual_ckr": ckr_name(rv),
                },
            )
            if deviation is not None:
                semantic.append(deviation)
        return semantic

    event_kind = event["event"]
    event_detail: dict[str, Any] = {
        "attribute": event["attribute"],
        "event": event_kind,
        "readback_operation": "C_GetAttributeValue",
    }
    if event_kind == "omitted":
        semantic.append(
            C.record_as(
                "honest_deviation",
                kind="policy",
                label=label,
                operation="C_GetAttributeValue",
                summary=f"{label}: permission attribute unavailable; enforcement oracle disabled",
                detail={**event_detail, "oracle_disabled": True},
            )
        )
    elif event_kind == "malformed":
        semantic.append(
            C.record_as(
                "wrong_result",
                kind="metadata",
                label=label,
                operation="C_GetAttributeValue",
                summary=f"{label}: permission attribute readback is malformed",
                detail={
                    **event_detail,
                    "value_type": event["value_type"],
                    "value_repr": event["value_repr"],
                },
            )
        )
    elif event["value"] is True:
        semantic.append(
            C.record_as(
                "honest_deviation",
                kind="policy",
                label=label,
                operation="C_GetAttributeValue",
                summary=f"{label}: module did not claim the permission restriction",
                detail={**event_detail, "value": True},
            )
        )

    # A provider/process failure may occur after the attribute readback but
    # before the dependent operation returns. Preserve the readback finding and
    # let the terminal crash/timeout remain independent and strongest.
    if rv is None:
        return semantic

    detail = {
        "attribute": event["attribute"],
        "event": event_kind,
        "operation": operation,
        "actual_ckr": ckr_name(rv),
    }
    if event_kind in {"omitted", "malformed"}:
        prior = semantic[-1]
        if prior.detail is not None:
            prior.detail["dependent_operation"] = operation
            prior.detail["dependent_actual_ckr"] = ckr_name(rv)
    if event_kind == "omitted":
        deviation = _record_ckr_deviation(
            label=label,
            operation=operation,
            rv=rv,
            detail={**detail, "oracle_disabled": True},
        )
        if deviation is not None:
            semantic.append(deviation)
        return semantic

    if event_kind == "malformed":
        deviation = _record_ckr_deviation(
            label=label,
            operation=operation,
            rv=rv,
            detail=detail,
        )
        if deviation is not None:
            semantic.append(deviation)
        return semantic

    claimed = event["value"] is False
    if not claimed:
        if event_kind == "boolean":
            readback = semantic[-1]
            if readback.detail is not None:
                readback.detail["dependent_operation"] = operation
                readback.detail["dependent_actual_ckr"] = ckr_name(rv)
        deviation = _record_ckr_deviation(
            label=label,
            operation=operation,
            rv=rv,
            detail=detail,
        )
        if deviation is not None:
            semantic.append(deviation)
    elif rv == int(CKR_OK):
        semantic.append(
            C.record_as(
                "self_contradiction",
                kind="policy",
                label=label,
                operation=operation,
                expected=(CKR_KEY_FUNCTION_NOT_PERMITTED,),
                actual=rv,
                summary=f"{label}: claimed the permission restriction then accepted the operation",
                detail=detail,
            )
        )
    else:
        deviation = _record_ckr_deviation(
            label=label,
            operation=operation,
            rv=rv,
            detail=detail,
        )
        if deviation is not None:
            semantic.append(deviation)
    return semantic


def _classify_permission_flag(
    out: str,
    *,
    label: str,
    operation: str,
    attribute: int,
) -> None:
    _raise_strongest(
        _collect_permission_observations(
            out,
            label=label,
            operation=operation,
            attribute=attribute,
        )
    )


def _check_permission_probe(
    rc: int,
    out: str,
    err: str,
    *,
    context: str,
    operation: str,
    attribute: int,
) -> None:
    # A normal setup refusal is a terminal provider-operability result owned by
    # the shared subprocess helper. Do not manufacture missing-event/CKR
    # harness findings for a child that never reached the measurement.
    lines = out.splitlines()
    setup_lines = [line for line in lines if line.startswith("SETUP_XFAIL:")]
    event_lines = [line for line in lines if line.startswith(_EVENT_PREFIX)]
    ckr_lines = [line for line in lines if line.startswith("CKR:")]
    if setup_lines and not event_lines and not ckr_lines:
        assert_ckr_subprocess_ok(rc, out, err, context=context)
        return
    semantic = _collect_permission_observations(
        out,
        label=context,
        operation=operation,
        attribute=attribute,
        completed=rc == 0 and SUBPROCESS_TIMEOUT_MARKER not in err and not setup_lines,
    )
    # The child evidence is already recorded. A signal/SEH/timeout is processed
    # next and therefore remains the strongest terminal disposition.
    try:
        assert_ckr_subprocess_ok(rc, out, err, context=context)
    except BaseException as exc:
        process_record = getattr(exc, "_pkcs11_check_classification", None)
        if (
            setup_lines
            and isinstance(process_record, C.Classification)
            and process_record.reason == "not_operational"
        ):
            strongest = next((item for item in semantic if item.outcome == "fail"), None)
            if strongest is not None:
                C.raise_for_record(strongest)
        raise
    _raise_strongest(semantic)


def _run_probe(p11_config: Any, probe: str) -> tuple[int, str, str]:
    result = run_probe(
        "ckr_raw_attrs",
        {"module_path": str(p11_config.module), "probe": probe},
        pin=pin_from_config(p11_config),
        timeout=15,
        coverage="session",
    )
    return result.returncode, result.stdout, result.stderr


class TestKeyFunctionNotPermitted:
    """Keys with CKA_*=False tested via raw C_*Init calls."""

    def test_encrypt_not_permitted(self, p11_config: Any) -> None:
        """Key with CKA_ENCRYPT=False -> C_EncryptInit -> CKR_KEY_FUNCTION_NOT_PERMITTED.

        PKCS#11 v3.2: If CKA_ENCRYPT is False, C_EncryptInit MUST return
        CKR_KEY_FUNCTION_NOT_PERMITTED. Some modules return CKR_OK, meaning the key
        permission flag is silently ignored -- keys without CKA_ENCRYPT=True can still
        be used to encrypt. This is a security finding.
        """
        rc, out, err = _run_probe(p11_config, "encrypt")
        _check_permission_probe(
            rc,
            out,
            err,
            context="C_EncryptInit with CKA_ENCRYPT=False",
            operation="C_EncryptInit",
            attribute=int(CKA_ENCRYPT),
        )

    def test_sign_not_permitted(self, p11_config: Any) -> None:
        """Key with CKA_SIGN=False -> C_SignInit -> CKR_KEY_FUNCTION_NOT_PERMITTED."""
        rc, out, err = _run_probe(p11_config, "sign")
        _check_permission_probe(
            rc,
            out,
            err,
            context="C_SignInit with CKA_SIGN=False",
            operation="C_SignInit",
            attribute=int(CKA_SIGN),
        )

    def test_decrypt_not_permitted(self, p11_config: Any) -> None:
        """Key with CKA_DECRYPT=False -> C_DecryptInit -> CKR_KEY_FUNCTION_NOT_PERMITTED.

        PKCS#11 v3.2: If CKA_DECRYPT is False, C_DecryptInit MUST return
        CKR_KEY_FUNCTION_NOT_PERMITTED. Some modules return CKR_OK, meaning the key
        permission flag is silently ignored -- keys without CKA_DECRYPT=True can still
        be used to decrypt. This is a security finding.
        """
        rc, out, err = _run_probe(p11_config, "decrypt")
        _check_permission_probe(
            rc,
            out,
            err,
            context="C_DecryptInit with CKA_DECRYPT=False",
            operation="C_DecryptInit",
            attribute=int(CKA_DECRYPT),
        )
