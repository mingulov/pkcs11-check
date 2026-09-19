"""CKR buffer sizing tests via raw ctypes calls.

Tests CKR_BUFFER_TOO_SMALL: output functions with undersized buffers.
Uses pkcs11_check.raw.RawPKCS11 - wrapper handles buffer sizing internally.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from typing import Any, Literal, cast

import pytest

from pkcs11_check.classification import (
    Classification,
    derive_verdict,
    fail_as,
    get_records,
    raise_for_record,
    record,
    record_as,
)
from pkcs11_check.raw.rv import ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_OK,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import (
    SUBPROCESS_TIMEOUT_MARKER,
    pin_from_config,
)
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed

pytestmark = [pytest.mark.access, pytest.mark.subprocess]

CountMode = Literal["none", "exact", "range"]

_EC_SETUP_PREFIX = "EC_SETUP:"
_EC_CLEANUP_PREFIX = "EC_CLEANUP:"
_EC_PROBE = "ecdh_aes_wrap_compressed_public_key_buffer_too_small"
_EC_MECHANISM = "CKM_ECDH_AES_KEY_WRAP"
_MAX_EC_LINE = 8192
_EC_ATTRS = (
    ("CKA_EC_POINT", 385),
    ("CKA_EC_PARAMS", 384),
)
_EC_ROLES = frozenset({"target_key", "compressed_pub", "priv", "pub"})
_EC_CLEANUP_ORDER = ("target_key", "compressed_pub", "priv", "pub")
_BUFFER_FIELD_NAMES = frozenset(
    {
        "CKR",
        "INITIAL_COUNT",
        "RETURNED_COUNT",
        "GUARD_OVERWRITTEN",
        "RETRY_CKR",
        "RETRY_LENGTH",
        "RETRY_MATCH",
        "RETRY_OUTPUT_CORRECT",
        "RETRY_USABLE",
        "OUTPUT_CORRECT",
        "MATCH",
        "FINAL_CKR",
        "FINAL_LEN",
        "RETRY_LEN",
        "NEEDED",
        "LEN",
        "OVERWRITTEN",
        "FINAL_OK",
        "OUTPUT_LENGTH_WITHIN_DECLARED",
        "SIZE_SENTINEL_CORRECT",
    }
)


class _DuplicateJSONKeyError(ValueError):
    pass


def _json_pairs_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKeyError(key)
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"nonfinite JSON value {value}")


def _is_json_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _ec_descriptor(value: object, expected: tuple[str, int]) -> bool:
    if not isinstance(value, dict) or set(value) != {"name", "id"}:
        return False
    identifier = value.get("id")
    return (
        value.get("name") == expected[0]
        and _is_json_int(identifier)
        and cast(int, identifier) == expected[1]
    )


def _ec_probe_is_selected(value: dict[str, object], expected_probe: str | None) -> bool:
    payload_probe = value.get("probe")
    return (
        expected_probe == _EC_PROBE
        and isinstance(payload_probe, str)
        and payload_probe == _EC_PROBE
    )


def _ec_record(
    reason: str,
    *,
    context: str,
    summary: str,
    kind: str | None = None,
    actual: int | None = None,
    detail: dict[str, object] | None = None,
    operation: str = "C_GetAttributeValue",
    mechanism: str | None = _EC_MECHANISM,
    emit: bool = True,
) -> Classification:
    if emit:
        return record_as(
            reason,
            kind=kind,
            label=context,
            operation=operation,
            mechanism=mechanism,
            actual=actual,
            summary=summary,
            detail=detail,
        )
    outcome, severity = derive_verdict(reason, kind)
    return Classification(
        reason=reason,
        outcome=outcome,
        severity=severity,
        kind=kind,
        label=context,
        summary=summary,
        operation=operation,
        mechanism=mechanism,
        actual_ckr=ckr_name(actual) if actual is not None else None,
        detail=detail,
    )


def _parse_ec_facts(
    output: str,
    *,
    context: str,
    process_complete: bool,
    expected_probe: str | None,
) -> tuple[
    list[Classification],
    list[Classification],
    list[Classification],
    str | None,
    str | None,
    bool,
    int | None,
    int | None,
    tuple[int, ...],
    tuple[int, ...],
]:
    """Parse the facts-only EC setup/cleanup protocol and classify provider effects."""
    semantic: list[Classification] = []
    protocol: list[Classification] = []
    exact_protocol: list[Classification] = []
    done_status: str | None = None
    saw_setup = False
    attr_index = 0
    point_present = False
    point_seen = False
    point_state: str | None = None
    point_encoding: str | None = None
    params_present = False
    read_error_seen = False
    unexpected_read_error = False
    done_seen = False
    cleanup_roles: set[str] = set()
    cleanup_index: int | None = None
    cleanup_last_index = -1
    legacy_setup_seen = False
    setup_index: int | None = None
    ready_index: int | None = None
    setup_refusal_indices: list[int] = []
    measurement_indices: list[int] = []

    def protocol_error(message: str) -> None:
        bounded_message = message[:256]
        protocol.append(
            _ec_record(
                "harness_error",
                context=context,
                operation="EC_SETUP",
                mechanism=None,
                summary=f"{context}: malformed EC protocol: {bounded_message}",
                detail={"protocol": "ec_setup", "probe_incomplete": True},
                emit=False,
            )
        )

    def parse_line(line: str, prefix: str) -> dict[str, object] | None:
        payload = line.removeprefix(prefix)
        if len(payload) > _MAX_EC_LINE:
            protocol_error("event exceeds bounded transport limit")
            return None
        try:
            value = json.loads(
                payload,
                object_pairs_hook=_json_pairs_without_duplicates,
                parse_constant=_reject_json_constant,
            )
        except (MemoryError, RecursionError):
            protocol_error("bounded JSON parse failure")
            return None
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            protocol_error(f"invalid JSON: {type(exc).__name__}")
            return None
        if not isinstance(value, dict):
            protocol_error("event must be a JSON object")
            return None
        return value

    setup_common = {"schema", "probe", "event"}
    lines = output.splitlines()
    for line_index, line in enumerate(lines):
        if line.startswith("SETUP_XFAIL:"):
            if line.removeprefix("SETUP_XFAIL:").strip():
                legacy_setup_seen = True
                setup_refusal_indices.append(line_index)
        if line == "OK" or line.startswith("OK:") or line.split(":", 1)[0] in _BUFFER_FIELD_NAMES:
            measurement_indices.append(line_index)
        if line.startswith(_EC_SETUP_PREFIX):
            value = parse_line(line, _EC_SETUP_PREFIX)
            if value is None:
                continue
            if (
                set(value) < setup_common
                or not _is_json_int(value.get("schema"))
                or cast(int, value.get("schema")) != 1
                or not _ec_probe_is_selected(value, expected_probe)
            ):
                protocol_error("invalid schema, probe, or common fields")
                continue
            saw_setup = True
            if setup_index is None:
                setup_index = line_index
            if cleanup_index is not None:
                protocol_error("setup event follows cleanup")
            event = value.get("event")
            if not isinstance(event, str):
                protocol_error("event is not a string")
                continue
            if done_seen:
                protocol_error("event follows done")
            if event == "attribute":
                if read_error_seen:
                    protocol_error("read_error cannot coexist with attribute events")
                    continue
                expected_keys = setup_common | {"operation", "attribute", "state"}
                if value.get("state") == "present":
                    expected_keys |= {"value_len"}
                elif value.get("state") == "unusable":
                    expected_keys |= {"value_type", "value_len"}
                if set(value) != expected_keys or value.get("operation") != "C_GetAttributeValue":
                    protocol_error("invalid attribute event fields")
                    continue
                if attr_index >= len(_EC_ATTRS):
                    protocol_error("duplicate or unexpected attribute event")
                    continue
                expected_attr = _EC_ATTRS[attr_index]
                if not _ec_descriptor(value.get("attribute"), expected_attr):
                    protocol_error("attribute events are out of order")
                    continue
                state = value.get("state")
                if not isinstance(state, str) or state not in {"missing", "present", "unusable"}:
                    protocol_error("invalid attribute state")
                    continue
                if state == "present":
                    value_len = value.get("value_len")
                    if not _is_json_int(value_len):
                        protocol_error("present value_len must be a positive integer")
                        continue
                    if cast(int, value_len) <= 0:
                        protocol_error("present value_len must be a positive integer")
                        continue
                    if expected_attr[0] == "CKA_EC_POINT":
                        point_present = True
                    elif expected_attr[0] == "CKA_EC_PARAMS":
                        params_present = True
                elif state == "unusable":
                    value_type = value.get("value_type")
                    value_len = value.get("value_len")
                    if not isinstance(value_type, str) or not value_type or len(value_type) > 64:
                        protocol_error("invalid unusable attribute facts")
                        continue
                    if value_len is not None:
                        if not _is_json_int(value_len) or cast(int, value_len) < 0:
                            protocol_error("invalid unusable attribute facts")
                            continue
                    semantic.append(
                        _ec_record(
                            "not_operational",
                            kind="metadata",
                            context=context,
                            summary=f"{context}: {expected_attr[0]} is unusable",
                            detail={
                                "dependent_operation": "C_WrapKey",
                                "curve": "secp256r1",
                                "attribute": {
                                    "name": expected_attr[0],
                                    "id": expected_attr[1],
                                },
                                "state": "unusable",
                                "value_type": value_type,
                                "value_len": value_len,
                            },
                        )
                    )
                elif state == "missing":
                    semantic.append(
                        _ec_record(
                            "not_operational",
                            kind="metadata",
                            context=context,
                            summary=f"{context}: {expected_attr[0]} is missing",
                            detail={
                                "dependent_operation": "C_WrapKey",
                                "curve": "secp256r1",
                                "attribute": {
                                    "name": expected_attr[0],
                                    "id": expected_attr[1],
                                },
                                "state": "missing",
                            },
                        )
                    )
                attr_index += 1
            elif event == "point":
                expected_keys = setup_common | {
                    "operation",
                    "attribute",
                    "curve",
                    "state",
                    "encoding",
                    "diagnostic",
                }
                if set(value) != expected_keys or value.get("operation") != "C_GetAttributeValue":
                    protocol_error("invalid point event fields")
                    continue
                if read_error_seen:
                    protocol_error("read_error cannot coexist with point events")
                    continue
                if attr_index != 2 or not point_present or point_seen:
                    protocol_error("point event lacks a unique present point attribute")
                    continue
                if (
                    not _ec_descriptor(value.get("attribute"), _EC_ATTRS[0])
                    or value.get("curve") != "secp256r1"
                ):
                    protocol_error("invalid point descriptor or curve")
                    continue
                state = value.get("state")
                encoding = value.get("encoding")
                diagnostic = value.get("diagnostic")
                if (
                    not isinstance(state, str)
                    or state not in {"usable", "encoding_error", "invalid_point"}
                    or not isinstance(encoding, str)
                    or encoding
                    not in {
                        "raw_uncompressed",
                        "der_uncompressed",
                        "der_compressed",
                        "unrecognized",
                    }
                    or not isinstance(diagnostic, str)
                    or len(diagnostic) > 256
                    or state == "usable"
                    and (encoding == "unrecognized" or diagnostic != "")
                    or state != "usable"
                    and not diagnostic
                ):
                    protocol_error("invalid point facts")
                    continue
                point_seen = True
                point_state = state
                point_encoding = encoding
                detail = {
                    "dependent_operation": "C_WrapKey",
                    "curve": "secp256r1",
                    "attribute": {"name": "CKA_EC_POINT", "id": 385},
                    "encoding": encoding,
                    "state": state,
                }
                if state == "encoding_error":
                    semantic.append(
                        _ec_record(
                            "not_operational",
                            kind="metadata",
                            context=context,
                            summary=f"{context}: EC point encoding is unavailable ({diagnostic})",
                            detail={**detail, "diagnostic": diagnostic},
                        )
                    )
                elif state == "invalid_point":
                    semantic.append(
                        _ec_record(
                            "wrong_result",
                            kind="crypto",
                            context=context,
                            summary=(
                                f"{context}: provider returned an invalid EC point ({diagnostic})"
                            ),
                            detail={**detail, "diagnostic": diagnostic},
                        )
                    )
            elif event == "read_error":
                if done_seen:
                    protocol_error("read_error event follows done")
                expected_keys = setup_common | {"operation", "requested_attributes", "rv"}
                if set(value) != expected_keys or value.get("operation") != "C_GetAttributeValue":
                    protocol_error("invalid read_error fields")
                    continue
                if read_error_seen:
                    protocol_error("duplicate read_error event")
                    continue
                requested = value.get("requested_attributes")
                if (
                    not isinstance(requested, list)
                    or len(requested) != len(_EC_ATTRS)
                    or any(
                        not _ec_descriptor(item, expected)
                        for item, expected in zip(requested, _EC_ATTRS, strict=True)
                    )
                ):
                    protocol_error("invalid requested attribute descriptors")
                    continue
                rv = value.get("rv")
                if not _is_json_int(rv) or rv == 0:
                    protocol_error("read_error rv must be a nonzero integer")
                    continue
                read_error_seen = True
                if attr_index != 0 or point_seen:
                    protocol_error("read_error cannot coexist with attribute events")
                if rv in (int(CKR_ATTRIBUTE_SENSITIVE), int(CKR_ATTRIBUTE_TYPE_INVALID)):
                    semantic.append(
                        _ec_record(
                            "not_operational",
                            kind="metadata",
                            context=context,
                            actual=rv,
                            summary=f"{context}: C_GetAttributeValue refused EC attributes",
                            detail={
                                "dependent_operation": "C_WrapKey",
                                "curve": "secp256r1",
                                "requested_attributes": requested,
                            },
                        )
                    )
                else:
                    unexpected_read_error = True
                    assert isinstance(rv, int)
                    rv_display = f"{rv:#x}"[:64]
                    exact_protocol.append(
                        _ec_record(
                            "harness_error",
                            context=context,
                            actual=rv,
                            summary=(f"{context}: unexpected C_GetAttributeValue CKR {rv_display}"),
                            detail={
                                "protocol": "ec_setup",
                                "unexpected_reader_termination": True,
                                "requested_attributes": requested,
                            },
                            emit=False,
                        )
                    )
            elif event == "done":
                if set(value) != setup_common | {"status"}:
                    protocol_error("invalid done fields")
                    continue
                status = value.get("status")
                if not isinstance(status, str) or status not in {
                    "ready",
                    "unavailable",
                    "invalid_point",
                    "read_refused",
                }:
                    protocol_error("invalid done status")
                    continue
                if done_seen:
                    protocol_error("duplicate done event")
                    continue
                done_valid = not done_seen and cleanup_index is None
                done_seen = True
                done_status = status
                if read_error_seen and status != "read_refused":
                    protocol_error("read_error must complete with read_refused")
                    done_valid = False
                elif status == "read_refused" and not read_error_seen:
                    protocol_error("read_refused requires read_error")
                    done_valid = False
                elif status == "invalid_point" and (
                    attr_index != 2 or point_state != "invalid_point"
                ):
                    protocol_error("invalid_point requires both attributes and an invalid point")
                    done_valid = False
                elif status == "ready" and (
                    attr_index != 2 or point_state != "usable" or not params_present
                ):
                    protocol_error("ready requires usable point and both present attributes")
                    done_valid = False
                elif status == "unavailable" and attr_index != 2:
                    protocol_error("unavailable requires both attribute events")
                    done_valid = False
                elif status == "unavailable" and point_present and not point_seen:
                    protocol_error("present point requires a point event")
                    done_valid = False
                elif status == "unavailable" and point_state == "invalid_point":
                    protocol_error("invalid point requires invalid_point completion")
                    done_valid = False
                elif status == "unavailable" and params_present and point_state == "usable":
                    protocol_error("usable setup requires ready completion")
                    done_valid = False
                if done_valid and status == "ready":
                    ready_index = line_index
            else:
                protocol_error(f"unsupported event {event!r}")
        elif line.startswith(_EC_CLEANUP_PREFIX):
            value = parse_line(line, _EC_CLEANUP_PREFIX)
            if value is None:
                continue
            expected_keys = {"schema", "probe", "object", "operation", "rv"}
            if (
                set(value) != expected_keys
                or not _is_json_int(value.get("schema"))
                or cast(int, value.get("schema")) != 1
                or not _ec_probe_is_selected(value, expected_probe)
            ):
                protocol_error("invalid cleanup fields")
                continue
            cleanup_owned = (
                setup_index is not None
                and setup_index < line_index
                or legacy_setup_seen
                and setup_refusal_indices[-1] < line_index
            )
            if not cleanup_owned:
                protocol_error("cleanup requires applicable EC setup ownership")
            role = value.get("object")
            rv = value.get("rv")
            if (
                not isinstance(role, str)
                or role not in _EC_ROLES
                or value.get("operation") != "C_DestroyObject"
                or not _is_json_int(rv)
                or rv == 0
                or role in cleanup_roles
            ):
                protocol_error("invalid or duplicate cleanup event")
                continue
            if cleanup_owned and cleanup_index is None:
                cleanup_index = line_index
            cleanup_roles.add(role)
            assert isinstance(rv, int)
            role_index = _EC_CLEANUP_ORDER.index(role)
            if role_index <= cleanup_last_index:
                protocol_error("cleanup roles are out of order")
            cleanup_last_index = max(cleanup_last_index, role_index)
            semantic.append(
                _ec_record(
                    "not_operational",
                    kind="lifecycle",
                    context=context,
                    operation="C_DestroyObject",
                    mechanism=None,
                    actual=rv,
                    summary=f"{context}: C_DestroyObject failed for {role}",
                    detail={"object": role},
                )
            )

    if saw_setup:
        if read_error_seen:
            if done_status != "read_refused" and not unexpected_read_error and process_complete:
                protocol_error("read_error sequence is incomplete")
        elif process_complete and attr_index != 2:
            protocol_error("EC setup did not emit both attributes")
        if process_complete and not done_seen and not unexpected_read_error:
            protocol_error("EC setup did not emit done")
    if len(protocol) > 1:
        protocol = [
            replace(
                protocol[0],
                summary="; ".join(item.summary for item in protocol),
                detail={"protocol": "ec_setup", "probe_incomplete": True},
            )
        ]
    return (
        semantic,
        protocol,
        exact_protocol,
        done_status,
        point_encoding,
        saw_setup,
        cleanup_index,
        ready_index,
        tuple(setup_refusal_indices),
        tuple(measurement_indices),
    )


def _run_probe(p11_config: Any, probe: str) -> tuple[int, str, str]:
    """Launch the ``ckr_raw_buffer`` probe (Level.LOGIN) and return (rc, out, err).

    The PIN travels solely through ``_P11CHECK_PIN`` (via ``pin_from_config`` ->
    ``run_probe``); it is never embedded in the probe source or params (Invariant I3).
    """
    result = run_probe(
        "ckr_raw_buffer",
        {"module_path": str(p11_config.module), "probe": probe},
        pin=pin_from_config(p11_config),
        timeout=15,
        coverage="session",
    )
    return result.returncode, result.stdout, result.stderr


@dataclass(frozen=True)
class BufferProbeSchema:
    """Required protocol fields and effect checks for one buffer probe."""

    expected_ckr: int | None = int(CKR_BUFFER_TOO_SMALL)
    expected_count: int | None = None
    require_initial_count: bool = False
    required_fields: tuple[str, ...] = ("CKR", "GUARD_OVERWRITTEN", "RETURNED_COUNT")
    require_retry: bool = False
    retry_fields: tuple[str, ...] = ("RETRY_CKR", "RETRY_LENGTH")
    retry_effect_fields: tuple[str, ...] = ()
    retry_length_reference: str | None = None
    success_effect_fields: tuple[str, ...] = ()
    retry_usable: bool = False
    max_count: int | None = None
    count_mode: CountMode = "none"
    count_min: int | None = None
    count_max: int | None = None


def _collect_buffer_measurement(
    fields: dict[str, str],
    *,
    schema: BufferProbeSchema,
    context: str,
    validate_required: bool,
) -> list[Classification]:
    """Collect provider effects and (when appropriate) protocol defects."""
    failures: list[Classification] = []
    operation = context.split(":", 1)[0]
    values: dict[str, int] = {}

    def add(
        reason: str,
        *,
        kind: str | None = None,
        summary: str,
    ) -> None:
        outcome, severity = derive_verdict(reason, kind)
        failures.append(
            Classification(
                reason=reason,
                outcome=outcome,
                severity=severity,
                kind=kind,
                label=context,
                summary=summary,
                operation=operation,
            )
        )

    def parse(name: str, *, required: bool = False) -> int | None:
        value = fields.get(name)
        if value is None:
            if required and validate_required:
                add("probe_incomplete", summary=f"{context}: missing {name} measurement")
            return None
        try:
            parsed = int(value, 0)
        except (TypeError, ValueError):
            if validate_required:
                add("harness_error", summary=f"{context}: malformed {name} measurement {value!r}")
            return None
        values[name] = parsed
        return parsed

    ckr = parse("CKR", required="CKR" in schema.required_fields)
    overwritten = parse("GUARD_OVERWRITTEN", required="GUARD_OVERWRITTEN" in schema.required_fields)
    for name in schema.required_fields:
        if name not in {"CKR", "GUARD_OVERWRITTEN"}:
            parse(name, required=True)

    initial = parse(
        "INITIAL_COUNT",
        required=(
            schema.require_initial_count
            or schema.expected_count is not None
            or schema.count_mode != "none"
        ),
    )
    returned = parse(
        "RETURNED_COUNT",
        required=(
            schema.expected_count is not None
            or schema.require_initial_count
            or schema.max_count is not None
            or schema.count_mode != "none"
        ),
    )
    # Both success and BUFFER_TOO_SMALL make the returned count observable.  A clean
    # CKR deviation must not hide an independently contradictory size measurement.
    count_is_observable = ckr in (int(CKR_BUFFER_TOO_SMALL), int(CKR_OK))
    if (
        count_is_observable
        and schema.expected_count is not None
        and initial is not None
        and initial != schema.expected_count
    ):
        add(
            "self_contradiction",
            kind="metadata",
            summary=(
                f"{context}: initial count {initial} contradicts expected count "
                f"{schema.expected_count}"
            ),
        )
    if schema.count_mode == "exact":
        expected_returned = schema.expected_count if schema.expected_count is not None else initial
        if (
            count_is_observable
            and initial is not None
            and returned is not None
            and expected_returned is not None
            and returned != expected_returned
        ):
            add(
                "self_contradiction",
                kind="metadata",
                summary=(
                    f"{context}: returned count {returned} contradicts expected count "
                    f"{expected_returned}"
                ),
            )
    elif schema.count_mode == "range" and count_is_observable and returned is not None:
        lower = schema.count_min if schema.count_min is not None else schema.expected_count
        upper = schema.count_max
        if lower is not None and returned < lower:
            add(
                "self_contradiction",
                kind="metadata",
                summary=(
                    f"{context}: returned count {returned} is below the permitted minimum {lower}"
                ),
            )
        if upper is not None and returned > upper:
            add(
                "self_contradiction",
                kind="metadata",
                summary=(
                    f"{context}: returned count {returned} exceeds the permitted maximum {upper}"
                ),
            )
    if schema.max_count is not None and returned is not None and returned > schema.max_count:
        add(
            "self_contradiction",
            kind="metadata",
            summary=(
                f"{context}: returned count {returned} exceeds declared maximum {schema.max_count}"
            ),
        )

    if ckr is not None and schema.expected_ckr is not None and ckr != schema.expected_ckr:
        add(
            "honest_deviation",
            summary=(
                f"{context}: returned CKR 0x{ckr:08x} instead of expected "
                f"CKR 0x{schema.expected_ckr:08x}"
            ),
        )
    elif (
        ckr is not None
        and schema.expected_ckr is None
        and ckr
        not in (
            int(CKR_BUFFER_TOO_SMALL),
            int(CKR_OK),
        )
    ):
        if not is_standard_ckr(ckr) and not is_vendor_defined_ckr(ckr):
            add(
                "self_contradiction",
                kind="metadata",
                summary=f"{context}: returned undefined CKR 0x{ckr:08x}",
            )
        else:
            add(
                "nonspec_reject",
                summary=(
                    f"{context}: returned unsupported clean CKR 0x{ckr:08x}; "
                    "expected CKR_OK or CKR_BUFFER_TOO_SMALL"
                ),
            )
    if overwritten is not None and overwritten < 0:
        add(
            "self_contradiction",
            kind="metadata",
            summary=f"{context}: guard measurement {overwritten} is negative",
        )
    elif overwritten is not None and overwritten > 0:
        add(
            "self_contradiction",
            kind="policy",
            summary=(
                f"{context}: provider overwrote {overwritten} guard byte(s) beyond the "
                "declared output buffer"
            ),
        )

    if ckr == int(CKR_BUFFER_TOO_SMALL):
        if schema.retry_usable:
            usable = parse("RETRY_USABLE", required=True)
            if usable == 0:
                add(
                    "self_contradiction",
                    kind="lifecycle",
                    summary=f"{context}: retry length is unusable after CKR_BUFFER_TOO_SMALL",
                )
        else:
            usable = None
        # A MEASURED usable==0 settles it: the provider returned CKR_BUFFER_TOO_SMALL
        # without a usable length, so the probe could not size a retry buffer and
        # correctly did not try. Demanding the retry measurements anyway produced four
        # `harness_error` records on top of the self_contradiction recorded just above --
        # noise that blamed us for a measurement the provider's own behaviour made
        # unobtainable. Only an UNMEASURED usable falls back to the schema's requirement.
        retry_required = schema.require_retry if usable is None else usable > 0
        for name in schema.retry_fields:
            parse(name, required=retry_required)
        for name in schema.retry_effect_fields:
            parse(name, required=retry_required)
    else:
        for name in schema.retry_fields + schema.retry_effect_fields:
            if name in fields:
                parse(name)

    # A child may have emitted retry evidence even when its initial CKR deviated
    # from the expected value.  Always retain and classify that evidence rather
    # than letting the clean initial deviation hide a retry failure.
    retry_ckr = values.get("RETRY_CKR")
    retry_length = values.get("RETRY_LENGTH")
    if retry_ckr is not None and retry_ckr != int(CKR_OK):
        add(
            "self_contradiction",
            kind="lifecycle",
            summary=f"{context}: retry returned CKR 0x{retry_ckr:08x} instead of CKR_OK",
        )
    retry_reference = (
        values.get(schema.retry_length_reference) if schema.retry_length_reference else initial
    )
    if retry_length is not None and (
        retry_length <= 0 or retry_reference is not None and retry_length != retry_reference
    ):
        add(
            "self_contradiction",
            kind="lifecycle",
            summary=(
                f"{context}: retry length {retry_length} is unusable; expected "
                f"{retry_reference if retry_reference is not None else 'a positive length'}"
            ),
        )

    if ckr == int(CKR_OK):
        for name in schema.success_effect_fields:
            parse(name, required=True)

    for name in (
        "RETRY_OUTPUT_CORRECT",
        "OUTPUT_CORRECT",
        "RETRY_MATCH",
        "MATCH",
    ):
        if name in fields:
            effect = parse(name)
            if effect == 0:
                add(
                    "wrong_result",
                    kind="crypto",
                    summary=f"{context}: {name} reports incorrect output",
                )
    for name, kind in (
        ("FINAL_OK", "lifecycle"),
        ("OUTPUT_LENGTH_WITHIN_DECLARED", "policy"),
        ("SIZE_SENTINEL_CORRECT", "metadata"),
    ):
        if name in fields:
            effect = parse(name)
            if effect == 0:
                add(
                    "self_contradiction",
                    kind=kind,
                    summary=f"{context}: {name} reports an invalid provider effect",
                )
    if "FINAL_CKR" in fields:
        final_ckr = parse("FINAL_CKR")
        if final_ckr not in (None, int(CKR_OK)):
            add(
                "self_contradiction",
                kind="lifecycle",
                summary=f"{context}: final operation returned CKR 0x{final_ckr:08x}",
            )
    # Collapse repeated measurement-schema defects within each reason group. Missing
    # fields (unresolved attribution) merge separately from malformed ones (our own
    # emission defect) so the collapse never moves a record across the
    # harness/provider attribution boundary.
    for reason in ("harness_error", "probe_incomplete"):
        group = [item for item in failures if item.reason == reason]
        if len(group) <= 1:
            continue
        details = "; ".join(item.summary for item in group)
        first = failures.index(group[0])
        failures[first] = replace(
            group[0],
            summary=details,
            detail={"protocol": "measurement_schema", "probe_incomplete": True},
        )
        failures = [
            item for index, item in enumerate(failures) if item.reason != reason or index == first
        ]
    return failures


def _raise_strongest(failures: list[Classification]) -> Classification | None:
    """Return concrete provider failures first, harness failures last.

    All records are preserved; only the raised headline is ordered. Unresolved
    attribution (``probe_incomplete``) sorts between the two: a concrete provider
    verdict drawn from observed bytes outranks a missing measurement, which still
    outranks a defect in our own emission.
    """
    for outcome in ("fail", "xfail"):
        for item in failures:
            if item.outcome == outcome and item.reason not in ("harness_error", "probe_incomplete"):
                return item
        for item in failures:
            if item.outcome == outcome and item.reason == "probe_incomplete":
                return item
        for item in failures:
            if item.outcome == outcome:
                return item
    return None


def classify_buffer_measurement(
    fields: dict[str, str],
    *,
    expected_count: int | None = None,
    count_mode: CountMode = "none",
    count_min: int | None = None,
    count_max: int | None = None,
    context: str,
    raise_outcome: bool = True,
    expected_ckr: int | None = int(CKR_BUFFER_TOO_SMALL),
    max_count: int | None = None,
    require_initial_count: bool = False,
    required_fields: tuple[str, ...] = ("CKR", "GUARD_OVERWRITTEN", "RETURNED_COUNT"),
    require_retry: bool = False,
    retry_effect_fields: tuple[str, ...] = (),
    success_effect_fields: tuple[str, ...] = (),
    retry_usable: bool = False,
    retry_length_reference: str | None = None,
) -> Classification | None:
    """Classify a buffer probe using its explicit, per-probe protocol schema."""
    schema = BufferProbeSchema(
        expected_ckr=expected_ckr,
        expected_count=expected_count,
        require_initial_count=require_initial_count,
        required_fields=required_fields,
        require_retry=require_retry,
        retry_effect_fields=retry_effect_fields,
        success_effect_fields=success_effect_fields,
        retry_usable=retry_usable,
        retry_length_reference=retry_length_reference,
        max_count=max_count,
        count_mode=count_mode,
        count_min=count_min,
        count_max=count_max,
    )
    failures = _collect_buffer_measurement(
        fields, schema=schema, context=context, validate_required=True
    )
    for item in failures:
        record(item)
    strongest = _raise_strongest(failures)
    if strongest is not None and raise_outcome:
        raise_for_record(strongest)
    return strongest


def _parse_buffer_fields(output: str) -> dict[str, str]:
    """Parse the one-line measurement fields emitted by a raw buffer probe."""
    fields: dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        if name in {
            "CKR",
            "INITIAL_COUNT",
            "RETURNED_COUNT",
            "GUARD_OVERWRITTEN",
            "RETRY_CKR",
            "RETRY_LENGTH",
            "RETRY_MATCH",
            "RETRY_OUTPUT_CORRECT",
            "RETRY_USABLE",
            "OUTPUT_CORRECT",
            "MATCH",
            "FINAL_CKR",
            "FINAL_LEN",
            "RETRY_LEN",
            "NEEDED",
            "LEN",
            "OVERWRITTEN",
            "FINAL_OK",
            "OUTPUT_LENGTH_WITHIN_DECLARED",
            "SIZE_SENTINEL_CORRECT",
        }:
            fields[name] = value.strip()
    return fields


def _check_buffer_probe(
    rc: int,
    output: str,
    stderr: str,
    *,
    context: str,
    probe: str | None = None,
    expected_count: int | None = None,
    count_mode: CountMode = "none",
    count_min: int | None = None,
    count_max: int | None = None,
    expected_ckr: int | None = int(CKR_BUFFER_TOO_SMALL),
    max_count: int | None = None,
    require_initial_count: bool = False,
    required_fields: tuple[str, ...] = ("CKR", "GUARD_OVERWRITTEN", "RETURNED_COUNT"),
    require_retry: bool = False,
    retry_effect_fields: tuple[str, ...] = (),
    success_effect_fields: tuple[str, ...] = (),
    retry_usable: bool = False,
    retry_length_reference: str | None = None,
) -> None:
    """Apply provider effects before process precedence for one buffer probe."""
    process_complete = (
        rc == 0
        and SUBPROCESS_TIMEOUT_MARKER not in stderr
        and not any(
            line.startswith("HARNESS_ERROR:")
            for line in (*output.splitlines(), *stderr.splitlines())
        )
    )
    (
        semantic,
        protocol,
        exact_protocol,
        ec_done_status,
        point_encoding,
        has_ec_setup,
        cleanup_index,
        ready_index,
        setup_refusal_indices,
        measurement_indices,
    ) = _parse_ec_facts(
        output,
        context=context,
        process_complete=process_complete,
        expected_probe=probe,
    )
    malformed_marker: str | None = None
    for line in output.splitlines():
        if line.startswith("SETUP_XFAIL:"):
            prefix = "SETUP_XFAIL:"
            reason, kind = "not_operational", None
        elif line.startswith("BREAK:"):
            prefix = "BREAK:"
            reason, kind = "self_contradiction", "crypto"
        elif line.startswith("DEVIATION_XFAIL:"):
            prefix = "DEVIATION_XFAIL:"
            reason, kind = "honest_deviation", None
        else:
            continue
        payload = line.removeprefix(prefix).strip()
        if not payload:
            malformed_marker = prefix.removesuffix(":")
            continue
        outcome, severity = derive_verdict(reason, kind)
        semantic.append(
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
    # EC records are emitted through record_as() in _ec_record(), preserving the
    # explicit C_* operation/mechanism context. Legacy text markers are assembled
    # below and still need to be added directly.
    for item in semantic:
        if item.detail and "protocol_marker" in item.detail:
            record(item)
    for item in protocol:
        record(item)
    for item in exact_protocol:
        record(item)
    fields = _parse_buffer_fields(output)
    schema = BufferProbeSchema(
        expected_ckr=expected_ckr,
        expected_count=expected_count,
        require_initial_count=require_initial_count,
        required_fields=required_fields,
        require_retry=require_retry,
        retry_effect_fields=retry_effect_fields,
        success_effect_fields=success_effect_fields,
        retry_usable=retry_usable,
        retry_length_reference=retry_length_reference,
        max_count=max_count,
        count_mode=count_mode,
        count_min=count_min,
        count_max=count_max,
    )
    # A non-normal process disposition is authoritative.  We still collect complete
    # fields already emitted by the child, but never fabricate missing-field harness
    # records for a signal, SEH, timeout, or non-zero child exit.
    has_terminal_marker = any(
        line == "OK" or line.startswith("OK:") for line in output.splitlines()
    )
    has_ok_terminal = has_terminal_marker
    if has_ec_setup and ec_done_status in {"unavailable", "invalid_point", "read_refused"}:
        has_terminal_marker = True
    if (
        has_ec_setup
        and ec_done_status in {"unavailable", "invalid_point", "read_refused"}
        and (fields or has_ok_terminal)
    ):
        protocol.append(
            _ec_record(
                "harness_error",
                context=context,
                operation="EC_SETUP",
                mechanism=None,
                summary=f"{context}: terminal EC setup cannot accompany buffer evidence",
                detail={"protocol": "ec_setup", "probe_incomplete": True},
                emit=False,
            )
        )
        record(protocol[-1])
    if cleanup_index is not None and any(index > cleanup_index for index in measurement_indices):
        protocol.append(
            _ec_record(
                "harness_error",
                context=context,
                operation="EC_SETUP",
                mechanism=None,
                summary=f"{context}: buffer measurement begins after cleanup",
                detail={"protocol": "ec_setup", "probe_incomplete": True},
                emit=False,
            )
        )
        record(protocol[-1])
    if cleanup_index is not None and any(index > cleanup_index for index in setup_refusal_indices):
        protocol.append(
            _ec_record(
                "harness_error",
                context=context,
                operation="EC_SETUP",
                mechanism=None,
                summary=f"{context}: setup refusal follows cleanup",
                detail={"protocol": "ec_setup", "probe_incomplete": True},
                emit=False,
            )
        )
        record(protocol[-1])
    if (
        ready_index is not None
        and process_complete
        and not has_ok_terminal
        and not any(
            index > ready_index and (cleanup_index is None or index < cleanup_index)
            for index in setup_refusal_indices
        )
    ):
        protocol.append(
            _ec_record(
                "probe_incomplete",
                context=context,
                operation="EC_SETUP",
                mechanism=None,
                summary=(
                    f"{context}: ready setup did not emit a later setup refusal or "
                    "complete OK measurement"
                ),
                detail={"protocol": "ec_setup", "probe_incomplete": True},
                emit=False,
            )
        )
        record(protocol[-1])
    process_is_normal = (
        rc == 0
        and SUBPROCESS_TIMEOUT_MARKER not in stderr
        and (has_terminal_marker or (bool(semantic) and not fields))
        and not any(
            line.startswith("HARNESS_ERROR:")
            for line in (*output.splitlines(), *stderr.splitlines())
        )
    )
    failures = _collect_buffer_measurement(
        fields,
        schema=schema,
        context=context,
        validate_required=process_is_normal and has_ok_terminal and malformed_marker is None,
    )
    if point_encoding is not None and has_ec_setup:
        failures = [
            replace(
                item,
                detail={**(item.detail or {}), "ec_point_encoding": point_encoding},
            )
            for item in failures
        ]
    for item in failures:
        record(item)
    termination, _ = assert_subprocess_completed(rc, output, stderr, context=context)
    explicit_harness_records = [
        item for item in get_records() if item.reason == "harness_error" and item.label == context
    ]
    # A provider observation without the terminal OK marker is incomplete protocol.
    # Check this before provider deviations so a clean CKR mismatch cannot mask the
    # harness failure, while all observations parsed above remain recorded.
    hard_provider = _raise_strongest([*semantic, *failures])
    if hard_provider is not None and hard_provider.outcome == "fail":
        raise_for_record(hard_provider)
    if protocol or exact_protocol or malformed_marker is not None:
        malformed = (
            protocol[0]
            if protocol
            else exact_protocol[0]
            if exact_protocol
            else Classification(
                reason="harness_error",
                outcome="fail",
                severity="HIGH",
                label=context,
                summary=f"{context}: malformed marker",
                detail={"probe_incomplete": True, "protocol": "malformed_marker"},
            )
        )
        if not protocol and not exact_protocol:
            record(malformed)
        raise_for_record(malformed)
    if fields and not has_terminal_marker:
        fail_as(
            "probe_incomplete",
            label=context,
            summary=f"{context}: buffer probe did not emit a complete OK measurement",
            detail={"probe_incomplete": True, "termination": termination},
        )
    strongest = _raise_strongest([*semantic, *failures, *explicit_harness_records])
    if strongest is not None:
        raise_for_record(strongest)
    if not any(line == "OK" or line.startswith("OK:") for line in output.splitlines()):
        fail_as(
            "probe_incomplete",
            label=context,
            summary=f"{context}: buffer probe did not emit a complete OK measurement",
            detail={"probe_incomplete": True, "termination": termination},
        )


class TestBufferTooSmall:
    """Output operations with undersized buffers."""

    def test_digest_buffer_too_small(self, p11_config: Any) -> None:
        """C_Digest with 1-byte output -> CKR_BUFFER_TOO_SMALL.

        PKCS#11 v3.2: C_Digest with undersized output buffer MUST return
        CKR_BUFFER_TOO_SMALL and update *pulDigestLen with the required size.

        Uses a 64-byte buffer filled with guard bytes (0xAA) and passes out_len=1.
        After the call, checks how many guard bytes were overwritten to confirm
        whether the module actually wrote past the declared buffer boundary.
        """
        rc, out, err = _run_probe(p11_config, "digest_buffer_too_small")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_Digest undersized buffer",
            expected_count=32,
            count_mode="exact",
            require_retry=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
        )

    def test_encrypt_buffer_too_small(self, p11_config: Any) -> None:
        """C_Encrypt AES-ECB with 1-byte output -> CKR_BUFFER_TOO_SMALL."""
        rc, out, err = _run_probe(p11_config, "encrypt_buffer_too_small")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_Encrypt undersized buffer",
            expected_count=16,
            count_mode="exact",
        )

    def test_sign_buffer_too_small(self, p11_config: Any) -> None:
        """C_Sign with 1-byte output -> CKR_BUFFER_TOO_SMALL."""
        rc, out, err = _run_probe(p11_config, "sign_buffer_too_small")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_Sign undersized buffer",
            expected_count=256,
            count_mode="exact",
            require_retry=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
        )


class TestListBufferTooSmallGuards:
    """List-returning APIs must not write past the declared output count."""

    def test_get_slot_list_buffer_too_small_preserves_guard(self, p11_config: Any) -> None:
        """C_GetSlotList with one declared slot must preserve adjacent guard bytes."""
        rc, out, err = _run_probe(p11_config, "get_slot_list_guard")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_GetSlotList undersized list buffer guard",
            require_initial_count=True,
            count_mode="exact",
            require_retry=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
        )

    def test_get_mechanism_list_buffer_too_small_preserves_guard(self, p11_config: Any) -> None:
        """C_GetMechanismList with one declared slot must preserve adjacent guard bytes."""
        rc, out, err = _run_probe(p11_config, "get_mechanism_list_guard")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_GetMechanismList undersized list buffer guard",
            require_initial_count=True,
            count_mode="exact",
            require_retry=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
        )

    def test_get_interface_list_buffer_too_small_preserves_guard(self, p11_config: Any) -> None:
        """C_GetInterfaceList with one declared slot must preserve adjacent guard bytes."""
        rc, out, err = _run_probe(p11_config, "get_interface_list_guard")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_GetInterfaceList undersized list buffer guard",
            require_initial_count=True,
            count_mode="exact",
            require_retry=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
        )


class TestSearchOutputGuards:
    """Search APIs must not write past the declared object-handle count."""

    def test_find_objects_max_count_one_preserves_guard(self, p11_config: Any) -> None:
        """C_FindObjects must return at most ulMaxObjectCount handles."""
        rc, out, err = _run_probe(p11_config, "find_objects_max_count_one_guard")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_FindObjects one-handle output guard",
            expected_ckr=int(CKR_OK),
            max_count=1,
        )


class TestAttributeBufferTooSmallGuards:
    """C_GetAttributeValue must preserve caller buffers and size state."""

    def test_get_attribute_value_buffer_too_small_preserves_guard_and_retries(
        self, p11_config: Any
    ) -> None:
        """C_GetAttributeValue must not write past an undersized attribute buffer."""
        rc, out, err = _run_probe(p11_config, "get_attribute_value_guard")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_GetAttributeValue undersized attribute buffer guard",
            required_fields=("CKR", "GUARD_OVERWRITTEN", "RETURNED_COUNT", "NEEDED"),
            require_retry=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
            retry_length_reference="NEEDED",
        )


class TestDecryptBufferTooSmallGuards:
    """Decrypt output APIs must preserve state after CKR_BUFFER_TOO_SMALL."""

    def test_aes_cbc_pad_decrypt_buffer_too_small_preserves_guard_and_retries(
        self, p11_config: Any
    ) -> None:
        """C_Decrypt(CKM_AES_CBC_PAD) must be retryable after an undersized output."""
        rc, out, err = _run_probe(p11_config, "aes_cbc_pad_decrypt_buffer_too_small")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_Decrypt AES-CBC-PAD undersized output buffer guard",
            expected_count=len(b"cbc-pad-output"),
            count_mode="range",
            count_min=len(b"cbc-pad-output"),
            count_max=16,
            require_retry=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
        )

    def test_aes_cbc_pad_decrypt_update_buffer_too_small_preserves_guard_and_retries(
        self, p11_config: Any
    ) -> None:
        """C_DecryptUpdate(CKM_AES_CBC_PAD) must preserve state after undersized output."""
        rc, out, err = _run_probe(p11_config, "aes_cbc_pad_decrypt_update_buffer_too_small")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_DecryptUpdate AES-CBC-PAD undersized output buffer guard",
            expected_ckr=None,
            require_retry=True,
            retry_usable=True,
            retry_effect_fields=("FINAL_CKR", "RETRY_OUTPUT_CORRECT"),
            success_effect_fields=("FINAL_CKR", "FINAL_OK", "MATCH"),
        )

    def test_aes_cbc_pad_encrypt_final_buffer_too_small_preserves_guard_and_retries(
        self, p11_config: Any
    ) -> None:
        """C_EncryptFinal(CKM_AES_CBC_PAD) must preserve state after undersized output."""
        rc, out, err = _run_probe(p11_config, "aes_cbc_pad_encrypt_final_buffer_too_small")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_EncryptFinal AES-CBC-PAD undersized output buffer guard",
            expected_ckr=None,
            require_retry=True,
            retry_usable=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
            success_effect_fields=("MATCH",),
        )

    def test_aes_cbc_pad_decrypt_final_buffer_too_small_preserves_guard_and_retries(
        self, p11_config: Any
    ) -> None:
        """C_DecryptFinal(CKM_AES_CBC_PAD) must preserve state after undersized output."""
        rc, out, err = _run_probe(p11_config, "aes_cbc_pad_decrypt_final_buffer_too_small")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_DecryptFinal AES-CBC-PAD undersized output buffer guard",
            expected_ckr=None,
            require_retry=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
            success_effect_fields=("MATCH",),
        )


class TestByteOutputBufferTooSmallGuards:
    """Byte-output APIs must not write past the declared output length."""

    def test_wrap_key_buffer_too_small_preserves_guard(self, p11_config: Any) -> None:
        """C_WrapKey with one declared byte must preserve adjacent guard bytes."""
        rc, out, err = _run_probe(p11_config, "wrap_key_buffer_too_small")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_WrapKey undersized output buffer guard",
            require_initial_count=True,
            count_mode="exact",
            require_retry=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
        )

    def test_ecdh_aes_wrap_compressed_public_key_buffer_too_small_preserves_guard(
        self,
        p11_config: Any,
        p11_raw_session: Any,
    ) -> None:
        """ECDH-AES C_WrapKey with compressed EC public key must size safely."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDH_AES_KEY_WRAP"):
            pytest.skip("CKM_ECDH_AES_KEY_WRAP not supported")
        if not (rs.has_mechanism("EC_KEY_PAIR_GEN") or rs.has_mechanism("ECDSA_KEY_PAIR_GEN")):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")

        rc, out, err = _run_probe(
            p11_config, "ecdh_aes_wrap_compressed_public_key_buffer_too_small"
        )
        _check_buffer_probe(
            rc,
            out,
            err,
            context="ECDH-AES C_WrapKey compressed public key undersized output buffer guard",
            probe=_EC_PROBE,
            require_initial_count=True,
            count_mode="exact",
            require_retry=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
        )

    def test_get_operation_state_buffer_too_small_preserves_guard(self, p11_config: Any) -> None:
        """C_GetOperationState with one declared byte must preserve adjacent guard bytes."""
        rc, out, err = _run_probe(p11_config, "get_operation_state_buffer_too_small")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_GetOperationState undersized output buffer guard",
            require_initial_count=True,
            count_mode="exact",
            require_retry=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
        )
