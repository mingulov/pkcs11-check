"""Crash-safe RSA malformed-input probes with outcome and protocol validation."""

from __future__ import annotations

import ctypes
import json
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKA_MODULUS,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_OK,
    CKR_PENDING,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import (
    SUBPROCESS_TIMEOUT_MARKER,
    pin_from_config,
)
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed

pytestmark = [pytest.mark.security, pytest.mark.subprocess]

_SCHEMA = 1
_NATIVE_CKR_MAX = (1 << (ctypes.sizeof(CK_ULONG) * 8)) - 1
_MARKERS = ("RSA_ATTRIBUTE:", "RSA_RV:", "RSA_DONE:")
_EXPECTED_ATTR_KEYS = {"schema", "case", "operation", "attribute", "state"}
_EXPECTED_RV_KEYS = {"schema", "case", "stage", "operation", "mechanism", "rv"}
_EXPECTED_DONE_KEYS = {"schema", "case", "status"}
_EXPECTED_STAGES = {
    "keygen",
    "attribute_read",
    "decrypt_init",
    "decrypt",
    "sign_setup",
    "sign",
    "verify_baseline_init",
    "verify_baseline",
    "verify_init",
    "verify",
}
_EXPECTED_DONE_STATUSES = {
    "complete",
    "omitted",
    "malformed",
    "setup_refused",
    "oracle_disabled",
}


# Child protocol codes that report ABSENCE (a required marker never arrived) rather
# than a malformed or contradictory emission. Attribution there is unresolved, so
# these stay loud provider-side fails instead of inferred harness defects
# (classification.py: HARNESS_REASONS is positive-claim only).
_ABSENT_PROTOCOL_CODES = frozenset({"missing_attribute", "missing_done"})


def _protocol_error(label: str, code: str, summary: str) -> C.Classification:
    reason = "probe_incomplete" if code in _ABSENT_PROTOCOL_CODES else "harness_error"
    outcome, severity = C.derive_verdict(reason, None)
    shape = "incomplete" if code in _ABSENT_PROTOCOL_CODES else "malformed"
    return C.Classification(
        reason=reason,
        outcome=outcome,
        severity=severity,
        label=label,
        summary=f"{label}: {shape} RSA child protocol ({code}): {summary}",
        detail={"protocol": code, "probe_incomplete": True},
    )


def _strict_json(payload: str) -> dict[str, Any]:
    """Decode an object while rejecting duplicate JSON keys."""

    def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key {key!r}")
            result[key] = value
        return result

    value = json.loads(payload, object_pairs_hook=_reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError("payload is not an object")
    return value


def _validate_common(payload: dict[str, Any], *, expected_keys: set[str], case_id: str) -> None:
    if set(payload) != expected_keys:
        raise ValueError("schema fields/cardinality do not match")
    if type(payload.get("schema")) is not int or payload["schema"] != _SCHEMA:
        raise ValueError("unsupported schema")
    if type(payload.get("case")) is not str or payload["case"] != case_id:
        raise ValueError("case does not match selected probe")


def _parse_attribute(line: str, *, case_id: str) -> dict[str, Any]:
    payload = _strict_json(line.removeprefix("RSA_ATTRIBUTE:"))
    if payload.get("operation") != "C_GetAttributeValue":
        raise ValueError("attribute operation does not match C_GetAttributeValue")
    descriptor = payload.get("attribute")
    if not isinstance(descriptor, dict) or set(descriptor) != {"name", "id"}:
        raise ValueError("attribute descriptor does not match CKA_MODULUS")
    if (
        descriptor.get("name") != "CKA_MODULUS"
        or type(descriptor.get("id")) is not int
        or descriptor["id"] != int(CKA_MODULUS)
    ):
        raise ValueError("attribute descriptor does not match CKA_MODULUS")
    state = payload.get("state")
    if not isinstance(state, str):
        raise ValueError("attribute state is not a string")
    if state == "missing":
        keys = _EXPECTED_ATTR_KEYS
    elif state == "present":
        keys = _EXPECTED_ATTR_KEYS | {"value_len", "modulus_bits"}
    elif state == "malformed":
        keys = _EXPECTED_ATTR_KEYS | {"value_type", "value_repr"}
        if "value_len" in payload or "modulus_bits" in payload:
            keys |= {"value_len", "modulus_bits"}
    elif state == "inconsistent":
        keys = _EXPECTED_ATTR_KEYS | {"value_len", "modulus_bits", "expected_bits"}
    else:
        raise ValueError("invalid attribute state")
    _validate_common(payload, expected_keys=keys, case_id=case_id)
    if state in {"present", "inconsistent"}:
        if type(payload.get("value_len")) is not int or payload["value_len"] <= 0:
            raise ValueError("attribute value_len is not positive")
        if type(payload.get("modulus_bits")) is not int or payload["modulus_bits"] <= 0:
            raise ValueError("attribute modulus_bits is not positive")
    if state == "malformed" and ("value_len" in payload or "modulus_bits" in payload):
        if type(payload.get("value_len")) is not int or payload["value_len"] < 0:
            raise ValueError("malformed attribute value_len is invalid")
        if type(payload.get("modulus_bits")) is not int or payload["modulus_bits"] < 0:
            raise ValueError("malformed attribute modulus_bits is invalid")
    if state == "inconsistent" and (
        type(payload.get("expected_bits")) is not int or payload["expected_bits"] <= 0
    ):
        raise ValueError("attribute expected_bits is not positive")
    if state == "malformed":
        if not (
            isinstance(payload.get("value_type"), str)
            and 0 < len(payload["value_type"]) <= 64
            and isinstance(payload.get("value_repr"), str)
            and 0 < len(payload["value_repr"]) <= 256
        ):
            raise ValueError("malformed attribute evidence is unbounded or missing")
    return payload


def _parse_rv(line: str, *, case_id: str, mechanism: str) -> dict[str, Any]:
    payload = _strict_json(line.removeprefix("RSA_RV:"))
    stage = payload.get("stage")
    if not isinstance(stage, str) or stage not in _EXPECTED_STAGES:
        raise ValueError("invalid RSA_RV stage")
    allowed_stages = (
        {"keygen", "attribute_read", "decrypt_init", "decrypt"}
        if case_id.startswith("decrypt:")
        else {
            "keygen",
            "sign_setup",
            "sign",
            "verify_baseline_init",
            "verify_baseline",
            "verify_init",
            "verify",
        }
    )
    if stage not in allowed_stages:
        raise ValueError("RSA_RV stage does not belong to selected case")
    keys = _EXPECTED_RV_KEYS | ({"value_len"} if stage == "sign" else set())
    _validate_common(payload, expected_keys=keys, case_id=case_id)
    expected_mechanism = "CKM_RSA_PKCS_KEY_PAIR_GEN" if stage == "keygen" else mechanism
    if not isinstance(payload.get("mechanism"), str) or payload["mechanism"] != expected_mechanism:
        raise ValueError("mechanism does not match selected probe")
    expected_operation: dict[str, str | None] = {
        "keygen": "C_GenerateKeyPair",
        "attribute_read": "C_GetAttributeValue",
        "decrypt_init": "C_DecryptInit",
        "decrypt": "C_Decrypt",
        "sign_setup": None,
        "sign": "C_Sign",
        "verify_baseline_init": "C_VerifyInit",
        "verify_baseline": "C_Verify",
        "verify_init": "C_VerifyInit",
        "verify": "C_Verify",
    }
    if payload.get("operation") != expected_operation[stage]:
        raise ValueError("operation does not match RSA_RV stage")
    rv = payload.get("rv")
    if type(rv) is not int or not 0 <= rv <= _NATIVE_CKR_MAX:
        raise ValueError("rv is not a native-width CK_RV")
    if stage == "sign" and (type(payload.get("value_len")) is not int or payload["value_len"] < 0):
        raise ValueError("signature length is invalid")
    return payload


def _parse_done(line: str, *, case_id: str) -> dict[str, Any]:
    payload = _strict_json(line.removeprefix("RSA_DONE:"))
    _validate_common(payload, expected_keys=_EXPECTED_DONE_KEYS, case_id=case_id)
    if (
        not isinstance(payload.get("status"), str)
        or payload["status"] not in _EXPECTED_DONE_STATUSES
    ):
        raise ValueError("invalid RSA_DONE status")
    return payload


def _malformed_rv_affects_mutation_oracle(line: str, *, case_id: str) -> bool:
    """Classify a malformed RSA_RV marker without trusting a duplicate's last value."""
    if not case_id.startswith("verify:"):
        return False
    try:
        pairs = json.loads(
            line.removeprefix("RSA_RV:"),
            object_pairs_hook=lambda items: items,
        )
    except (ValueError, json.JSONDecodeError):
        return True
    if not isinstance(pairs, list) or any(
        not isinstance(item, tuple) or len(item) != 2 or not isinstance(item[0], str)
        for item in pairs
    ):
        return True
    keys = [item[0] for item in pairs]
    if len(keys) != len(set(keys)):
        return True
    stages = [item[1] for item in pairs if item[0] == "stage"]
    if len(stages) != 1 or not isinstance(stages[0], str):
        return True
    return stages[0] not in {"keygen", "sign_setup"}


def _is_defined_ckr(rv: int) -> bool:
    return is_standard_ckr(rv) or is_vendor_defined_ckr(rv)


def _record_rv(
    payload: dict[str, Any],
    *,
    label: str,
    mechanism: str,
    expected_rvs: tuple[int, ...],
    baseline_verified: bool = True,
) -> C.Classification | None:
    stage = payload["stage"]
    rv = payload["rv"]
    operation = payload["operation"]
    item_mechanism = payload["mechanism"]
    detail = {"protocol": "rsa_rv", "stage": stage, "case": payload["case"]}

    if stage in {"keygen", "attribute_read"}:
        if rv == int(CKR_OK) or not _is_defined_ckr(rv):
            return C.record_as(
                "wrong_result",
                kind="metadata",
                label=label,
                operation=operation,
                mechanism=item_mechanism,
                expected=(CKR_OK,),
                actual=rv,
                summary=(
                    f"{label}: {operation} reported an invalid caught CK_RV {rv:#x}"
                    if rv == int(CKR_OK)
                    else f"{label}: {operation} reported undefined CK_RV {rv:#x}"
                ),
                detail=detail,
            )
        return C.record_as(
            "not_operational",
            label=label,
            operation=operation,
            mechanism=item_mechanism,
            expected=(CKR_OK,),
            actual=rv,
            summary=f"{label}: {operation} is not operational ({ckr_name(rv)})",
            detail=detail,
        )

    if stage == "sign" and rv == int(CKR_OK) and payload["value_len"] == 0:
        return C.record_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation="C_Sign",
            mechanism=item_mechanism,
            expected=(CKR_OK,),
            actual=rv,
            summary=f"{label}: empty signature was reported as successful",
            detail={**detail, "value_len": 0},
        )
    if stage == "sign_setup":
        if rv == int(CKR_OK):
            return C.record_as(
                "wrong_result",
                kind="metadata",
                label=label,
                operation=None,
                mechanism=item_mechanism,
                expected=(CKR_OK,),
                actual=rv,
                summary=f"{label}: sign setup reported CKR_OK as a caught failure",
                detail=detail,
            )
        if not _is_defined_ckr(rv):
            return C.record_as(
                "wrong_result",
                kind="metadata",
                label=label,
                operation=None,
                mechanism=mechanism,
                expected=(CKR_OK,),
                actual=rv,
                summary=f"{label}: sign setup reported undefined CK_RV {rv:#x}",
                detail=detail,
            )
        return C.record_as(
            "not_operational",
            label=label,
            operation=None,
            mechanism=item_mechanism,
            expected=(CKR_OK,),
            actual=rv,
            summary=f"{label}: signing setup is not operational ({ckr_name(rv)})",
            detail=detail,
        )
    if stage in {"decrypt_init", "verify_init"}:
        if rv == int(CKR_OK):
            return None
        if not _is_defined_ckr(rv):
            return C.record_as(
                "wrong_result",
                kind="metadata",
                label=label,
                operation=operation,
                mechanism=item_mechanism,
                expected=(CKR_OK,),
                actual=rv,
                summary=f"{label}: initialization reported undefined CK_RV {rv:#x}",
                detail=detail,
            )
        return C.record_as(
            "not_operational",
            label=label,
            operation=operation,
            mechanism=item_mechanism,
            expected=(CKR_OK,),
            actual=rv,
            summary=f"{label}: {operation} is not operational ({ckr_name(rv)})",
            detail=detail,
        )
    if stage == "verify_baseline_init":
        if rv == int(CKR_OK):
            return None
        if rv == int(CKR_PENDING):
            return C.record_as(
                "honest_deviation",
                label=label,
                operation=operation,
                mechanism=item_mechanism,
                expected=(CKR_OK,),
                actual=rv,
                summary="baseline C_VerifyInit returned CKR_PENDING; mutation oracle disabled",
                detail={**detail, "terminal": False, "oracle_disabled": True},
            )
        if not _is_defined_ckr(rv):
            return C.record_as(
                "wrong_result",
                kind="metadata",
                label=label,
                operation=operation,
                mechanism=item_mechanism,
                expected=(CKR_OK,),
                actual=rv,
                summary=f"{label}: baseline C_VerifyInit reported undefined CK_RV {rv:#x}",
                detail=detail,
            )
        return C.record_as(
            "not_operational",
            label=label,
            operation=operation,
            mechanism=item_mechanism,
            expected=(CKR_OK,),
            actual=rv,
            summary=f"{label}: baseline C_VerifyInit is not operational ({ckr_name(rv)})",
            detail={**detail, "oracle_disabled": True},
        )
    if stage == "verify_baseline":
        if rv == int(CKR_OK):
            return None
        if rv == int(CKR_PENDING):
            return C.record_as(
                "honest_deviation",
                label=label,
                operation=operation,
                mechanism=item_mechanism,
                expected=(CKR_OK,),
                actual=rv,
                summary="baseline C_Verify returned CKR_PENDING; mutation oracle disabled",
                detail={**detail, "terminal": False, "oracle_disabled": True},
            )
        if not _is_defined_ckr(rv):
            return C.record_as(
                "wrong_result",
                kind="metadata",
                label=label,
                operation=operation,
                mechanism=item_mechanism,
                expected=(CKR_OK,),
                actual=rv,
                summary=f"{label}: baseline C_Verify reported undefined CK_RV {rv:#x}",
                detail=detail,
            )
        if rv in (int(CKR_SIGNATURE_INVALID), int(CKR_SIGNATURE_LEN_RANGE)):
            return C.record_as(
                "wrong_result",
                kind="crypto",
                label=label,
                operation=operation,
                mechanism=item_mechanism,
                expected=(CKR_OK,),
                actual=rv,
                summary=(
                    f"{label}: provider rejected its own successful signature during baseline "
                    f"C_Verify ({ckr_name(rv)})"
                ),
                detail={**detail, "baseline_verified": False},
            )
        return C.record_as(
            "not_operational",
            label=label,
            operation=operation,
            mechanism=item_mechanism,
            expected=(CKR_OK,),
            actual=rv,
            summary=(
                f"{label}: baseline C_Verify is not operational ({ckr_name(rv)}); "
                "mutation oracle disabled"
            ),
            detail={**detail, "oracle_disabled": True},
        )
    if stage == "sign":
        if rv == int(CKR_OK):
            return None
        if not _is_defined_ckr(rv):
            return C.record_as(
                "wrong_result",
                kind="metadata",
                label=label,
                operation=operation,
                mechanism=mechanism,
                expected=(CKR_OK,),
                actual=rv,
                summary=f"{label}: C_Sign reported undefined CK_RV {rv:#x}",
                detail=detail,
            )
        return C.record_as(
            "not_operational",
            label=label,
            operation=operation,
            mechanism=item_mechanism,
            expected=(CKR_OK,),
            actual=rv,
            summary=f"{label}: C_Sign is not operational ({ckr_name(rv)})",
            detail=detail,
        )
    if stage == "verify" and not baseline_verified and rv != int(CKR_OK):
        if rv == int(CKR_PENDING):
            return C.record_as(
                "honest_deviation",
                label=label,
                operation=operation,
                mechanism=item_mechanism,
                expected=expected_rvs,
                actual=rv,
                summary=(
                    f"{label}: corrupted-signature outcome is not attributable because "
                    "baseline verification did not establish the oracle"
                ),
                detail={**detail, "oracle_disabled": True, "baseline_verified": False},
            )
        if _is_defined_ckr(rv):
            return C.record_as(
                "honest_deviation",
                label=label,
                operation=operation,
                mechanism=item_mechanism,
                expected=expected_rvs,
                actual=rv,
                summary=(
                    f"{label}: corrupted-signature CK_RV is not attributable because "
                    "baseline verification did not establish the oracle"
                ),
                detail={**detail, "oracle_disabled": True, "baseline_verified": False},
            )
    if rv == int(CKR_OK):
        if stage == "verify" and not baseline_verified:
            return C.record_as(
                "honest_deviation",
                label=label,
                operation=operation,
                mechanism=item_mechanism,
                expected=expected_rvs,
                actual=rv,
                summary=(
                    f"{label}: corrupted-signature outcome is not attributable because "
                    "baseline verification did not establish the oracle"
                ),
                detail={**detail, "oracle_disabled": True, "baseline_verified": False},
            )
        if stage == "decrypt" and item_mechanism == "CKM_RSA_PKCS":
            # RSA PKCS#1 v1.5 implicit rejection: the Bleichenbacher/Marvin-attack
            # countermeasure implemented by OpenSSL >= 3.2 and NSS by design. On a
            # padding failure the implementation returns CKR_OK with a deterministic
            # pseudo-random plaintext instead of an error CKR, precisely so the
            # caller cannot use the return code as a padding oracle. This probe only
            # observes the CK_RV protocol trace (no returned plaintext), so it
            # cannot prove genuine forgery acceptance versus the countermeasure --
            # the observation is real and worth keeping, but it must not be branded
            # a CRITICAL crypto break for behavior that is a conformant defense.
            return C.record_as(
                "honest_deviation",
                label=label,
                operation=operation,
                mechanism=item_mechanism,
                expected=expected_rvs,
                actual=rv,
                summary=(
                    f"{label}: returned CKR_OK for malformed RSA PKCS#1 v1.5 "
                    "ciphertext; consistent with an implicit-rejection countermeasure "
                    "(OpenSSL >= 3.2 / NSS), not distinguishable from genuine "
                    "acceptance without the returned plaintext"
                ),
                detail={**detail, "implicit_rejection_suspected": True},
            )
        return C.record_as(
            "accepted_invalid",
            kind="crypto",
            label=label,
            operation=operation,
            mechanism=item_mechanism,
            expected=expected_rvs,
            actual=rv,
            summary=f"{label}: accepted invalid RSA input with CKR_OK",
            detail=detail,
        )
    if rv == int(CKR_PENDING):
        return C.record_as(
            "honest_deviation",
            label=label,
            operation=operation,
            mechanism=item_mechanism,
            expected=expected_rvs,
            actual=rv,
            summary=f"{label}: provider returned CKR_PENDING; no terminal rejection observed",
            detail={**detail, "terminal": False},
        )
    if not _is_defined_ckr(rv):
        return C.record_as(
            "wrong_result",
            kind="metadata",
            label=label,
            operation=operation,
            mechanism=item_mechanism,
            expected=expected_rvs,
            actual=rv,
            summary=f"{label}: operation reported undefined CK_RV {rv:#x}",
            detail=detail,
        )
    if rv in expected_rvs:
        if stage == "verify" and not baseline_verified:
            return C.record_as(
                "honest_deviation",
                label=label,
                operation=operation,
                mechanism=item_mechanism,
                expected=expected_rvs,
                actual=rv,
                summary=(
                    f"{label}: corrupted-signature rejection is not attributable because "
                    "baseline verification did not establish the oracle"
                ),
                detail={**detail, "oracle_disabled": True, "baseline_verified": False},
            )
        return None
    return C.record_as(
        "nonspec_reject",
        label=label,
        operation=operation,
        mechanism=item_mechanism,
        expected=expected_rvs,
        actual=rv,
        summary=f"{label}: operation rejected invalid RSA input with {ckr_name(rv)}",
        detail=detail,
    )


def _raise_strongest(records: list[C.Classification]) -> None:
    for reason in ("wrong_result", "accepted_invalid", "self_contradiction", "crash"):
        item = next((record for record in records if record.reason == reason), None)
        if item is not None:
            C.raise_for_record(item)
    item = next((record for record in records if record.outcome == "fail"), None)
    if item is not None:
        C.raise_for_record(item)
    item = next((record for record in records if record.outcome == "xfail"), None)
    if item is not None:
        C.raise_for_record(item)


def _measurement_summary(
    attrs: list[dict[str, Any]], rvs: list[dict[str, Any]], dones: list[dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    """Return a bounded, JSON-safe summary for a later crash/timeout record."""
    return {
        "attributes": [
            {
                "state": item["state"],
                **{name: item[name] for name in ("value_len", "modulus_bits") if name in item},
            }
            for item in attrs[:8]
        ],
        "rvs": [
            {
                "stage": item["stage"],
                "operation": item["operation"],
                "mechanism": item["mechanism"],
                "rv": item["rv"],
                **({"value_len": item["value_len"]} if "value_len" in item else {}),
            }
            for item in rvs[:8]
        ],
        "done": [{"status": item["status"]} for item in dones[:1]],
    }


def _allowed_stage_order(case_id: str) -> tuple[str, ...]:
    if case_id.startswith("decrypt:"):
        return ("keygen", "attribute_read", "decrypt_init", "decrypt")
    return (
        "keygen",
        "sign_setup",
        "sign",
        "verify_baseline_init",
        "verify_baseline",
        "verify_init",
        "verify",
    )


def _valid_interrupted_stage_prefix(case_id: str, stages: list[str]) -> bool:
    """Allow a crash to omit only the tail of a valid child stage sequence."""
    candidates: tuple[tuple[str, ...], ...]
    if case_id.startswith("decrypt:"):
        candidates = (
            ("keygen",),
            ("attribute_read",),
            ("decrypt_init", "decrypt"),
        )
    else:
        candidates = (
            ("keygen",),
            ("sign_setup",),
            ("sign", "verify_baseline_init", "verify_baseline", "verify_init", "verify"),
            ("sign", "verify_baseline_init", "verify_init", "verify"),
        )
    return any(candidate[: len(stages)] == tuple(stages) for candidate in candidates)


def _transition_errors(case_id: str, rvs: list[dict[str, Any]]) -> list[str]:
    """Return impossible provider-observation transitions, including crash paths."""
    by_stage = {item["stage"]: item for item in rvs}
    stages = [item["stage"] for item in rvs]
    errors: list[str] = []
    if case_id.startswith("decrypt:"):
        for terminal in ("keygen", "attribute_read"):
            if terminal in by_stage and len(stages) > 1:
                errors.append(f"{terminal} refusal cannot be followed by another RSA stage")
        init = by_stage.get("decrypt_init")
        if init is not None and init["rv"] != int(CKR_OK) and "decrypt" in by_stage:
            errors.append("decrypt_init refusal cannot be followed by decrypt")
        return errors
    for terminal in ("keygen", "sign_setup"):
        if terminal in by_stage and len(stages) > 1:
            errors.append(f"{terminal} refusal cannot be followed by another RSA stage")
    sign = by_stage.get("sign")
    if (
        sign is not None
        and (sign["rv"] != int(CKR_OK) or sign.get("value_len", 0) == 0)
        and any(stage.startswith("verify_") or stage == "verify" for stage in stages)
    ):
        errors.append("sign failure/empty signature cannot be followed by verification")
    baseline_init = by_stage.get("verify_baseline_init")
    if (
        baseline_init is not None
        and baseline_init["rv"] != int(CKR_OK)
        and "verify_baseline" in by_stage
    ):
        errors.append("baseline-init refusal cannot be followed by baseline verification")
    verify_init = by_stage.get("verify_init")
    if verify_init is not None and verify_init["rv"] != int(CKR_OK) and "verify" in by_stage:
        errors.append("verify-init refusal cannot be followed by verify")
    return errors


def _check_protocol(
    rc: int,
    stdout: str,
    stderr: str,
    *,
    case_id: str,
    mechanism: str,
    operation: str,
    expected_rvs: tuple[int, ...],
    requires_attribute: bool,
) -> None:
    """Parse independent RSA observations, then apply process disposition."""
    label = f"{case_id} {operation}"
    attrs: list[dict[str, Any]] = []
    rvs: list[dict[str, Any]] = []
    dones: list[dict[str, Any]] = []
    sequence: list[tuple[str, dict[str, Any]]] = []
    protocol_records: list[C.Classification] = []
    setup_lines: list[str] = []
    unknown_rsa_lines: list[str] = []
    lineage_marker_parse_error = False

    for line in stdout.splitlines():
        if line.startswith("SETUP_XFAIL:"):
            setup_lines.append(line)
            continue
        marker = next((prefix for prefix in _MARKERS if line.startswith(prefix)), None)
        if marker is None:
            if line.startswith("RSA_"):
                unknown_rsa_lines.append(line)
            continue
        try:
            if marker == "RSA_ATTRIBUTE:":
                item = _parse_attribute(line, case_id=case_id)
                attrs.append(item)
                sequence.append(("attribute", item))
            elif marker == "RSA_RV:":
                item = _parse_rv(line, case_id=case_id, mechanism=mechanism)
                rvs.append(item)
                sequence.append(("rv", item))
            else:
                item = _parse_done(line, case_id=case_id)
                dones.append(item)
                sequence.append(("done", item))
        except (ValueError, json.JSONDecodeError) as exc:
            if marker == "RSA_RV:" and _malformed_rv_affects_mutation_oracle(line, case_id=case_id):
                lineage_marker_parse_error = True
            protocol_records.append(
                _protocol_error(label, "malformed_marker", f"{marker[:-1]}: {exc}")
            )

    if unknown_rsa_lines:
        protocol_records.append(
            _protocol_error(label, "unknown_marker", "unknown RSA protocol marker")
        )
    if len(setup_lines) > 1:
        protocol_records.append(_protocol_error(label, "duplicate_setup", "duplicate setup marker"))
    if setup_lines and (attrs or rvs or dones):
        protocol_records.append(
            _protocol_error(label, "mixed_terminal_markers", "setup and RSA markers were mixed")
        )
    if not requires_attribute and attrs:
        protocol_records.append(
            _protocol_error(label, "unexpected_attribute", "RSA_ATTRIBUTE is not valid for verify")
        )
    if len(attrs) > 1:
        protocol_records.append(
            _protocol_error(label, "duplicate_attribute", "duplicate RSA_ATTRIBUTE")
        )
    if len(dones) > 1:
        protocol_records.append(_protocol_error(label, "duplicate_done", "duplicate RSA_DONE"))
    stage_counts: dict[str, int] = {}
    for item in rvs:
        stage_counts[item["stage"]] = stage_counts.get(item["stage"], 0) + 1
    duplicate_stages = {stage for stage, count in stage_counts.items() if count > 1}
    if duplicate_stages:
        protocol_records.append(
            _protocol_error(
                label, "duplicate_rv", f"duplicate RSA_RV stage(s): {sorted(duplicate_stages)}"
            )
        )
    if ({"keygen", "attribute_read"} & {item["stage"] for item in rvs}) and attrs:
        protocol_records.append(
            _protocol_error(
                label,
                "terminal_setup_attribute",
                "terminal keygen/attribute_read branch must not emit RSA_ATTRIBUTE",
            )
        )

    if any(kind == "done" for kind, _ in sequence) and sequence[-1][0] != "done":
        protocol_records.append(
            _protocol_error(label, "marker_after_done", "RSA_DONE must be the final child marker")
        )
    if any(kind == "rv" for kind, _ in sequence) and any(
        kind == "attribute" for kind, _ in sequence
    ):
        first_rv = next(index for index, (kind, _) in enumerate(sequence) if kind == "rv")
        last_attr = max(index for index, (kind, _) in enumerate(sequence) if kind == "attribute")
        if last_attr > first_rv:
            protocol_records.append(
                _protocol_error(label, "marker_order", "RSA_ATTRIBUTE must precede RSA_RV")
            )
    unique_stages = [item["stage"] for item in rvs if item["stage"] not in duplicate_stages]
    stage_order = _allowed_stage_order(case_id)
    stage_positions = [stage_order.index(stage) for stage in unique_stages]
    if stage_positions != sorted(stage_positions):
        protocol_records.append(
            _protocol_error(
                label,
                "stage_order",
                f"RSA_RV stages are out of order: {unique_stages}",
            )
        )
    if "sign_setup" in unique_stages and len(unique_stages) != 1:
        protocol_records.append(
            _protocol_error(label, "stage_order", "sign_setup must be terminal")
        )
    for transition in _transition_errors(case_id, rvs):
        protocol_records.append(_protocol_error(label, "stage_transition", transition))

    termination_kind: str = "exit"
    if rc != 0 or SUBPROCESS_TIMEOUT_MARKER in stderr:
        from pkcs11_check.core.process_observation import termination_from_returncode

        termination = termination_from_returncode(
            rc,
            timed_out=SUBPROCESS_TIMEOUT_MARKER in stderr,
            stderr=stderr,
        )
        termination_kind = str(termination["kind"])
    interrupted = termination_kind in {"signal", "exception", "timeout"}
    attr_state_for_transition = attrs[0].get("state") if len(attrs) == 1 else None
    if (
        requires_attribute
        and attr_state_for_transition in {"missing", "malformed", "inconsistent"}
        and any(item["stage"] in {"decrypt_init", "decrypt"} for item in rvs)
    ):
        protocol_records.append(
            _protocol_error(
                label,
                "attribute_terminality",
                "missing/malformed/inconsistent modulus cannot be followed by decrypt stages",
            )
        )
    if (
        interrupted
        and unique_stages
        and not _valid_interrupted_stage_prefix(case_id, unique_stages)
    ):
        protocol_records.append(
            _protocol_error(
                label,
                "stage_order",
                f"RSA_RV stages are not a valid interrupted prefix: {unique_stages}",
            )
        )

    if not setup_lines and (not interrupted or len(dones) > 0):
        marker_seen = any(line.startswith("RSA_ATTRIBUTE:") for line in stdout.splitlines())
        terminal_setup_stage = bool({"keygen", "attribute_read"} & set(unique_stages))
        if requires_attribute and len(attrs) == 0 and not marker_seen and not terminal_setup_stage:
            protocol_records.append(
                _protocol_error(label, "missing_attribute", "RSA_ATTRIBUTE is required")
            )
        if len(dones) == 0:
            protocol_records.append(_protocol_error(label, "missing_done", "RSA_DONE is required"))

        attr_state_for_shape = attrs[0].get("state") if len(attrs) == 1 else None
        expected_stages: list[str]
        if "keygen" in unique_stages:
            expected_stages = ["keygen"]
            expected_status = "setup_refused"
        elif "attribute_read" in unique_stages:
            expected_stages = ["attribute_read"]
            expected_status = "oracle_disabled"
        elif requires_attribute and attr_state_for_shape == "missing":
            expected_stages = []
            init = next((item for item in rvs if item["stage"] == "decrypt_init"), None)
            if init is not None:
                expected_stages.append("decrypt_init")
                if init["rv"] == int(CKR_OK):
                    expected_stages.append("decrypt")
            expected_status = "omitted"
        elif requires_attribute and attr_state_for_shape in {"malformed", "inconsistent"}:
            expected_stages = []
            expected_status = "malformed"
        elif requires_attribute and attr_state_for_shape == "present":
            expected_stages = ["decrypt_init"]
            init = next((item for item in rvs if item["stage"] == "decrypt_init"), None)
            if init is not None and init["rv"] == int(CKR_OK):
                expected_stages.append("decrypt")
            expected_status = "complete"
        elif not requires_attribute:
            sign_setup = next((item for item in rvs if item["stage"] == "sign_setup"), None)
            sign = next((item for item in rvs if item["stage"] == "sign"), None)
            baseline_init = next(
                (item for item in rvs if item["stage"] == "verify_baseline_init"), None
            )
            verify_init = next((item for item in rvs if item["stage"] == "verify_init"), None)
            if sign_setup is not None:
                expected_stages = ["sign_setup"]
                expected_status = "setup_refused"
            elif sign is not None:
                expected_stages = ["sign"]
                if sign["rv"] == int(CKR_OK) and sign.get("value_len", 0) > 0:
                    expected_stages.append("verify_baseline_init")
                    if baseline_init is not None and baseline_init["rv"] == int(CKR_OK):
                        expected_stages.append("verify_baseline")
                    expected_stages.append("verify_init")
                    if verify_init is not None and verify_init["rv"] == int(CKR_OK):
                        expected_stages.append("verify")
                expected_status = "malformed" if sign.get("value_len") == 0 else "complete"
            else:
                expected_stages = ["sign"]
                expected_status = "complete"
        else:
            expected_stages = []
            expected_status = "complete"
        actual_stages = unique_stages
        if actual_stages != expected_stages:
            protocol_records.append(
                _protocol_error(
                    label,
                    "wrong_result_cardinality",
                    "stage cardinality: expected RSA stages "
                    f"{expected_stages}, got {actual_stages}",
                )
            )
        if len(dones) == 1 and dones[0]["status"] != expected_status:
            protocol_records.append(
                _protocol_error(
                    label,
                    "done_status",
                    f"expected RSA_DONE status {expected_status!r}, got {dones[0]['status']!r}",
                )
            )

    semantic: list[C.Classification] = []
    attr = attrs[0] if len(attrs) == 1 else None
    attr_state = attr.get("state") if attr is not None else None
    if attr is not None and attr_state == "missing":
        dependent_terminal = [
            {
                "stage": item["stage"],
                "operation": item["operation"],
                "mechanism": item["mechanism"],
                "actual_ckr": ckr_name(item["rv"]),
            }
            for item in rvs
            if item["stage"] == "decrypt" and item["stage"] not in duplicate_stages
        ]
        semantic.append(
            C.record_as(
                "honest_deviation",
                label=label,
                operation="C_GetAttributeValue",
                mechanism=mechanism,
                summary=f"{label}: modulus unavailable; decrypt oracle disabled",
                detail={
                    "protocol": "rsa_attribute",
                    "attribute": "CKA_MODULUS",
                    "state": "missing",
                    "oracle_disabled": True,
                    "dependent_terminal": dependent_terminal,
                },
            )
        )
    elif attr is not None and attr_state in {"malformed", "inconsistent"}:
        semantic.append(
            C.record_as(
                "wrong_result",
                kind="metadata",
                label=label,
                operation="C_GetAttributeValue",
                mechanism=mechanism,
                summary=f"{label}: present RSA modulus metadata is malformed",
                detail={"protocol": "rsa_attribute", **attr},
            )
        )
    elif attr is not None and (attr.get("value_len") != 256 or attr.get("modulus_bits") != 2048):
        semantic.append(
            C.record_as(
                "wrong_result",
                kind="metadata",
                label=label,
                operation="C_GetAttributeValue",
                mechanism=mechanism,
                summary=f"{label}: RSA modulus is inconsistent with requested RSA-2048 key",
                detail={"protocol": "rsa_attribute", **attr},
            )
        )

    # A missing, malformed, or inconsistent modulus disables only the decrypt
    # oracle. Verify cases have no modulus marker and remain independently
    # classified. A malformed or inconsistent attribute is itself a hard
    # metadata finding, but any independently valid operation observation
    # remains useful and must not be discarded.
    baseline_init_ok = [
        item
        for item in rvs
        if item["stage"] == "verify_baseline_init" and item["rv"] == int(CKR_OK)
    ]
    baseline_ok = [
        item for item in rvs if item["stage"] == "verify_baseline" and item["rv"] == int(CKR_OK)
    ]
    sign_ok = [
        item
        for item in rvs
        if item["stage"] == "sign" and item["rv"] == int(CKR_OK) and item.get("value_len", 0) > 0
    ]
    relevant_duplicate = duplicate_stages & {"sign", "verify_baseline_init", "verify_baseline"}
    baseline_sequence_coherent = unique_stages[:3] == [
        "sign",
        "verify_baseline_init",
        "verify_baseline",
    ]
    baseline_verified = (
        not lineage_marker_parse_error
        and not relevant_duplicate
        and baseline_sequence_coherent
        and len(sign_ok) == 1
        and len(baseline_init_ok) == 1
        and len(baseline_ok) == 1
    )
    mutation_init_ok = [
        item for item in rvs if item["stage"] == "verify_init" and item["rv"] == int(CKR_OK)
    ]
    mutation_sequence_coherent = unique_stages[3:] in (
        [],
        ["verify_init"],
        ["verify_init", "verify"],
    )
    mutation_oracle = (
        baseline_verified
        and len(mutation_init_ok) == 1
        and mutation_sequence_coherent
        and not (duplicate_stages & {"verify_init", "verify"})
        and not any(
            "verify-init refusal" in record.summary or "verify-init" in record.summary
            for record in protocol_records
        )
    )
    terminal_attribute_states = {"missing", "malformed", "inconsistent"}
    for item in rvs:
        if item["stage"] in duplicate_stages:
            continue
        # Any terminal modulus state disables only the dependent decrypt oracle,
        # while preserving the actual provider CK_RV as independent evidence.
        if (
            attr_state in terminal_attribute_states
            and item["stage"] == "decrypt"
            and _is_defined_ckr(item["rv"])
        ):
            semantic.append(
                C.record_as(
                    "honest_deviation",
                    label=label,
                    operation=item["operation"],
                    mechanism=item["mechanism"],
                    expected=expected_rvs,
                    actual=item["rv"],
                    summary=(
                        f"{label}: decrypt outcome is not attributable because RSA modulus "
                        f"attribute state is {attr_state}; decrypt oracle disabled"
                    ),
                    detail={
                        "protocol": "rsa_rv",
                        "stage": "decrypt",
                        "case": item["case"],
                        "attribute_state": attr_state,
                        "oracle_disabled": True,
                    },
                )
            )
            continue
        result = _record_rv(
            item,
            label=label,
            mechanism=mechanism,
            expected_rvs=expected_rvs,
            baseline_verified=mutation_oracle,
        )
        if result is not None:
            semantic.append(result)

    setup_record: C.Classification | None = None
    if setup_lines:
        setup_detail = setup_lines[0].removeprefix("SETUP_XFAIL:").strip()
        setup_record = C.record_as(
            "not_operational",
            label=label,
            summary=f"{label}: {setup_detail}",
            detail={"protocol": "setup_xfail"},
        )

    # Collapse several protocol defects from one child into one record; valid
    # observations from other markers remain independent. Absence records
    # (missing_attribute/missing_done) are appended after every emission defect, so a
    # mixed collapse keeps the first -- harness-owned -- reason.
    if len(protocol_records) > 1:
        first = protocol_records[0]
        if first.detail is not None:
            first.detail["protocols"] = [
                item.detail.get("protocol") for item in protocol_records if item.detail is not None
            ]
        protocol_records = [first]

    # Valid provider observations and protocol defects are recorded before the
    # process disposition, so a later crash/timeout cannot erase them.
    for record in protocol_records:
        C.record(record)
    try:
        _, explicit_harness = assert_subprocess_completed(rc, stdout, stderr, context=label)
    except BaseException:
        crash = next(
            (record for record in reversed(C.get_records()) if record.reason == "crash"),
            None,
        )
        if crash is not None:
            crash.detail = {
                **(crash.detail or {}),
                "parsed_measurement": _measurement_summary(attrs, rvs, dones),
            }
        raise

    process_harness = (
        next(
            (record for record in reversed(C.get_records()) if record.reason == "harness_error"),
            None,
        )
        if explicit_harness
        else None
    )

    if setup_lines and not (attrs or rvs or dones):
        assert setup_record is not None
        if process_harness is not None:
            _raise_strongest([process_harness])
        if protocol_records:
            _raise_strongest([setup_record, *protocol_records])
        _raise_strongest([setup_record])
        return

    if process_harness is not None:
        _raise_strongest(
            [
                *semantic,
                *protocol_records,
                *([setup_record] if setup_record else []),
                process_harness,
            ]
        )
    if protocol_records:
        _raise_strongest(semantic + protocol_records + ([setup_record] if setup_record else []))
    if setup_record is not None:
        _raise_strongest(semantic + [setup_record])
    _raise_strongest(semantic)


def _run_decrypt_probe(p11_config: Any, *, mech: str, variant: str, context: str) -> None:
    result = run_probe(
        "error_path_rsa",
        {
            "module_path": str(p11_config.module),
            "slot_id": getattr(p11_config, "slot", None),
            "probe": "decrypt",
            "mech": mech,
            "variant": variant,
        },
        pin=pin_from_config(p11_config),
        timeout=15,
        coverage="session",
    )
    mechanism = "CKM_RSA_PKCS" if mech == "pkcs" else "CKM_RSA_PKCS_OAEP"
    expected = (
        (
            int(CKR_ENCRYPTED_DATA_INVALID),
            int(CKR_ENCRYPTED_DATA_LEN_RANGE),
        )
        if variant in {"truncated", "extended"}
        else (int(CKR_ENCRYPTED_DATA_INVALID),)
    )
    _check_protocol(
        result.returncode,
        result.stdout,
        result.stderr,
        case_id=f"decrypt:{mech}:{variant}",
        mechanism=mechanism,
        operation="C_Decrypt",
        expected_rvs=expected,
        requires_attribute=True,
    )


class TestRsaPkcsDecryptErrorPaths:
    def _run(self, p11_raw_session: Any, p11_config: Any, variant: str) -> None:
        if not p11_raw_session.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")
        _run_decrypt_probe(p11_config, mech="pkcs", variant=variant, context=variant)

    def test_rsa_pkcs_decrypt_random_ciphertext(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        self._run(p11_raw_session, p11_config, "random")

    def test_rsa_pkcs_decrypt_truncated(self, p11_raw_session: Any, p11_config: Any) -> None:
        self._run(p11_raw_session, p11_config, "truncated")

    def test_rsa_pkcs_decrypt_extended(self, p11_raw_session: Any, p11_config: Any) -> None:
        self._run(p11_raw_session, p11_config, "extended")

    def test_rsa_pkcs_decrypt_all_zeros(self, p11_raw_session: Any, p11_config: Any) -> None:
        self._run(p11_raw_session, p11_config, "all_zeros")

    def test_rsa_pkcs_decrypt_all_ff(self, p11_raw_session: Any, p11_config: Any) -> None:
        self._run(p11_raw_session, p11_config, "all_ff")


class TestRsaOaepDecryptErrorPaths:
    def _run(self, p11_raw_session: Any, p11_config: Any, variant: str) -> None:
        if not p11_raw_session.has_mechanism("RSA_PKCS_OAEP"):
            pytest.skip("CKM_RSA_PKCS_OAEP not supported")
        _run_decrypt_probe(p11_config, mech="oaep", variant=variant, context=variant)

    def test_rsa_oaep_decrypt_random_ciphertext(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        self._run(p11_raw_session, p11_config, "random")

    def test_rsa_oaep_decrypt_truncated(self, p11_raw_session: Any, p11_config: Any) -> None:
        self._run(p11_raw_session, p11_config, "truncated")


class TestRsaVerifyCorruptedSignature:
    def test_rsa_verify_corrupted_signature(self, p11_raw_session: Any, p11_config: Any) -> None:
        if not p11_raw_session.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")
        result = run_probe(
            "error_path_rsa",
            {
                "module_path": str(p11_config.module),
                "slot_id": getattr(p11_config, "slot", None),
                "probe": "verify",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        _check_protocol(
            result.returncode,
            result.stdout,
            result.stderr,
            case_id="verify:sha256_rsa_pkcs:bitflip",
            mechanism="CKM_SHA256_RSA_PKCS",
            operation="C_Verify",
            expected_rvs=(int(CKR_SIGNATURE_INVALID),),
            requires_attribute=False,
        )
