"""Stateful generic HashML/HashSLH contract and legacy probes.

The corrected family modules retain the hot shared-session positive paths.  This
file owns the small, stateful negative/lifecycle probes so every operation starts
with a function-scoped raw session and cannot contaminate a later positive case.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest

from pkcs11_check import classification
from pkcs11_check.compliance import ComplianceLevel
from pkcs11_check.compliance import note as compliance_note
from pkcs11_check.raw.pack_mechanisms import mech_hash_sign_context
from pkcs11_check.raw.recipes import destroy_quietly, sign_multipart, sign_single, verify_single
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CKM,
    CKM_HASH_ML_DSA,
    CKM_HASH_ML_DSA_SHA256,
    CKM_HASH_SLH_DSA,
    CKM_HASH_SLH_DSA_SHA256,
    CKM_SHA3_256,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512,
    CKR_DATA_LEN_RANGE,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
)
from pkcs11_check.testcases import test_hash_ml_dsa as ml
from pkcs11_check.testcases import test_hash_slh_dsa as slh
from pkcs11_check.testcases.mechanism_helpers import run_legacy_null_parameter_sequence

pytestmark = [pytest.mark.pqc]


@dataclass(frozen=True)
class _Family:
    label: str
    generic_name: str
    generic_mech: CKM
    suffix_name: str
    suffix_mech: CKM
    keygen_name: str
    keygen: Callable[[Any], tuple[int, int]]
    message: bytes
    sign_error_ckrs: tuple[int, ...]


_FAMILIES = (
    _Family(
        label="ML-DSA",
        generic_name="HASH_ML_DSA",
        generic_mech=CKM_HASH_ML_DSA,
        suffix_name="HASH_ML_DSA_SHA256",
        suffix_mech=CKM_HASH_ML_DSA_SHA256,
        keygen_name="ML_DSA_KEY_PAIR_GEN",
        keygen=ml._generate_ml_dsa_keypair,
        message=ml._MESSAGE,
        sign_error_ckrs=ml._SIGN_ERROR_CKRS,
    ),
    _Family(
        label="SLH-DSA",
        generic_name="HASH_SLH_DSA",
        generic_mech=CKM_HASH_SLH_DSA,
        suffix_name="HASH_SLH_DSA_SHA256",
        suffix_mech=CKM_HASH_SLH_DSA_SHA256,
        keygen_name="SLH_DSA_KEY_PAIR_GEN",
        keygen=slh._generate_slh_dsa_keypair,
        message=slh._MESSAGE,
        sign_error_ckrs=slh._SIGN_ERROR_CKRS,
    ),
)

_CHAINS = ("roundtrip-44", "tamper-25", "multipart-136", "streaming-96")
_HASHES = (
    ("SHA-256", CKM_SHA256),
    ("SHA-384", CKM_SHA384),
    ("SHA-512", CKM_SHA512),
    ("SHA3-256", CKM_SHA3_256),
)
_WRONG_LENGTH_CASES = tuple(
    (family, hash_name, hash_mech)
    for family in _FAMILIES
    for hash_name, hash_mech in (_HASHES if family.label == "ML-DSA" else _HASHES[:1])
)
_LEGACY_PHASES = {
    "roundtrip-44": (
        "C_SignInit",
        "C_Sign",
        "C_Sign",
        "C_VerifyInit",
        "C_Verify",
    ),
    "tamper-25": (
        "C_SignInit",
        "C_Sign",
        "C_Sign",
        "C_VerifyInit",
        "C_Verify",
    ),
    "multipart-136": (
        "C_SignInit",
        *("C_SignUpdate",) * 4,
        "C_SignFinal",
        "C_SignFinal",
        "C_VerifyInit",
        *("C_VerifyUpdate",) * 4,
        "C_VerifyFinal",
    ),
    "streaming-96": (
        "C_SignInit",
        "C_Sign",
        "C_Sign",
        "C_SignInit",
        *("C_SignUpdate",) * 3,
        "C_SignFinal",
        "C_SignFinal",
        "C_VerifyInit",
        "C_VerifyUpdate",
        "C_VerifyFinal",
        "C_VerifyInit",
        *("C_VerifyUpdate",) * 3,
        "C_VerifyFinal",
    ),
}


def _skip_if_no(rs: Any, family: _Family, *, suffix: bool = False) -> None:
    name = family.suffix_name if suffix else family.generic_name
    if not rs.has_mechanism(name):
        pytest.skip(f"CKM_{name} not supported by module")
    if not rs.has_mechanism(family.keygen_name):
        pytest.skip(f"CKM_{family.keygen_name} not supported by module")


def _last_trace(raw: Any, *phases: str) -> dict[str, Any]:
    """Return the last bounded trace entry for one of the named phases."""
    entries = getattr(raw, "rv_trace", [])
    wanted = set(phases)
    for entry in reversed(entries):
        if not phases or entry.get("fn") in wanted:
            return {key: entry.get(key) for key in ("i", "fn", "rv", "rv_name") if key in entry}
    return {}


def _chain_detail(family: _Family, chain: str) -> dict[str, Any]:
    if chain == "roundtrip-44":
        payload = b"hello pkcs11 sign test" * 2
        return {
            "family": family.label,
            "chain": chain,
            "parameter": "NULL",
            "payload_hex": payload.hex(),
            "payload_len": len(payload),
            "verify_payload_hex": payload.hex(),
            "verify_payload_len": len(payload),
            "chunk_lengths": [],
        }
    if chain == "tamper-25":
        payload = b"original data for signing"
        changed = b"tampered data XXXXXXXXXXX"
        return {
            "family": family.label,
            "chain": chain,
            "parameter": "NULL",
            "payload_hex": payload.hex(),
            "payload_len": len(payload),
            "verify_payload_hex": changed.hex(),
            "verify_payload_len": len(changed),
            "chunk_lengths": [],
        }
    if chain == "multipart-136":
        payload = b"multipart signing test input data " * 4
        size = len(payload) // 4
        chunks = [
            payload[:size],
            payload[size : 2 * size],
            payload[2 * size : 3 * size],
            payload[3 * size :],
        ]
        return {
            "family": family.label,
            "chain": chain,
            "parameter": "NULL",
            "payload_hex": payload.hex(),
            "payload_len": len(payload),
            "verify_payload_hex": payload.hex(),
            "verify_payload_len": len(payload),
            "chunk_lengths": [len(chunk) for chunk in chunks],
        }
    if chain == "streaming-96":
        payload = b"multipart sign equivalence test " * 3
        size = len(payload) // 3
        chunks = [payload[:size], payload[size : 2 * size], payload[2 * size :]]
        return {
            "family": family.label,
            "chain": chain,
            "parameter": "NULL",
            "payload_hex": payload.hex(),
            "payload_len": len(payload),
            "verify_payload_hex": payload.hex(),
            "verify_payload_len": len(payload),
            "chunk_lengths": [len(chunk) for chunk in chunks],
        }
    raise ValueError(f"unknown legacy chain {chain!r}")


def _append_trace(detail: dict[str, Any], raw: Any, *phases: str) -> dict[str, Any]:
    trace = _last_trace(raw, *phases)
    if trace:
        detail["last_trace"] = trace
        detail["reached_phase"] = trace.get("fn")
        detail["actual_rv"] = trace.get("rv_name", trace.get("rv"))
    return trace


def _phase_progress(detail: dict[str, Any], raw: Any, planned: tuple[str, ...]) -> None:
    """Keep the bounded actual RV sequence and conditional calls not reached."""
    wanted = set(planned)
    observed = [
        {"phase": entry["fn"], "rv": entry.get("rv"), "rv_name": entry.get("rv_name")}
        for entry in getattr(raw, "rv_trace", [])
        if entry.get("fn") in wanted
    ]
    names = [entry["phase"] for entry in observed]
    detail["reached_phases"] = observed
    if names == list(planned[: len(names)]):
        detail["unreached_phases"] = list(planned[len(names) :])
    else:
        detail["unreached_phases"] = "indeterminate (observed order differs from call plan)"
        detail["planned_phases"] = list(planned)


def _refusal_phase(
    raw: Any,
    exc: CkrAssertionError,
    detail: dict[str, Any],
    *,
    phases: tuple[str, ...],
    label: str,
    mechanism: str,
) -> tuple[str | None, classification.Classification | None]:
    """A typed RV is attributable only when the last relevant raw call agrees."""
    trace = _append_trace(detail, raw, *phases)
    detail["exception_rv"] = ckr_name(int(exc.rv))
    if trace.get("fn") in phases and trace.get("rv") == int(exc.rv):
        return str(trace["fn"]), None
    detail["phase_evidence"] = "missing or inconsistent RV trace"
    record = classification.record_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation="unknown",
        mechanism=mechanism,
        actual=int(exc.rv),
        detail=detail,
    )
    return None, record


def _cleanup(rs: Any, pub: int, priv: int, detail: dict[str, Any]) -> None:
    cleanup = detail.setdefault("cleanup", {"public": "not_attempted", "private": "not_attempted"})
    cleanup["public"] = "attempted_unconfirmed"
    try:
        destroy_quietly(rs.raw, rs.sh, pub)
    except BaseException:
        cleanup["public"] = "best_effort_call_raised_unconfirmed"
        raise
    else:
        cleanup["public"] = "best_effort_call_returned_unconfirmed"
    finally:
        cleanup["private"] = "attempted_unconfirmed"
        try:
            destroy_quietly(rs.raw, rs.sh, priv)
        except BaseException:
            cleanup["private"] = "best_effort_call_raised_unconfirmed"
            raise
        else:
            cleanup["private"] = "best_effort_call_returned_unconfirmed"


def _record_clean_refusal(
    exc: CkrAssertionError,
    *,
    label: str,
    family: _Family,
    detail: dict[str, Any],
    expected: tuple[int, ...] = (),
    operation: str = "C_SignInit",
    standard_reason: str = "not_operational",
    mechanism_name: str | None = None,
) -> classification.Classification:
    rv = int(exc.rv)
    detail["actual_rv"] = ckr_name(rv)
    if is_vendor_defined_ckr(rv):
        reason = "nonspec_reject"
        kind = None
    elif is_standard_ckr(rv):
        reason = standard_reason if rv in family.sign_error_ckrs else "honest_deviation"
        kind = None
    else:
        reason = "self_contradiction"
        kind = "metadata"
    return classification.record_as(
        reason,
        kind=kind,
        label=label,
        operation=operation,
        mechanism=f"CKM_{mechanism_name or family.generic_name}",
        expected=expected or None,
        actual=rv,
        detail=detail,
    )


def _record_expected_reject(
    exc: CkrAssertionError | None,
    *,
    label: str,
    family: _Family,
    detail: dict[str, Any],
    expected: tuple[int, ...],
    operation: str,
    phase: str | None,
) -> classification.Classification | None:
    if exc is None:
        return classification.record_as(
            "accepted_invalid",
            label=label,
            operation=operation,
            mechanism=f"CKM_{family.generic_name}",
            expected=expected,
            actual="CKR_OK",
            detail=detail,
        )
    if not isinstance(exc, CkrAssertionError):
        raise exc
    rv = int(exc.rv)
    detail["actual_rv"] = ckr_name(rv)
    if phase == operation and rv in expected:
        return None
    return _record_clean_refusal(
        exc,
        label=label,
        family=family,
        detail=detail,
        expected=expected,
        operation=phase or "unknown",
    )


def _legacy_record(
    family: _Family,
    chain: str,
    detail: dict[str, Any],
    *,
    rv: int | None,
    phase: str | None,
) -> classification.Classification | None:
    if phase == "C_SignInit" and rv is not None and rv == int(CKR_MECHANISM_PARAM_INVALID):
        return None
    if rv is None:
        return classification.record_as(
            "self_contradiction",
            kind="metadata",
            label=f"CKM_{family.generic_name} legacy {chain} missing phase evidence",
            operation="C_SignInit",
            mechanism=f"CKM_{family.generic_name}",
            detail=detail,
        )
    return _record_clean_refusal(
        CkrAssertionError(f"legacy {chain}: {ckr_name(rv)}", rv),
        label=f"CKM_{family.generic_name} legacy {chain} later rejection",
        family=family,
        detail=detail,
        expected=(int(CKR_MECHANISM_PARAM_INVALID),),
        operation=phase or "C_SignInit",
        standard_reason="honest_deviation",
    )


@pytest.mark.parametrize("family", _FAMILIES, ids=lambda family: family.label)
@pytest.mark.parametrize("chain", _CHAINS)
def test_legacy_registry_null_parameter_chain(
    p11_raw_session: Any, family: _Family, chain: str
) -> None:
    """Preserve each old NULL-parameter chain with phase-sensitive evidence."""
    rs = p11_raw_session
    _skip_if_no(rs, family)
    pub, priv = family.keygen(rs)
    detail = _chain_detail(family, chain)
    terminal: classification.Classification | None = None
    try:
        rs.raw.enable_rv_trace()
        try:
            result = run_legacy_null_parameter_sequence(
                rs.raw, rs.sh, priv, pub, family.generic_mech, chain
            )
        except CkrAssertionError as exc:
            progress = getattr(exc, "_pkcs11_legacy_progress", [])
            detail["completed_events"] = [
                {
                    key: event.get(key)
                    for key in ("phase", "effect", "rv", "verified")
                    if key in event
                }
                for event in progress
            ]
            completed_sign = any(event.get("phase", "").startswith("C_Sign") for event in progress)
            if completed_sign:
                _append_trace(detail, rs.raw, *_LEGACY_PHASES[chain])
                detail["exception_rv"] = ckr_name(int(exc.rv))
                terminal = classification.record_as(
                    "accepted_invalid",
                    label=f"CKM_{family.generic_name} legacy {chain} accepted NULL parameters",
                    operation="C_Sign",
                    mechanism=f"CKM_{family.generic_name}",
                    expected=(int(CKR_MECHANISM_PARAM_INVALID),),
                    actual="CKR_OK",
                    detail=detail,
                )
            else:
                phase, phase_error = _refusal_phase(
                    rs.raw,
                    exc,
                    detail,
                    phases=_LEGACY_PHASES[chain],
                    label=f"CKM_{family.generic_name} legacy {chain} missing phase evidence",
                    mechanism=f"CKM_{family.generic_name}",
                )
                terminal = phase_error or _legacy_record(
                    family, chain, detail, rv=int(exc.rv), phase=phase
                )
        else:
            detail["completed_events"] = [
                {
                    key: event.get(key)
                    for key in ("phase", "effect", "rv", "verified")
                    if key in event
                }
                for event in result.get("events", [])
            ]
            if any(
                event.get("phase", "").startswith("C_Sign") for event in result.get("events", [])
            ):
                terminal = classification.record_as(
                    "accepted_invalid",
                    label=f"CKM_{family.generic_name} legacy {chain} accepted NULL parameters",
                    operation="C_Sign",
                    mechanism=f"CKM_{family.generic_name}",
                    expected=(int(CKR_MECHANISM_PARAM_INVALID),),
                    actual="CKR_OK",
                    detail=detail,
                )
            else:
                terminal = classification.record_as(
                    "self_contradiction",
                    kind="metadata",
                    label=f"CKM_{family.generic_name} legacy {chain} missing Sign evidence",
                    operation="C_SignInit",
                    mechanism=f"CKM_{family.generic_name}",
                    detail=detail,
                )
        _phase_progress(detail, rs.raw, _LEGACY_PHASES[chain])
    finally:
        _cleanup(rs, pub, priv, detail)
    if terminal is None:
        compliance_note(
            f"CKM_{family.generic_name} legacy {chain}: phase=C_SignInit; "
            f"rv={ckr_name(int(CKR_MECHANISM_PARAM_INVALID))}; exact={detail}",
            ComplianceLevel.STANDARD,
        )
    if terminal is not None:
        classification.raise_for_record(terminal)


@pytest.mark.parametrize("family", _FAMILIES, ids=lambda family: family.label)
def test_generic_valid_parameter_rejects_multipart(p11_raw_session: Any, family: _Family) -> None:
    """A valid generic parameter must not silently complete multipart Sign."""
    rs = p11_raw_session
    _skip_if_no(rs, family)
    pub, priv = family.keygen(rs)
    digest = hashlib.sha256(family.message).digest()
    chunks = [digest[:16], digest[16:]]
    detail: dict[str, Any] = {
        "family": family.label,
        "payload_hex": digest.hex(),
        "payload_len": len(digest),
        "chunk_lengths": [len(chunk) for chunk in chunks],
        "parameter": "CK_HASH_SIGN_ADDITIONAL_CONTEXT(SHA-256)",
    }
    terminal: classification.Classification | None = None
    standard_rejection: tuple[str, int] | None = None
    planned = ("C_SignInit", "C_SignUpdate", "C_SignUpdate", "C_SignFinal", "C_SignFinal")
    try:
        rs.raw.enable_rv_trace()
        try:
            signature = sign_multipart(
                rs.raw,
                rs.sh,
                priv,
                family.generic_mech,
                chunks,
                mech_param=mech_hash_sign_context(family.generic_mech, hash_mech=CKM_SHA256),
            )
        except CkrAssertionError as exc:
            phase, phase_error = _refusal_phase(
                rs.raw,
                exc,
                detail,
                phases=planned,
                label=f"CKM_{family.generic_name} valid-param multipart missing phase evidence",
                mechanism=f"CKM_{family.generic_name}",
            )
            if phase_error is not None:
                terminal = phase_error
            elif phase in {"C_SignUpdate", "C_SignFinal"} and is_standard_ckr(exc.rv):
                standard_rejection = (phase, int(exc.rv))
            else:
                terminal = _record_clean_refusal(
                    exc,
                    label=f"CKM_{family.generic_name} valid-param multipart {phase}",
                    family=family,
                    detail=detail,
                    operation=phase or "unknown",
                )
        else:
            detail.update({"reached_phase": "C_SignFinal", "signature_len": len(signature)})
            terminal = classification.record_as(
                "accepted_invalid",
                label=f"CKM_{family.generic_name} valid parameters reached multipart Final",
                operation="C_SignFinal",
                mechanism=f"CKM_{family.generic_name}",
                actual="CKR_OK",
                detail=detail,
            )
        _phase_progress(detail, rs.raw, planned)
    finally:
        _cleanup(rs, pub, priv, detail)
    if standard_rejection is not None:
        phase, rv = standard_rejection
        compliance_note(
            f"CKM_{family.generic_name} valid-parameter multipart rejected at "
            f"{phase} with {ckr_name(rv)}; evidence={detail}",
            ComplianceLevel.STANDARD,
        )
    if terminal is not None:
        classification.raise_for_record(terminal)


@pytest.mark.parametrize(
    ("family", "hash_name", "hash_mech"),
    _WRONG_LENGTH_CASES,
    ids=lambda value: value.label if isinstance(value, _Family) else str(value),
)
def test_wrong_length_sign_rejects_original_message(
    p11_raw_session: Any, family: _Family, hash_name: str, hash_mech: CKM
) -> None:
    """The preserved raw message is invalid for generic prehash Sign."""
    rs = p11_raw_session
    _skip_if_no(rs, family)
    pub, priv = family.keygen(rs)
    detail: dict[str, Any] = {
        "family": family.label,
        "hash": hash_name,
        "payload_hex": family.message.hex(),
        "payload_len": len(family.message),
        "parameter": f"CK_HASH_SIGN_ADDITIONAL_CONTEXT({hash_name})",
    }
    terminal: classification.Classification | None = None
    planned = ("C_SignInit", "C_Sign", "C_Sign")
    try:
        rs.raw.enable_rv_trace()
        try:
            signature = sign_single(
                rs.raw,
                rs.sh,
                priv,
                family.generic_mech,
                family.message,
                mech_param=mech_hash_sign_context(family.generic_mech, hash_mech=hash_mech),
            )
        except CkrAssertionError as exc:
            phase, phase_error = _refusal_phase(
                rs.raw,
                exc,
                detail,
                phases=planned,
                label=f"CKM_{family.generic_name} wrong-length Sign missing phase evidence",
                mechanism=f"CKM_{family.generic_name}",
            )
            terminal = phase_error or _record_expected_reject(
                exc,
                label=f"CKM_{family.generic_name} wrong-length Sign ({hash_name})",
                family=family,
                detail=detail,
                expected=(int(CKR_DATA_LEN_RANGE),),
                operation="C_Sign",
                phase=phase,
            )
        else:
            detail["signature_len"] = len(signature)
            terminal = _record_expected_reject(
                None,
                label=f"CKM_{family.generic_name} wrong-length Sign ({hash_name})",
                family=family,
                detail=detail,
                expected=(int(CKR_DATA_LEN_RANGE),),
                operation="C_Sign",
                phase="C_Sign",
            )
        _phase_progress(detail, rs.raw, planned)
    finally:
        _cleanup(rs, pub, priv, detail)
    if terminal is None:
        compliance_note(
            f"CKM_{family.generic_name} wrong-length Sign ({hash_name}): "
            f"phase=C_Sign; rv={ckr_name(int(CKR_DATA_LEN_RANGE))}; evidence={detail}",
            ComplianceLevel.STANDARD,
        )
    if terminal is not None:
        classification.raise_for_record(terminal)


@pytest.mark.parametrize("family", _FAMILIES, ids=lambda family: family.label)
def test_changed_input_verify_does_not_verify(p11_raw_session: Any, family: _Family) -> None:
    """A valid generic signature must not verify against the old raw message."""
    rs = p11_raw_session
    _skip_if_no(rs, family)
    pub, priv = family.keygen(rs)
    digest = hashlib.sha256(family.message).digest()
    param = mech_hash_sign_context(family.generic_mech, hash_mech=CKM_SHA256)
    detail: dict[str, Any] = {
        "family": family.label,
        "signed_payload_hex": digest.hex(),
        "signed_payload_len": len(digest),
        "original_verify_payload_hex": digest.hex(),
        "original_verify_payload_len": len(digest),
        "verify_payload_hex": family.message.hex(),
        "verify_payload_len": len(family.message),
        "original_verified": "unreached",
        "changed_verified": "unreached",
        "changed_input_target_reached": False,
    }
    terminal: classification.Classification | None = None
    planned = (
        "C_SignInit",
        "C_Sign",
        "C_Sign",
        "C_VerifyInit",
        "C_Verify",
        "C_VerifyInit",
        "C_Verify",
    )
    try:
        rs.raw.enable_rv_trace()
        try:
            signature = sign_single(
                rs.raw, rs.sh, priv, family.generic_mech, digest, mech_param=param
            )
            detail["signature_len"] = len(signature)
            original_verified = verify_single(
                rs.raw, rs.sh, pub, family.generic_mech, digest, signature, mech_param=param
            )
            detail["original_verified"] = original_verified
            original_trace = _append_trace(detail, rs.raw, "C_Verify")
            detail["original_verify_rv"] = original_trace.get("rv_name")
            if not original_verified:
                terminal = classification.record_as(
                    "wrong_result",
                    kind="crypto",
                    label=f"CKM_{family.generic_name} freshly signed digest failed Verify",
                    operation="C_Verify",
                    mechanism=f"CKM_{family.generic_name}",
                    actual=original_trace.get("rv"),
                    detail=detail,
                )
            elif sum(
                entry.get("fn") == "C_Verify" for entry in rs.raw.rv_trace
            ) != 1 or original_trace.get("rv") != int(CKR_OK):
                terminal = classification.record_as(
                    "self_contradiction",
                    kind="metadata",
                    label=f"CKM_{family.generic_name} missing original Verify effect trace",
                    operation="unknown",
                    mechanism=f"CKM_{family.generic_name}",
                    detail=detail,
                )
            else:
                changed_verified = verify_single(
                    rs.raw,
                    rs.sh,
                    pub,
                    family.generic_mech,
                    family.message,
                    signature,
                    mech_param=param,
                )
                detail["changed_verified"] = changed_verified
                changed_trace = _append_trace(detail, rs.raw, "C_Verify")
                verify_count = sum(entry.get("fn") == "C_Verify" for entry in rs.raw.rv_trace)
                detail["changed_verify_rv"] = (
                    changed_trace.get("rv_name") if verify_count == 2 else None
                )
                if changed_verified:
                    terminal = classification.record_as(
                        "wrong_result",
                        kind="crypto",
                        label=f"CKM_{family.generic_name} changed input verified",
                        operation="C_Verify",
                        mechanism=f"CKM_{family.generic_name}",
                        actual=changed_trace.get("rv"),
                        detail=detail,
                    )
                elif verify_count != 2 or changed_trace.get("rv") not in {
                    int(CKR_SIGNATURE_INVALID),
                    int(CKR_SIGNATURE_LEN_RANGE),
                }:
                    terminal = classification.record_as(
                        "self_contradiction",
                        kind="metadata",
                        label=(
                            f"CKM_{family.generic_name} changed-input missing Verify effect trace"
                        ),
                        operation="unknown",
                        mechanism=f"CKM_{family.generic_name}",
                        detail=detail,
                    )
                elif changed_trace["rv"] == int(CKR_SIGNATURE_LEN_RANGE):
                    terminal = classification.record_as(
                        "honest_deviation",
                        label=(
                            f"CKM_{family.generic_name} valid signature rejected by length "
                            "on changed input"
                        ),
                        operation="C_Verify",
                        mechanism=f"CKM_{family.generic_name}",
                        expected=(int(CKR_SIGNATURE_INVALID),),
                        actual=int(CKR_SIGNATURE_LEN_RANGE),
                        detail=detail,
                    )
        except CkrAssertionError as exc:
            phase, phase_error = _refusal_phase(
                rs.raw,
                exc,
                detail,
                phases=planned,
                label=f"CKM_{family.generic_name} changed-input missing phase evidence",
                mechanism=f"CKM_{family.generic_name}",
            )
            terminal = phase_error or _record_clean_refusal(
                exc,
                label=f"CKM_{family.generic_name} changed-input positive refusal at {phase}",
                family=family,
                detail=detail,
                operation=phase or "unknown",
            )
        _phase_progress(detail, rs.raw, planned)
        detail["changed_input_target_reached"] = (
            sum(entry["phase"] == "C_Verify" for entry in detail["reached_phases"]) == 2
        )
        if terminal is None and detail["unreached_phases"]:
            terminal = classification.record_as(
                "self_contradiction",
                kind="metadata",
                label=f"CKM_{family.generic_name} incomplete changed-input phase trace",
                operation="unknown",
                mechanism=f"CKM_{family.generic_name}",
                detail=detail,
            )
    finally:
        _cleanup(rs, pub, priv, detail)
    if terminal is None:
        compliance_note(
            f"CKM_{family.generic_name} original digest verified with "
            f"{detail['original_verify_rv']}; changed-input rejection: "
            f"phase=C_Verify; rv={detail['changed_verify_rv']}; evidence={detail}",
            ComplianceLevel.STANDARD,
        )
    if terminal is not None:
        classification.raise_for_record(terminal)


@pytest.mark.parametrize("family", _FAMILIES, ids=lambda family: family.label)
def test_generic_and_hash_suffix_cross_verify(p11_raw_session: Any, family: _Family) -> None:
    """Generic and fixed-SHA-256 mechanisms cross-verify on one key."""
    rs = p11_raw_session
    _skip_if_no(rs, family)
    _skip_if_no(rs, family, suffix=True)
    pub, priv = family.keygen(rs)
    digest = hashlib.sha256(family.message).digest()
    param = mech_hash_sign_context(family.generic_mech, hash_mech=CKM_SHA256)
    detail: dict[str, Any] = {
        "family": family.label,
        "generic_payload_hex": digest.hex(),
        "generic_payload_len": len(digest),
        "suffix_payload_hex": family.message.hex(),
        "suffix_payload_len": len(family.message),
        "bidirectional": True,
    }
    terminal: classification.Classification | None = None
    planned = (
        "C_SignInit",
        "C_Sign",
        "C_Sign",
        "C_VerifyInit",
        "C_Verify",
        "C_SignInit",
        "C_Sign",
        "C_Sign",
        "C_VerifyInit",
        "C_Verify",
    )
    active_mechanism = family.generic_name
    detail["generic_to_suffix"] = "unreached"
    detail["suffix_to_generic"] = "unreached"
    try:
        rs.raw.enable_rv_trace()
        try:
            generic_signature = sign_single(
                rs.raw, rs.sh, priv, family.generic_mech, digest, mech_param=param
            )
            detail["generic_signature_len"] = len(generic_signature)
            active_mechanism = family.suffix_name
            generic_verified = verify_single(
                rs.raw, rs.sh, pub, family.suffix_mech, family.message, generic_signature
            )
            detail["generic_to_suffix"] = generic_verified
            if not generic_verified:
                terminal = classification.record_as(
                    "wrong_result",
                    kind="crypto",
                    label=f"CKM_{family.generic_name} signature rejected by fixed hash variant",
                    operation="C_Verify",
                    mechanism=f"CKM_{family.suffix_name}",
                    detail=detail,
                )
            else:
                suffix_signature = sign_single(
                    rs.raw, rs.sh, priv, family.suffix_mech, family.message
                )
                detail["suffix_signature_len"] = len(suffix_signature)
                active_mechanism = family.generic_name
                suffix_verified = verify_single(
                    rs.raw,
                    rs.sh,
                    pub,
                    family.generic_mech,
                    digest,
                    suffix_signature,
                    mech_param=param,
                )
                detail["suffix_to_generic"] = suffix_verified
                if not suffix_verified:
                    terminal = classification.record_as(
                        "wrong_result",
                        kind="crypto",
                        label=(
                            f"CKM_{family.suffix_name} signature rejected by generic hash variant"
                        ),
                        operation="C_Verify",
                        mechanism=f"CKM_{family.generic_name}",
                        detail=detail,
                    )
        except CkrAssertionError as exc:
            phase, phase_error = _refusal_phase(
                rs.raw,
                exc,
                detail,
                phases=planned,
                label=f"CKM_{family.generic_name}/{family.suffix_name} cross-verify missing phase",
                mechanism=f"CKM_{active_mechanism}",
            )
            terminal = phase_error or _record_clean_refusal(
                exc,
                label=f"CKM_{family.generic_name}/{family.suffix_name} positive refusal at {phase}",
                family=family,
                detail=detail,
                operation=phase or "unknown",
                mechanism_name=active_mechanism,
            )
        _phase_progress(detail, rs.raw, planned)
        if terminal is None:
            trace = _append_trace(detail, rs.raw, "C_Verify")
            if (
                len(detail["reached_phases"]) != len(planned)
                or detail["unreached_phases"]
                or trace.get("rv") != int(CKR_OK)
            ):
                terminal = classification.record_as(
                    "self_contradiction",
                    kind="metadata",
                    label=f"CKM_{family.generic_name}/{family.suffix_name} incomplete cross trace",
                    operation="unknown",
                    mechanism=f"CKM_{family.generic_name}",
                    detail=detail,
                )
    finally:
        _cleanup(rs, pub, priv, detail)
    if terminal is None:
        compliance_note(
            f"CKM_{family.generic_name}/{family.suffix_name} bidirectional cross-verify: "
            f"generic_to_suffix=True; suffix_to_generic=True; evidence={detail}",
            ComplianceLevel.STANDARD,
        )
    if terminal is not None:
        classification.raise_for_record(terminal)
