"""Shared helpers for CKR subprocess probes."""

from __future__ import annotations

import re

from pkcs11_check.classification import (
    Classification,
    derive_verdict,
    fail_as,
    raise_for_record,
    record,
)
from pkcs11_check.raw.rv import ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import _CK_ULONG_MAX, CKR_OK
from pkcs11_check.testcases._probes.honeypot import SETUP_XFAIL_PREFIX
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed

_SETUP_XFAIL_PREFIX = SETUP_XFAIL_PREFIX  # single source: the probe-layer sentinel
# A child probe that observed a genuine break (e.g. a wrong-key operation that
# actually produced output) emits BREAK: and the parent hard-fails it.
_BREAK_PREFIX = "BREAK:"
# A child probe that observed a clean, safe deviation (e.g. a module lenient at
# *Init but that still SAFELY refused at the terminal operation, leaving no
# usable operation behind) emits DEVIATION_XFAIL: and the parent records it as
# an xfail -- a noted deviation, not a hard failure.
_DEVIATION_XFAIL_PREFIX = "DEVIATION_XFAIL:"
# SETUP_REFUSED payload grammar (issue #28, hardened F1): "<Op>:0x<rv>" with a
# bare C_ entry-point name, shared with the buffer family
# (test_ckr_raw_buffer delegates here). Anything else is a malformed marker,
# never an xfail.
_SETUP_REFUSED_PREFIX = "SETUP_REFUSED:"
_SETUP_REFUSED_OP_RE = re.compile(r"C_[A-Za-z0-9_]+")


def parse_setup_refused_payload(payload: str) -> tuple[str, int] | None:
    """Parse a SETUP_REFUSED payload into ``(setup_op, setup_rv)``.

    Returns None for every malformed shape: empty/garbage payloads, extra
    delimiters, non-identifier ops, a refusal reporting CKR_OK (a refusal
    that succeeded contradicts itself), and unrepresentable CK_RVs.
    """
    parts = payload.split(":")
    if len(parts) != 2:
        return None
    setup_op, rv_text = parts
    if _SETUP_REFUSED_OP_RE.fullmatch(setup_op) is None:
        return None
    try:
        setup_rv = int(rv_text, 0)
    except ValueError:
        return None
    if not 0 < setup_rv <= _CK_ULONG_MAX:
        return None
    return setup_op, setup_rv


def setup_refused_record(context: str, setup_op: str, setup_rv: int) -> Classification:
    """Build the structured record for a validated setup refusal.

    The record names the exact refusing setup operation + CKR against the
    valid setup contract (CKR_OK) and marks the guarded target unreached, so
    report grouping attributes the outcome to the setup call, never the
    untested target. A standard or vendor-defined refusal keeps the
    not_operational xfail bucket (same as SETUP_XFAIL -- a clean refusal of
    valid setup is advertised-but-not-operational). An RV that is neither
    standard nor vendor-defined breaks the return-value contract itself:
    it records as a self_contradiction/metadata FAIL with the exact
    operation/RV and target_reached preserved (P4), never an xfail.
    Malformed marker syntax stays harness_error in the callers.
    """
    if is_standard_ckr(setup_rv) or is_vendor_defined_ckr(setup_rv):
        reason, kind = "not_operational", None
        summary = f"{context}: setup {setup_op} refused with {ckr_name(setup_rv)} (target untested)"
    else:
        reason, kind = "self_contradiction", "metadata"
        summary = (
            f"{context}: setup {setup_op} refused with undefined "
            f"{ckr_name(setup_rv)} (return-value contract violation; target untested)"
        )
    outcome, severity = derive_verdict(reason, kind)
    return Classification(
        reason=reason,
        outcome=outcome,
        severity=severity,
        kind=kind,
        label=context,
        operation=setup_op,
        expected_ckr=[ckr_name(int(CKR_OK))],
        actual_ckr=ckr_name(setup_rv),
        summary=summary,
        detail={
            "protocol_marker": "SETUP_REFUSED",
            "setup_operation": setup_op,
            "setup_rv": setup_rv,
            "target_reached": False,
        },
    )


def assert_ckr_subprocess_ok(
    rc: int,
    stdout: str,
    stderr: str,
    *,
    context: str,
) -> None:
    """Classify CKR child-process results without hiding provider crashes."""
    lines = stdout.splitlines()
    semantic: list[Classification] = []
    malformed_marker: str | None = None
    refused_malformed = False
    for line in lines:
        if line.startswith(_SETUP_XFAIL_PREFIX):
            reason = "not_operational"
            kind = None
            prefix = _SETUP_XFAIL_PREFIX
        elif line.startswith(_SETUP_REFUSED_PREFIX):
            prefix = _SETUP_REFUSED_PREFIX
            payload = line.removeprefix(prefix).strip()
            parsed = parse_setup_refused_payload(payload) if payload else None
            if parsed is None:
                refused_malformed = True
                continue
            setup_op, setup_rv = parsed
            semantic.append(setup_refused_record(context, setup_op, setup_rv))
            continue
        elif line.startswith(_BREAK_PREFIX):
            reason = "self_contradiction"
            kind = "crypto"
            prefix = _BREAK_PREFIX
        elif line.startswith(_DEVIATION_XFAIL_PREFIX):
            reason = "honest_deviation"
            kind = None
            prefix = _DEVIATION_XFAIL_PREFIX
        else:
            continue
        payload = line.removeprefix(prefix).strip()
        if not payload:
            if malformed_marker is None:
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

    # Record every semantic observation before process disposition can terminate the
    # wrapper. This preserves an earlier setup/deviation finding when a later child
    # crash or harness error is the strongest outcome.
    for classification in semantic:
        record(classification)

    complete = any(line == "OK" or line.startswith("OK:") for line in lines)
    termination, explicit_harness = assert_subprocess_completed(rc, stdout, stderr, context=context)
    malformed: Classification | None = None
    if malformed_marker is not None:
        malformed = Classification(
            reason="harness_error",
            outcome="fail",
            severity="HIGH",
            label=context,
            summary=f"{context}: malformed {malformed_marker} marker: empty payload",
            detail={
                "probe_incomplete": True,
                "protocol": "malformed_marker",
                "marker": malformed_marker,
                "termination": termination,
            },
        )
        record(malformed)

    if explicit_harness:
        # An explicit cleanup marker is a terminal harness disposition. The caller owns
        # parsing any CKR measurement that preceded it, so do not synthesize a second
        # missing-OK harness record or terminate on a valid semantic observation. A
        # separate malformed marker is retained above when the child emitted both.
        return

    if malformed is not None and not semantic:
        raise_for_record(malformed)

    refused_records = [
        classification
        for classification in semantic
        if classification.detail is not None
        and classification.detail.get("protocol_marker") == "SETUP_REFUSED"
    ]
    has_provider_fail = any(
        classification.reason == "self_contradiction" for classification in semantic
    )
    other_terminal = [
        classification
        for classification in semantic
        if classification.detail is not None
        and classification.detail.get("protocol_marker") not in (None, "SETUP_REFUSED")
        and classification.reason != "self_contradiction"
    ]
    has_measurement = any(line.startswith("CKR:0x") for line in lines)
    if refused_records and (
        len(refused_records) > 1 or other_terminal or complete or has_measurement
    ):
        # A refused setup is a single terminal fact -- real emitters print exactly
        # one marker per probe run. Duplicates, a refusal beside target
        # measurement/OK, or a refusal beside any other terminal marker are a
        # broken wire protocol, never an xfail. Legacy-only transcripts keep
        # their historical leniency (this rule needs a validated refusal). A
        # parsed provider FAIL still raises first (fail-before-malformed below),
        # so this cannot mask evidence.
        refused_malformed = True
    if refused_malformed and not has_provider_fail:
        refusal_malformed = Classification(
            reason="harness_error",
            outcome="fail",
            severity="HIGH",
            label=context,
            summary=f"{context}: malformed SETUP_REFUSED marker",
            detail={
                "probe_incomplete": True,
                "protocol": "malformed_marker",
                "marker": "SETUP_REFUSED",
                "termination": termination,
            },
        )
        record(refusal_malformed)
        raise_for_record(refusal_malformed)

    if malformed is not None and refused_records and not has_provider_fail:
        # A validated refusal must not override a malformed legacy terminal
        # marker: empty SETUP_XFAIL:/DEVIATION_XFAIL:/BREAK: payloads never
        # reach `other_terminal`, so the contradiction rule above cannot see
        # them. A parsed provider FAIL still raises first
        # (fail-before-malformed), so this cannot mask evidence. Legacy-only
        # transcripts keep their historical leniency (this rule needs a
        # validated refusal).
        raise_for_record(malformed)

    if semantic:
        strongest = next(
            (
                classification
                for classification in semantic
                if classification.reason == "self_contradiction"
            ),
            None,
        )
        if strongest is None:
            strongest = next(
                (
                    classification
                    for classification in semantic
                    if classification.reason == "honest_deviation"
                ),
                semantic[0],
            )
        raise_for_record(strongest)

    if not complete:
        # A CKR child with neither a semantic terminal marker nor an exact completion
        # marker delivered no trustworthy protocol result. Attribution is unresolved --
        # the missing line is as likely a module observation as our own bug -- so this
        # stays a loud provider-side fail, never a provider crash finding and never an
        # inferred harness defect (classification.py: HARNESS_REASONS is positive-claim
        # only).
        fail_as(
            "probe_incomplete",
            label=context,
            summary=(
                f"{context}: child subprocess did not emit an OK marker "
                "(terminal marker missing); "
                f"stdout: {stdout[-300:]}; stderr: {stderr[-300:]}"
            ),
            detail={
                "probe_incomplete": True,
                "protocol": "missing_terminal_marker",
                "termination": termination,
            },
        )
