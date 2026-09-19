"""Shared helpers for CKR subprocess probes."""

from __future__ import annotations

from pkcs11_check.classification import (
    Classification,
    derive_verdict,
    fail_as,
    raise_for_record,
    record,
)
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
    for line in lines:
        if line.startswith(_SETUP_XFAIL_PREFIX):
            reason = "not_operational"
            kind = None
            prefix = _SETUP_XFAIL_PREFIX
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
