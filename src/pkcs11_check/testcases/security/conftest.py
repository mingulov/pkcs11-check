"""Shared helpers for security vulnerability tests.

CKR error code sets for classifying module responses to malformed inputs.
Subprocess wrapper for crash-safe test execution.
"""

from __future__ import annotations

from pkcs11_check.classification import fail_as, raise_for_record, record_as, xfail_as
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_DATA_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_SESSION_HANDLE_INVALID,
    CKR_WRAPPED_KEY_INVALID,
    CKR_WRAPPED_KEY_LEN_RANGE,
)
from pkcs11_check.testcases._probes._emit import (
    PROVIDER_FINDING_MARKER,
    parse_provider_finding,
)
from pkcs11_check.testcases._probes.honeypot import SETUP_XFAIL_PREFIX
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed

# Clean rejection of boundary/invalid inputs (not crash, not OK)
BOUNDARY_REJECT_CKRS = {
    CKR_ARGUMENTS_BAD,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_SESSION_HANDLE_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_DEVICE_ERROR,
}

# Clean rejection of bad ciphertext/wrapped data
DATA_REJECT_CKRS = {
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_WRAPPED_KEY_INVALID,
    CKR_WRAPPED_KEY_LEN_RANGE,
    CKR_DATA_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_GENERAL_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_DEVICE_ERROR,
    CKR_ARGUMENTS_BAD,
}

# CKR names for subprocess output parsing
BOUNDARY_REJECT_NAMES = frozenset(ckr_name(int(c)) for c in BOUNDARY_REJECT_CKRS)
DATA_REJECT_NAMES = frozenset(ckr_name(int(c)) for c in DATA_REJECT_CKRS)
# SETUP_XFAIL_PREFIX (the parent<->child sentinel) is imported from the probe layer above,
# so this conftest's scanners use the single canonical definition rather than a local copy.


def assert_subprocess_no_crash(
    rc: int,
    stdout: str,
    stderr: str,
    *,
    context: str,
) -> None:
    """Assert a subprocess completed without crashing or child-script failure.

    Args:
        rc: subprocess returncode. Negative means killed by signal; positive
            means the child script failed before completing the probe.
        stdout: subprocess stdout.
        stderr: subprocess stderr.
        context: Human-readable test description for failure message.
    """
    assert_subprocess_completed(rc, stdout, stderr, context=context)
    for line in stdout.splitlines():
        if line.startswith(SETUP_XFAIL_PREFIX):
            # Child setup (keygen/Init) cleanly errored before the probe could run:
            # an advertised capability that is not operational -> xfail, recorded
            # via classify() so the plugin runtime gate never has to synthesize a
            # record-less verdict for it.
            xfail_as(
                "not_operational",
                label=context,
                summary=line.removeprefix(SETUP_XFAIL_PREFIX).strip(),
            )


def handle_child_provider_finding(
    rc: int,
    stdout: str,
    stderr: str,
    *,
    context: str,
    expected_reason: str,
    expected_kind: str,
    operation: str,
    mechanism: str | None,
) -> bool:
    """Handle a validated provider marker before applying child process disposition.

    A marker is an observation, not a verdict emitted by the child.  The parent records
    it before looking at ``rc`` so a later cleanup failure cannot erase provider evidence.
    A missing marker is the normal path and returns ``False``.  A malformed marker is
    deliberately left as ``probe_incomplete``: the parser never guesses that the
    provider or the harness is responsible for a broken wire protocol.
    """
    payload, parse_error = parse_provider_finding(stdout)
    if payload is None:
        if parse_error is None:
            return False
        assert_subprocess_completed(rc, stdout, stderr, context=context)
        fail_as(
            "probe_incomplete",
            label=context,
            summary=f"{context}: malformed {PROVIDER_FINDING_MARKER[:-1]} marker",
            detail={"protocol": "malformed_provider_finding", "error": parse_error},
        )

    assert payload is not None
    marker_reason = payload["reason"]
    marker_kind = payload["kind"]
    marker_operation = payload["operation"]
    marker_mechanism = payload["mechanism"]
    if (
        marker_reason != expected_reason
        or marker_kind != expected_kind
        or marker_operation != operation
        or marker_mechanism != mechanism
    ):
        assert_subprocess_completed(rc, stdout, stderr, context=context)
        fail_as(
            "probe_incomplete",
            label=context,
            summary=f"{context}: provider-finding marker identity does not match probe",
            detail={
                "protocol": "provider_finding_identity",
                "expected_reason": expected_reason,
                "actual_reason": marker_reason,
                "expected_kind": expected_kind,
                "actual_kind": marker_kind,
                "expected_operation": operation,
                "actual_operation": marker_operation,
                "expected_mechanism": mechanism,
                "actual_mechanism": marker_mechanism,
            },
        )

    child_detail = payload["detail"]
    assert isinstance(child_detail, str)
    finding = record_as(
        expected_reason,
        kind=expected_kind,
        label=f"{context}: {child_detail}",
        operation=operation,
        mechanism=mechanism,
        inherit_mechanism=False,
        summary=f"{context}: provider terminal evidence: {child_detail}",
        detail={"protocol": "provider_finding", "child_detail": child_detail},
    )
    assert_subprocess_completed(
        rc,
        stdout,
        stderr,
        context=context,
        already_attributed=True,
    )
    if finding.outcome in {"fail", "xfail"}:
        raise_for_record(finding)
    return True


def child_setup_reject_known(
    exc: BaseException,
    known_ckrs: tuple[int, ...],
    purpose: str,
) -> bool:
    """Classify a setup reject inside a crash-isolated child script.

    If ``exc`` matches one of ``known_ckrs`` (a clean, advertised-but-not-
    operational reject), emit a ``SETUP_XFAIL`` marker on stdout and return True
    so the caller can stop the probe cleanly; the parent's
    ``assert_subprocess_no_crash`` turns the marker into a classified
    ``not_operational`` xfail.
    Otherwise return False so the caller re-raises -- an unexpected error or
    crash must still surface, never be hidden by the setup guard.
    """
    from pkcs11_check.testcases.conftest import is_known_error

    if is_known_error(exc, known_ckrs):
        rv = getattr(exc, "rv", None)
        detail = ckr_name(rv) if rv is not None else str(exc)
        print(f"{SETUP_XFAIL_PREFIX}{purpose}: {detail}", flush=True)
        return True
    return False


# NOTE: the legacy f-string demand-zero honeypot template (HONEYPOT_MMAP_CODE) was removed
# after the probe-extraction migration; probes now call _probes/honeypot.demand_zero_buffer().
