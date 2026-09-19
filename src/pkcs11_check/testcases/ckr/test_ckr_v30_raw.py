"""CKR tests for v3.0 functions via raw ctypes calls.

Tests C_MessageEncryptInit, C_MessageDecryptInit, C_MessageSignInit,
C_MessageVerifyInit, C_EncryptMessage, C_SessionCancel using RawPKCS11
with funclist3_ptr for v3.0 function access.

Requires v3.0+ module. Skips on v2.40 modules.

Each test launches the ``ckr_v30_raw`` probe module (``_probes/ckr_v30_raw.py``) via
``run_probe`` at ``Level.LOGIN``: the probe infra opens a session and -- only when a PIN is
configured -- logs in, with the PIN travelling solely through the ``_P11CHECK_PIN`` env var
(never embedded in source or params -- Invariant I3).  This CLOSES the legacy leak that
formatted the PIN literal into the generated child-script source.  The probe drives the
per-test v3.0 call and emits a phase-labelled result for the ``_check`` classifier.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from pkcs11_check.classification import (
    Classification,
    derive_verdict,
    fail_as,
    raise_for_record,
    record,
)
from pkcs11_check.core.process_observation import termination_from_returncode
from pkcs11_check.raw.metadata_std import RV_NAMES
from pkcs11_check.raw.rv import ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_CRYPTOKI_ALREADY_INITIALIZED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_USER_ALREADY_LOGGED_IN,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import (
    SUBPROCESS_TIMEOUT_MARKER,
    pin_from_config,
)
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed

pytestmark = [pytest.mark.access, pytest.mark.subprocess]

_SKIP_TOKENS_BY_FUNCTION: dict[str, frozenset[str]] = {
    "C_MessageEncryptInit": frozenset({"v2.40_only", "no_v3_funcs"}),
    "C_EncryptMessage": frozenset({"v2.40_only", "no_v3_funcs", "no_EncryptMessage"}),
    "C_MessageDecryptInit": frozenset({"v2.40_only", "no_v3_funcs"}),
    "C_MessageSignInit": frozenset({"v2.40_only", "no_v3_funcs"}),
    "C_MessageVerifyInit": frozenset({"v2.40_only", "no_v3_funcs"}),
    "C_SessionCancel": frozenset({"v2.40_only", "no_v3_funcs", "no_SessionCancel"}),
}
_SETUP_RE = re.compile(
    r"^(C_Initialize|C_GetSlotList|C_OpenSession|C_Login) rejected with "
    r"(CKR_[A-Z0-9_]+|0x[0-9a-f]{8,16})$"
)
_STANDARD_RVS_BY_NAME: dict[str, int] = {name: rv for rv, name in RV_NAMES.items()}
_SETUP_SUCCESS_RVS: dict[str, frozenset[int]] = {
    "C_Initialize": frozenset({int(CKR_OK), int(CKR_CRYPTOKI_ALREADY_INITIALIZED)}),
    "C_Login": frozenset({int(CKR_OK), int(CKR_USER_ALREADY_LOGGED_IN)}),
}
_DEFAULT_SETUP_SUCCESS_RVS = frozenset({int(CKR_OK)})


def _is_defined_ckr(rv: int) -> bool:
    """Return whether *rv* is a standard or 32-bit vendor-defined CK_RV."""
    return is_standard_ckr(rv) or (is_vendor_defined_ckr(rv) and rv <= 0xFFFFFFFF)


def _is_impossible_setup_result(operation: str, rv: int | None) -> bool:
    """Return whether a setup marker claims that bootstrap accepted its state."""
    return rv is not None and rv in _SETUP_SUCCESS_RVS.get(operation, _DEFAULT_SETUP_SUCCESS_RVS)


def _run_probe(p11_config: Any, probe: str) -> tuple[int, str, str]:
    result = run_probe(
        "ckr_v30_raw",
        {"module_path": str(p11_config.module), "probe": probe},
        pin=pin_from_config(p11_config),
        timeout=15,
        coverage="session",
    )
    return result.returncode, result.stdout, result.stderr


def _check(rc: int, out: str, err: str, func: str) -> None:
    expected_phases = {
        "C_MessageEncryptInit": ("C_MessageEncryptInit",),
        "C_EncryptMessage": ("C_EncryptMessage",),
        "C_MessageDecryptInit": ("C_MessageDecryptInit",),
        "C_MessageSignInit": ("C_MessageSignInit",),
        "C_MessageVerifyInit": ("C_MessageVerifyInit",),
        "C_SessionCancel": ("C_SessionCancel",),
    }.get(func, (func,))
    # CKR_FUNCTION_NOT_SUPPORTED is NOT listed here. It is the spec-defined way to say a
    # v3.0 function is unimplemented -- capability absence, so _check_protocol turns it
    # into a *skip* carrying the declining function's identity. Listing it as an expected
    # RV would turn "the module does not implement this at all" into a silent pass, which
    # both inflates PASS counts and erases the observation from the report.
    expected_rvs = {
        "C_MessageEncryptInit": (CKR_MECHANISM_INVALID,),
        "C_EncryptMessage": (CKR_OPERATION_NOT_INITIALIZED,),
        "C_MessageDecryptInit": (CKR_MECHANISM_INVALID,),
        "C_MessageSignInit": (CKR_MECHANISM_INVALID,),
        "C_MessageVerifyInit": (CKR_MECHANISM_INVALID,),
        "C_SessionCancel": (CKR_OK, CKR_OPERATION_ACTIVE),
    }.get(func, (CKR_ARGUMENTS_BAD,))
    return _check_protocol(rc, out, err, func, expected_phases, expected_rvs)


def _check_protocol(
    rc: int,
    out: str,
    err: str,
    func: str,
    expected_phases: tuple[str, ...],
    expected_rvs: tuple[Any, ...],
) -> None:
    """Validate one complete probe record before applying process disposition."""
    result_re = re.compile(r"^RESULT:([A-Za-z0-9_.-]+):CKR:0x([0-9a-f]{8,16})$")
    results: list[tuple[str, int]] = []
    setup: list[str] = []
    skips: list[str] = []
    protocol_error: str | None = None
    terminal: str | None = None
    terminal_seen = False
    explicit_harness = any(
        line.startswith("HARNESS_ERROR:") for stream in (out, err) for line in stream.splitlines()
    )
    termination_hint = termination_from_returncode(
        rc,
        timed_out=SUBPROCESS_TIMEOUT_MARKER in err,
        stderr=err,
    )
    termination_kind = termination_hint["kind"]
    for line in out.splitlines():
        if line.startswith("RESULT:"):
            if terminal_seen:
                protocol_error = protocol_error or "result_after_terminal"
            match = result_re.fullmatch(line)
            if match is None:
                protocol_error = protocol_error or "malformed_result"
            else:
                phase = match.group(1)
                raw_rv = match.group(2)
                if phase is None or raw_rv is None:
                    protocol_error = protocol_error or "malformed_result"
                else:
                    results.append((phase, int(raw_rv, 16)))
        elif line.startswith("SETUP_XFAIL:"):
            if terminal_seen:
                protocol_error = protocol_error or "marker_after_terminal"
            payload = line.removeprefix("SETUP_XFAIL:")
            if not payload:
                protocol_error = protocol_error or "malformed_setup"
            setup.append(payload)
        elif line.startswith("SKIP:"):
            if terminal_seen:
                protocol_error = protocol_error or "marker_after_terminal"
            payload = line.removeprefix("SKIP:")
            if not payload:
                protocol_error = protocol_error or "malformed_skip"
            skips.append(payload)
        elif line.startswith("OK"):
            match = re.fullmatch(r"OK:([A-Za-z0-9_.-]+)", line)
            if line == "OK":
                protocol_error = protocol_error or "malformed_terminal_marker"
                marker_phase = None
            elif match is None:
                protocol_error = protocol_error or "malformed_terminal_marker"
                marker_phase = None
            else:
                marker_phase = match.group(1)
            if marker_phase is not None and terminal is not None:
                protocol_error = protocol_error or "duplicate_terminal_marker"
            elif marker_phase is not None:
                terminal = marker_phase
                terminal_seen = True
        elif line.startswith("MEASUREMENT:"):
            protocol_error = protocol_error or "unexpected_result_marker"
        elif line.startswith(("CKR:", "BREAK:", "DEVIATION_XFAIL:", "FATAL:")):
            protocol_error = protocol_error or "legacy_result_marker"

    if len(skips) > 1 or len(setup) > 1:
        protocol_error = protocol_error or "duplicate_marker"
    allowed_skips = _SKIP_TOKENS_BY_FUNCTION.get(func, frozenset())
    if any(skip not in allowed_skips for skip in skips):
        protocol_error = protocol_error or "invalid_skip_token"
    setup_facts: list[tuple[str, str | None, int | None]] = []
    for payload in setup:
        if payload == "no slot with a present token":
            setup_facts.append(("C_GetSlotList", None, None))
            continue
        setup_match = _SETUP_RE.fullmatch(payload)
        if setup_match is None:
            protocol_error = protocol_error or "invalid_setup_marker"
            continue
        setup_token = setup_match.group(2)
        if setup_token.startswith("CKR_"):
            setup_rv = _STANDARD_RVS_BY_NAME.get(setup_token)
            if setup_rv is None:
                protocol_error = protocol_error or "invalid_setup_marker"
                continue
        else:
            setup_rv = int(setup_token, 16)
        setup_facts.append(
            (
                setup_match.group(1),
                setup_token,
                setup_rv,
            )
        )
    if any(_is_impossible_setup_result(operation, rv) for operation, token, rv in setup_facts):
        protocol_error = protocol_error or "impossible_setup_result"
    phases = [phase for phase, _ in results]
    if len(phases) != len(set(phases)):
        protocol_error = protocol_error or "duplicate_result"
    if terminal is not None and terminal != func:
        protocol_error = protocol_error or "unexpected_terminal_phase"
    prefix_is_valid = (
        bool(results)
        and len(results) <= len(expected_phases)
        and tuple(phases) == expected_phases[: len(results)]
        and terminal is None
    )
    interrupted_after_prefix = prefix_is_valid and (
        explicit_harness or termination_kind in {"signal", "exception", "timeout"}
    )
    if results and len(results) > len(expected_phases):
        protocol_error = protocol_error or "wrong_result_cardinality"
    elif results and tuple(phases) != expected_phases[: len(results)]:
        protocol_error = protocol_error or "unexpected_result_phase"
    elif results and len(results) < len(expected_phases) and not interrupted_after_prefix:
        protocol_error = protocol_error or "wrong_result_cardinality"
    if skips and (setup or results or terminal is not None):
        protocol_error = protocol_error or "mixed_terminal_markers"
    if setup and (results or terminal is not None):
        protocol_error = protocol_error or "mixed_terminal_markers"
    if not results and not setup and not skips and not explicit_harness:
        protocol_error = protocol_error or "missing_result"
    if (
        results
        and len(results) == len(expected_phases)
        and terminal is None
        and not explicit_harness
    ):
        protocol_error = protocol_error or "missing_terminal_marker"

    semantic: list[Classification] = []
    # Function-level "not implemented" observations, kept apart from the child-emitted
    # ``skips`` so the mixed_terminal_markers protocol check above is unaffected.
    unimplemented: list[str] = []
    # Valid provider observations remain trustworthy when the process is
    # interrupted before later phases or the optional completion line; the
    # shared process disposition below preserves them alongside a crash/harness record.
    if protocol_error in (None, "missing_terminal_marker") and results:
        for phase, rv in results:
            expected_names = [ckr_name(int(code)) for code in expected_rvs]
            actual_name = ckr_name(rv)
            if rv in {int(code) for code in expected_rvs}:
                continue
            if rv == int(CKR_FUNCTION_NOT_SUPPORTED):
                # Capability absence at the function level: the module exposes the entry
                # point but declines the function outright. Orthogonal to mechanism
                # advertisement, so it is not a deviation -- but it is not a pass either.
                # Skip keeps the declining function named and visible in skip accounting.
                unimplemented.append(
                    f"{func}: {phase} not implemented (CKR_FUNCTION_NOT_SUPPORTED)"
                )
                continue
            if rv == int(CKR_OK):
                reason, kind = "accepted_invalid", "crypto"
                summary = f"{func}: accepted invalid operation with CKR_OK"
            elif not _is_defined_ckr(rv):
                reason, kind = "self_contradiction", "metadata"
                summary = f"{func}: undefined CK_RV {rv:#x}; expected {expected_names}"
            else:
                reason, kind = "nonspec_reject", None
                summary = f"{func}: non-spec rejection {actual_name}; expected {expected_names}"
            outcome, severity = derive_verdict(reason, kind)
            semantic.append(
                Classification(
                    reason=reason,
                    outcome=outcome,
                    severity=severity,
                    kind=kind,
                    label=func,
                    summary=summary,
                    operation=phase,
                    expected_ckr=expected_names,
                    actual_ckr=actual_name,
                    detail={"protocol": "result", "phase": phase},
                )
            )

    if setup and protocol_error is None and setup_facts:
        setup_operation, setup_actual, setup_rv = setup_facts[0]
        setup_expected = ["CKR_OK"]
        setup_actual_name: str | None
        if setup_rv is not None and not _is_defined_ckr(setup_rv):
            setup_reason, setup_kind = "self_contradiction", "metadata"
            setup_actual_name = ckr_name(setup_rv)
            setup_summary = (
                f"{func}: {setup_operation} reported undefined CK_RV "
                f"{setup_actual_name}; expected {setup_expected}"
            )
        else:
            setup_reason, setup_kind = "not_operational", None
            setup_actual_name = ckr_name(setup_rv) if setup_rv is not None else setup_actual
            setup_summary = f"{func}: {setup[0]}"
        outcome, severity = derive_verdict(setup_reason, setup_kind)
        semantic.append(
            Classification(
                reason=setup_reason,
                outcome=outcome,
                severity=severity,
                kind=setup_kind,
                label=func,
                summary=setup_summary,
                operation=setup_operation,
                expected_ckr=setup_expected,
                actual_ckr=setup_actual_name,
                detail={"protocol": "setup_xfail"},
            )
        )

    for item in semantic:
        record(item)
    # Pure absence (no result at all, or full results but no terminal line) is
    # unresolved attribution -- the missing bytes are as likely a module observation
    # as our own bug -- so it stays a loud provider-side fail. Every other protocol
    # error is an observably malformed or self-contradictory emission: ours.
    protocol_reason = (
        "probe_incomplete"
        if protocol_error in ("missing_result", "missing_terminal_marker")
        else "harness_error"
    )
    protocol: Classification | None = None
    if protocol_error is not None:
        protocol = Classification(
            reason=protocol_reason,
            outcome="fail",
            severity="HIGH",
            label=func,
            summary=f"{func}: invalid child result protocol ({protocol_error})",
            detail={"probe_incomplete": True, "protocol": protocol_error},
        )
        # If a valid result was followed by a crash before the optional completion
        # marker, the crash is the outer disposition; do not invent a second
        # protocol record for the marker the crash prevented.
        if protocol_error != "missing_terminal_marker":
            record(protocol)
    termination, explicit_harness_seen = assert_subprocess_completed(
        rc, out, err, context=func, already_attributed=protocol_error is not None
    )
    if explicit_harness_seen:
        return
    if protocol_error is not None:
        if protocol_error == "missing_terminal_marker" and protocol is not None:
            record(protocol)
        if protocol is not None:
            raise_for_record(protocol)
        fail_as(
            protocol_reason,
            label=func,
            summary=f"{func}: invalid child result protocol",
            detail={"probe_incomplete": True, "protocol": protocol_error},
        )
    if semantic:
        strongest = next(
            (item for item in semantic if item.reason in {"accepted_invalid", "wrong_result"}),
            semantic[0],
        )
        raise_for_record(strongest)
    if skips:
        pytest.skip(skips[0])
    if unimplemented:
        pytest.skip(unimplemented[0])
    if terminal is None:
        fail_as(
            "probe_incomplete",
            label=func,
            summary=f"{func}: child emitted no complete terminal marker",
            detail={
                "probe_incomplete": True,
                "protocol": "missing_terminal_marker",
                "termination": termination,
            },
        )


@pytest.mark.needs_function("C_MessageEncryptInit")
class TestMessageEncryptErrors:
    """v3.0 C_MessageEncryptInit error conditions."""

    def test_mechanism_invalid(self, p11_config: Any) -> None:
        """C_MessageEncryptInit with digest mechanism -> CKR_MECHANISM_INVALID."""
        rc, out, err = _run_probe(p11_config, "message_encrypt_mech_invalid")
        _check(rc, out, err, "C_MessageEncryptInit")

    def test_operation_not_initialized(self, p11_config: Any) -> None:
        """C_EncryptMessage without Init -> CKR_OPERATION_NOT_INITIALIZED."""
        rc, out, err = _run_probe(p11_config, "encrypt_message_no_init")
        _check(rc, out, err, "C_EncryptMessage")


@pytest.mark.needs_function("C_MessageDecryptInit")
class TestMessageDecryptErrors:
    """v3.0 C_MessageDecryptInit error conditions."""

    def test_mechanism_invalid(self, p11_config: Any) -> None:
        """C_MessageDecryptInit with digest mechanism."""
        rc, out, err = _run_probe(p11_config, "message_decrypt_mech_invalid")
        _check(rc, out, err, "C_MessageDecryptInit")


@pytest.mark.needs_function("C_MessageSignInit")
class TestMessageSignErrors:
    """v3.0 C_MessageSignInit error conditions."""

    def test_mechanism_invalid(self, p11_config: Any) -> None:
        """C_MessageSignInit with encrypt mechanism."""
        rc, out, err = _run_probe(p11_config, "message_sign_mech_invalid")
        _check(rc, out, err, "C_MessageSignInit")


@pytest.mark.needs_function("C_MessageVerifyInit")
class TestMessageVerifyErrors:
    """v3.0 C_MessageVerifyInit error conditions."""

    def test_mechanism_invalid(self, p11_config: Any) -> None:
        """C_MessageVerifyInit with encrypt mechanism."""
        rc, out, err = _run_probe(p11_config, "message_verify_mech_invalid")
        _check(rc, out, err, "C_MessageVerifyInit")


@pytest.mark.needs_function("C_SessionCancel")
class TestSessionCancelErrors:
    """v3.0 C_SessionCancel error conditions."""

    def test_cancel_no_operation(self, p11_config: Any) -> None:
        """C_SessionCancel with no active operation."""
        rc, out, err = _run_probe(p11_config, "session_cancel_no_operation")
        _check(rc, out, err, "C_SessionCancel")
