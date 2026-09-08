"""Safety properties of application-supplied mutex callbacks.

PKCS#11 v3.2 §5.4 says the library may call into application-supplied
mutex callbacks at any time on any thread.  Two properties matter for
robustness:

1.  If the application's callback returns a non-CKR_OK value, the
    library must propagate the failure cleanly (not crash, not deadlock).
2.  If the application's callback raises an exception (in a language
    binding like Python), the library must not be left in inconsistent
    state.

Modules that ignore caller-side error returns from mutex callbacks risk
silent data races — they think they hold a lock that the callback
refused to take.

Marked `@pytest.mark.destructive` because of the Init/Finalize cycles
each test performs in subprocess.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

import pytest

from pkcs11_check.classification import (
    Classification,
    derive_verdict,
    fail_as,
    raise_for_record,
    record,
)
from pkcs11_check.raw.rv import ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import CKR_CANT_LOCK, CKR_OK
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed

pytestmark = [pytest.mark.destructive, pytest.mark.access]

_RV_VALUE_RE = re.compile(r"0x[0-9a-f]{8,16}")


def _run_callback_probe(p11_config: Any, probe: str, timeout: int = 15) -> tuple[int, str, str]:
    """Run the mutex-callback probe in a subprocess and return (rc, stdout, stderr).

    The child (``_probes/mutex_callback_safety.py``) loads the module via raw ctypes and
    exercises ``C_Initialize`` with application-supplied mutex callbacks selected by
    ``probe``.  The raw CDLL path has no RawPKCS11 wrapper, so coverage routes to the raw
    accumulator (``coverage="raw"``).  No PIN / session / login is involved (I3).
    """
    result = run_probe(
        "mutex_callback_safety",
        {"module_path": str(p11_config.module), "slot_id": p11_config.slot, "probe": probe},
        timeout=timeout,
        coverage="raw",
    )
    # Preserve marker lines byte-for-byte.  In particular, stripping stdout
    # would turn a producer-impossible trailing space into valid provider
    # evidence before the exact marker parser sees it.
    return result.returncode, result.stdout, result.stderr


@dataclass(frozen=True)
class _ProbeValues:
    """Validated, mutually-exclusive values emitted by one mutex probe."""

    rv: int | None = None
    init_rv: int | None = None
    call_rv: int | None = None


def _protocol_error(context: str, protocol: str, summary: str) -> Classification:
    outcome, severity = derive_verdict("harness_error", None)
    return Classification(
        reason="harness_error",
        outcome=outcome,
        severity=severity,
        label=context,
        summary=summary,
        detail={"probe_incomplete": True, "protocol": protocol},
    )


def _is_defined_ckr(rv: int) -> bool:
    """Recognize standard/vendor CKRs within the 32-bit PKCS#11 value domain."""
    return 0 <= rv <= 0xFFFFFFFF and (is_standard_ckr(rv) or is_vendor_defined_ckr(rv))


def _parse_marker(
    lines: list[str],
    prefix: str,
    *,
    context: str,
    protocol_errors: list[Classification],
) -> tuple[int | None, bool]:
    """Parse one exact marker family; return (value, marker_was_present)."""
    matching = [line for line in lines if line.startswith(prefix)]
    if len(matching) > 1:
        protocol_errors.append(
            _protocol_error(
                context,
                f"duplicate_{prefix[:-1].lower()}",
                f"{context}: duplicate {prefix[:-1]} markers (incomplete protocol)",
            )
        )
        return None, True
    if not matching:
        return None, False
    # The probe emits the marker as one exact line.  Do not normalize its
    # payload: whitespace would be an impossible producer result and must not
    # be accepted as provider evidence.
    payload = matching[0][len(prefix) :]
    if _RV_VALUE_RE.fullmatch(payload) is None:
        protocol_errors.append(
            _protocol_error(
                context,
                f"malformed_{prefix[:-1].lower()}",
                f"{context}: malformed {prefix[:-1]} marker (incomplete protocol)",
            )
        )
        return None, True
    value = int(payload, 16)
    return value, True


def _rv_record(
    rv: int,
    *,
    label: str,
    operation: str,
    expected: tuple[int, ...] = (),
    ok_summary: str | None = None,
) -> Classification | None:
    """Return a provider record for a wrong/undefined callback result, if any."""
    if rv == CKR_OK and ok_summary is None:
        return None
    if rv != CKR_OK and _is_defined_ckr(rv):
        return None
    if rv == CKR_OK:
        reason = "honest_deviation"
        kind = "lifecycle"
        summary = ok_summary or f"{label}: callback failure was ignored (CKR_OK)"
    else:
        reason = "self_contradiction"
        kind = "metadata"
        summary = f"{label}: returned undefined CK_RV {ckr_name(rv)}"
    outcome, severity = derive_verdict(reason, kind)
    return Classification(
        reason=reason,
        outcome=outcome,
        severity=severity,
        kind=kind,
        label=label,
        operation=operation,
        expected_ckr=[ckr_name(code) for code in expected] or None,
        actual_ckr=ckr_name(rv),
        summary=summary,
    )


def _lock_init_record(rv: int) -> Classification | None:
    if rv == CKR_CANT_LOCK:
        return None
    if _is_defined_ckr(rv):
        outcome, severity = derive_verdict("nonspec_reject", None)
        return Classification(
            reason="nonspec_reject",
            outcome=outcome,
            severity=severity,
            label="C_Initialize with failing LockMutex callback",
            operation="C_Initialize",
            expected_ckr=[ckr_name(CKR_CANT_LOCK)],
            actual_ckr=ckr_name(rv),
            summary=(
                "C_Initialize with failing LockMutex callback: returned "
                f"{ckr_name(rv)} instead of the capability-specific {ckr_name(CKR_CANT_LOCK)}"
            ),
        )
    return _rv_record(
        rv,
        label="C_Initialize with failing LockMutex callback",
        operation="C_Initialize",
        expected=(CKR_CANT_LOCK,),
    )


def _lock_call_record(rv: int) -> Classification | None:
    return _rv_record(
        rv,
        label="C_GetInfo after failing LockMutex callback",
        operation="C_GetInfo",
        ok_summary=(
            "Module returned CKR_OK from C_GetInfo despite LockMutex callback returning "
            "CKR_GENERAL_ERROR; it ignored the callback failure."
        ),
    )


def _python_exception_record(rv: int) -> Classification | None:
    return _rv_record(
        rv,
        label="C_Initialize with Python exception in CreateMutex callback",
        operation="C_Initialize",
        ok_summary=(
            "C_Initialize returned CKR_OK after the CreateMutex callback raised a Python "
            "exception; the callback failure was swallowed."
        ),
    )


def _assert_normal_probe(
    rc: int,
    stdout: str,
    stderr: str,
    *,
    context: str,
    mode: Literal["rv", "lock"] = "rv",
    provider_factory: Callable[[int], Classification | None] | None = None,
) -> _ProbeValues | None:
    """Parse one complete callback result, then apply process disposition once."""
    protocol_errors: list[Classification] = []
    lines = stdout.splitlines()
    setup_lines = [line for line in lines if line.startswith("SETUP_XFAIL:")]
    all_result_lines = [
        line for line in lines if line.startswith(("RV=", "INIT_RV=", "CALL_RV="))
    ]
    setup_conflict = bool(setup_lines and all_result_lines)
    if setup_conflict:
        protocol_errors.append(
            _protocol_error(
                context,
                "setup_result_conflict",
                f"{context}: setup/result markers are mutually exclusive (setup/result conflict)",
            )
        )
    elif setup_lines:
        protocol_errors.append(
            _protocol_error(
                context,
                "unexpected_setup",
                (
                    f"{context}: duplicate setup refusal markers are an unexpected setup "
                    "state for mutex callback probe"
                    if len(setup_lines) > 1
                    else f"{context}: unexpected setup refusal marker for mutex callback probe"
                ),
            )
        )

    if mode == "rv":
        unexpected = [line for line in lines if line.startswith(("INIT_RV=", "CALL_RV="))]
        if unexpected:
            protocol_errors.append(
                _protocol_error(
                    context,
                    "unexpected_result_marker",
                    f"{context}: unexpected INIT_RV/CALL_RV marker for RV probe",
                )
            )
        rv, rv_present = _parse_marker(
            lines, "RV=", context=context, protocol_errors=protocol_errors
        )
        values = _ProbeValues(rv=rv)
        complete_result = rv_present and rv is not None
    else:
        unexpected = [line for line in lines if line.startswith("RV=")]
        if unexpected:
            protocol_errors.append(
                _protocol_error(
                    context,
                    "unexpected_result_marker",
                    f"{context}: unexpected RV marker for INIT_RV/CALL_RV probe",
                )
            )
        init_rv, init_present = _parse_marker(
            lines, "INIT_RV=", context=context, protocol_errors=protocol_errors
        )
        call_rv, call_present = _parse_marker(
            lines, "CALL_RV=", context=context, protocol_errors=protocol_errors
        )
        marker_sequence = [
            "CALL_RV" if line.startswith("CALL_RV=") else "INIT_RV"
            for line in lines
            if line.startswith(("INIT_RV=", "CALL_RV="))
        ]
        if marker_sequence and (
            marker_sequence[0] != "INIT_RV"
            or ("CALL_RV" in marker_sequence and marker_sequence.index("CALL_RV") != 1)
        ):
            protocol_errors.append(
                _protocol_error(
                    context,
                    "invalid_marker_order",
                    (
                        f"{context}: invalid lock result marker order; INIT_RV must "
                        "precede CALL_RV"
                    ),
                )
            )
        values = _ProbeValues(init_rv=init_rv, call_rv=call_rv)
        complete_result = init_present and init_rv is not None
        if init_rv == CKR_OK and not call_present:
            # Delay this required-marker error until after process disposition so a
            # crash does not become a fabricated harness finding.
            complete_result = False
        if init_rv != CKR_OK and init_rv is not None and call_present:
            protocol_errors.append(
                _protocol_error(
                    context,
                    "call_after_init_refusal",
                    f"{context}: CALL_RV is invalid after non-OK INIT_RV",
                )
            )
            complete_result = False

    provider_record: Classification | None = None
    if not setup_conflict and not protocol_errors and complete_result:
        if mode == "rv" and values.rv is not None and provider_factory is not None:
            provider_record = provider_factory(values.rv)
        elif (
            mode == "lock"
            and values.init_rv is not None
            and values.init_rv == CKR_OK
            and values.call_rv is not None
        ):
            provider_record = _lock_call_record(values.call_rv)
        elif mode == "lock" and values.init_rv is not None and values.init_rv != CKR_OK:
            provider_record = _lock_init_record(values.init_rv)
    if provider_record is not None:
        record(provider_record)
    for error in protocol_errors:
        record(error)

    _termination, explicit_harness = assert_subprocess_completed(
        rc, stdout, stderr, context=context
    )
    if explicit_harness:
        return None
    if protocol_errors:
        raise_for_record(protocol_errors[0])
    if mode == "lock" and values.init_rv is None:
        fail_as(
            "harness_error",
            label=context,
            summary=f"{context}: harness incomplete: missing INIT_RV marker",
            detail={"probe_incomplete": True, "protocol": "missing_init_rv"},
        )
    if mode == "lock" and values.init_rv == CKR_CANT_LOCK:
        pytest.skip(
            "module returned CKR_CANT_LOCK for app-supplied mutex callbacks; "
            "LockMutex failure path is not applicable"
        )
    if mode == "lock" and values.init_rv == CKR_OK and values.call_rv is None:
        fail_as(
            "harness_error",
            label=context,
            summary=f"{context}: missing CALL_RV marker after CKR_OK INIT_RV",
            detail={"probe_incomplete": True, "protocol": "missing_call_rv"},
        )
    if mode == "rv" and values.rv is None and not setup_lines:
        fail_as(
            "harness_error",
            label=context,
            summary=f"{context}: harness incomplete: missing RV marker",
            detail={"probe_incomplete": True, "protocol": "missing_rv"},
        )
    if provider_record is not None:
        raise_for_record(provider_record)
    return values


def _ignored_create_mutex_error(rv: int) -> Classification | None:
    if rv != CKR_OK:
        return _rv_record(
            rv,
            label="CreateMutex callback returning CKR_GENERAL_ERROR",
            operation="C_Initialize",
        )
    outcome, severity = derive_verdict("honest_deviation", "lifecycle")
    return Classification(
        reason="honest_deviation",
        outcome=outcome,
        severity=severity,
        kind="lifecycle",
        label="CreateMutex callback returning CKR_GENERAL_ERROR",
        operation="C_Initialize",
        summary=(
            "Module returned CKR_OK despite CreateMutex callback returning CKR_GENERAL_ERROR. "
            "Module may be ignoring caller-side mutex errors — data-race risk in concurrent "
            "use. Non-compliant but not a crash."
        ),
    )


class TestMutexCallbackErrorHandling:
    """When application callbacks signal failure, the module must not crash."""

    def test_create_mutex_callback_returning_general_error(self, p11_config: Any) -> None:
        """CreateMutex returning CKR_GENERAL_ERROR — module should propagate cleanly.

        Per spec §5.4 the module sees the failed return and should fail
        C_Initialize with a defined CKR.  Crash here is a real bug.
        """
        rc, stdout, stderr = _run_callback_probe(p11_config, "create_returns_general_error")
        _assert_normal_probe(
            rc,
            stdout,
            stderr,
            context="C_Initialize with failing CreateMutex callback",
            mode="rv",
            provider_factory=_ignored_create_mutex_error,
        )

    def test_lock_mutex_callback_returning_general_error_during_call(self, p11_config: Any) -> None:
        """LockMutex returning CKR_GENERAL_ERROR during a normal C_* call.

        After init, make some PKCS#11 call that internally locks; the
        callback fails.  Module should propagate as defined CKR.
        """
        rc, stdout, stderr = _run_callback_probe(p11_config, "lock_returns_general_error")
        _assert_normal_probe(
            rc,
            stdout,
            stderr,
            context="LockMutex callback returning CKR_GENERAL_ERROR during C_GetInfo",
            mode="lock",
        )

    def test_python_exception_in_create_mutex_callback(self, p11_config: Any) -> None:
        """A Python exception thrown from a mutex callback must not crash the module.

        ctypes propagates the exception by returning a default value (0)
        and printing a traceback.  The module sees CKR_OK and proceeds —
        this is its own kind of bug because the callback intended failure,
        but we're testing that the *binding* doesn't segfault.
        """
        rc, _stdout, stderr = _run_callback_probe(p11_config, "python_exception_in_create")
        _assert_normal_probe(
            rc,
            _stdout,
            stderr,
            context="CreateMutex callback raising Python exception",
            mode="rv",
            provider_factory=_python_exception_record,
        )
        # stderr will contain the callback traceback; that is expected evidence.
