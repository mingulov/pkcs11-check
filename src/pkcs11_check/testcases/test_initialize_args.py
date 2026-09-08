"""CK_C_INITIALIZE_ARGS matrix tests.

PKCS#11 v3.2 §5.4 specifies four mutually-exclusive initialization
modes via the `CK_C_INITIALIZE_ARGS` struct passed to `C_Initialize`:

| Callbacks supplied | CKF_OS_LOCKING_OK | Meaning                                  |
|--------------------|-------------------|------------------------------------------|
| None (all NULL)    | unset             | Library uses no locks (single-thread)    |
| None               | set               | Library uses OS locks                    |
| All 4              | unset             | Library uses caller's mutex callbacks    |
| All 4              | set               | Library may use either (caller's choice) |

Edge cases the spec calls out:
- Three of four callbacks set, one NULL → `CKR_ARGUMENTS_BAD`
- `pReserved` non-NULL → `CKR_ARGUMENTS_BAD`

These tests verify each mode is honored.  Real-module bugs that historically
appeared here:
- Some module builds segfault when callbacks are supplied without
  `CKF_OS_LOCKING_OK` then concurrent calls follow.
- Some modules ignore application callbacks silently (return `CKR_OK`
  but use OS locks anyway).
- Real HSMs sometimes reject all but one specific mode.

All tests run in subprocesses because each calls `C_Initialize` /
`C_Finalize` independently — running in the parent process would
collide with the shared session managed by `p11_raw_session`.

Marked `@pytest.mark.destructive` because of the Init/Finalize cycles.
"""

from __future__ import annotations

import re
from collections.abc import Callable
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
from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_CANT_LOCK,
    CKR_CRYPTOKI_ALREADY_INITIALIZED,
    CKR_OK,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed

pytestmark = [pytest.mark.destructive, pytest.mark.access]

_SETUP_REFUSAL_RE = re.compile(r"SETUP_XFAIL:C_Initialize refused with 0x([0-9a-f]{8,16})")
_RV_MARKER_RE = re.compile(r"RV=0x[0-9a-f]{8,16}")


def _run_init_args_probe(p11_config: Any, probe: str, timeout: int = 15) -> tuple[int, str, str]:
    """Run the ``initialize_args`` probe in a subprocess and return (rc, stdout, stderr).

    The child (``_probes/initialize_args.py``) loads the module via raw ctypes and calls
    ``C_Initialize`` (or, for the ``finalize_reserved_non_null`` probe, ``C_Finalize``) with
    the ``CK_C_INITIALIZE_ARGS`` setup selected by ``probe``.  The raw CDLL path has no
    RawPKCS11 wrapper, so coverage routes to the raw accumulator (``coverage="raw"``).  No
    PIN / session / login is involved (I3).
    """
    result = run_probe(
        "initialize_args",
        {"module_path": str(p11_config.module), "slot_id": p11_config.slot, "probe": probe},
        timeout=timeout,
        coverage="raw",
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def _parse_rv(stdout: str) -> int | None:
    for line in stdout.splitlines():
        if line.startswith("RV=0x"):
            if _RV_MARKER_RE.fullmatch(line) is None:
                raise ValueError(f"malformed RV marker: {line!r}")
            return int(line[len("RV=") :], 16)
    return None


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


def _negative_result_factory(
    *,
    expected: tuple[int, ...],
    label: str,
    accepted: Callable[[int], Classification | None],
) -> Callable[[int], Classification | None]:
    """Build a non-terminating three-way classifier for an emitted provider RV."""

    def make(rv: int) -> Classification | None:
        if rv == CKR_OK:
            return accepted(rv)
        if rv in expected:
            return None
        reason = "nonspec_reject" if _is_defined_ckr(rv) else "self_contradiction"
        kind = None if reason == "nonspec_reject" else "metadata"
        outcome, severity = derive_verdict(reason, kind)
        return Classification(
            reason=reason,
            outcome=outcome,
            severity=severity,
            kind=kind,
            label=label,
            operation="C_Initialize",
            expected_ckr=[ckr_name(code) for code in expected],
            actual_ckr=ckr_name(rv),
            summary=(
                f"{label}: returned {ckr_name(rv)}; expected "
                f"{', '.join(ckr_name(code) for code in expected)}"
            ),
        )

    return make


def _positive_init_result_factory(
    *, expected: tuple[int, ...], label: str
) -> Callable[[int], Classification | None]:
    """Classify a clean positive-init refusal without stopping probe parsing."""

    def make(rv: int) -> Classification | None:
        if rv in expected:
            return None
        reason = "not_operational" if _is_defined_ckr(rv) else "self_contradiction"
        kind = None if reason == "not_operational" else "metadata"
        outcome, severity = derive_verdict(reason, kind)
        return Classification(
            reason=reason,
            outcome=outcome,
            severity=severity,
            kind=kind,
            label=label,
            operation="C_Initialize",
            expected_ckr=[ckr_name(code) for code in expected],
            actual_ckr=ckr_name(rv),
            summary=(
                f"{label}: returned undefined CK_RV {ckr_name(rv)}"
                if reason == "self_contradiction"
                else f"{label}: returned {ckr_name(rv)}"
            ),
        )

    return make


def _normal_probe_rv(
    rc: int,
    stdout: str,
    stderr: str,
    *,
    context: str,
    provider_factory: Callable[[int], Classification | None] | None = None,
    allow_setup_refusal: bool = False,
) -> int | None:
    """Return a child RV only after normal process disposition is established.

    A crash/timeout is the provider finding and must not be replaced by a fabricated
    missing-RV harness record.  An explicit cleanup marker is already a complete
    harness observation, so callers stop without demanding a result that cleanup may
    have prevented from being emitted.
    """
    setup_records: list[Classification] = []
    protocol_errors: list[Classification] = []
    lines = stdout.splitlines()
    setup_lines = [line for line in lines if line.startswith("SETUP_XFAIL:")]
    rv_lines = [line for line in lines if line.startswith("RV=")]
    wrong_family_lines = [line for line in lines if line.startswith(("INIT_RV=", "CALL_RV="))]
    result_lines = [*rv_lines, *wrong_family_lines]
    setup_conflict = bool(setup_lines and result_lines)
    if setup_conflict:
        protocol_errors.append(
            _protocol_error(
                context,
                "setup_result_conflict",
                f"{context}: setup/result markers are mutually exclusive (setup/result conflict)",
            )
        )
    elif setup_lines and not allow_setup_refusal:
        protocol_errors.append(
            _protocol_error(
                context,
                "unexpected_setup",
                (
                    f"{context}: duplicate setup refusal markers are an unexpected setup "
                    "state for initialize-args probe"
                    if len(setup_lines) > 1
                    else f"{context}: unexpected setup refusal marker for initialize-args probe"
                ),
            )
        )
    elif len(setup_lines) > 1:
        protocol_errors.append(
            _protocol_error(
                context,
                "duplicate_setup",
                f"{context}: duplicate setup refusal markers",
            )
        )
    for line in (
        setup_lines
        if len(setup_lines) == 1 and allow_setup_refusal and not setup_conflict
        else []
    ):
        payload = line.removeprefix("SETUP_XFAIL:").strip()
        match = _SETUP_REFUSAL_RE.fullmatch(line)
        if not payload or match is None:
            protocol_errors.append(
                _protocol_error(
                    context,
                    "malformed_setup",
                    f"{context}: malformed setup marker (incomplete protocol)",
                )
            )
            continue
        setup_rv = int(match.group(1), 16)
        if setup_rv in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED):
            protocol_errors.append(
                _protocol_error(
                    context,
                    "malformed_setup",
                    f"{context}: malformed setup refusal marker carried an allowed init state",
                )
            )
            continue
        reason = "not_operational" if _is_defined_ckr(setup_rv) else "self_contradiction"
        kind = None if reason == "not_operational" else "metadata"
        outcome, severity = derive_verdict(reason, kind)
        setup_records.append(
            Classification(
                reason=reason,
                outcome=outcome,
                severity=severity,
                kind=kind,
                label=context,
                summary=(
                    f"{context}: {payload} (undefined CK_RV)"
                    if reason == "self_contradiction"
                    else f"{context}: {payload}"
                ),
                operation="C_Initialize",
                actual_ckr=ckr_name(setup_rv),
                detail={"protocol_marker": "SETUP_XFAIL"},
            )
        )
    for setup_record in setup_records[:1]:
        record(setup_record)

    rv: int | None = None
    if len(rv_lines) > 1:
        protocol_errors.append(
            _protocol_error(
                context,
                "duplicate_rv",
                f"{context}: child emitted duplicate RV markers (incomplete protocol)",
            )
        )
    if wrong_family_lines:
        protocol_errors.append(
            _protocol_error(
                context,
                "unexpected_result_marker",
                f"{context}: wrong result marker family for initialize-args probe",
            )
        )
    if len(rv_lines) == 1 and not setup_lines:
        try:
            rv = _parse_rv(stdout)
        except ValueError:
            protocol_errors.append(
                _protocol_error(
                    context,
                    "malformed_rv",
                    f"{context}: child emitted malformed RV marker (incomplete protocol)",
                )
            )
    if len(rv_lines) == 1 and not setup_lines and rv is None and not protocol_errors:
        protocol_errors.append(
            _protocol_error(
                context,
                "malformed_rv",
                f"{context}: child emitted malformed RV marker (incomplete protocol)",
            )
        )
    if setup_lines:
        rv = None
    provider_record = None
    if (
        rv is not None
        and provider_factory is not None
        and len(rv_lines) == 1
        and not setup_lines
        and not protocol_errors
    ):
        provider_record = provider_factory(rv)
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
    if setup_records:
        raise_for_record(setup_records[0])
    if provider_record is not None:
        raise_for_record(provider_record)
    if rv is None and not setup_records and not protocol_errors:
        fail_as(
            "harness_error",
            label=context,
            summary=f"{context}: child emitted no RV marker (incomplete protocol)",
            detail={"probe_incomplete": True, "protocol": "missing_rv"},
        )
    return rv


def _honest_deviation(
    *, label: str, summary: str, operation: str = "C_Initialize"
) -> Callable[[int], Classification | None]:
    def make(rv: int) -> Classification | None:
        if rv != CKR_OK:
            return None
        outcome, severity = derive_verdict("honest_deviation", "metadata")
        return Classification(
            reason="honest_deviation",
            outcome=outcome,
            severity=severity,
            kind="metadata",
            label=label,
            operation=operation,
            summary=summary,
        )

    return make


_accepted_reserved_args = _honest_deviation(
    label="C_Initialize non-NULL pReserved accepted",
    summary=(
        "Module accepts non-NULL pReserved (returns CKR_OK); spec §5.4 requires "
        "CKR_ARGUMENTS_BAD. Non-compliant but not security-impacting."
    ),
)
_accepted_partial_callbacks = _honest_deviation(
    label="C_Initialize partial mutex callbacks accepted",
    summary=(
        "Module accepts partial (3-of-4) mutex callbacks (returns CKR_OK); spec "
        "Sec.5.4 requires CKR_ARGUMENTS_BAD. Non-compliant but not security-impacting."
    ),
)
_accepted_finalize_reserved = _honest_deviation(
    label="C_Finalize non-NULL pReserved accepted",
    operation="C_Finalize",
    summary=(
        "Module accepts non-NULL pReserved in C_Finalize (returns CKR_OK); spec §11.4 "
        "requires CKR_ARGUMENTS_BAD. Non-compliant but not security-impacting "
        "(reserved field carries no caller data)."
    ),
)

_init_null_result = _positive_init_result_factory(
    expected=(CKR_OK,), label="C_Initialize(NULL)"
)
_init_empty_result = _positive_init_result_factory(
    expected=(CKR_OK, CKR_CANT_LOCK), label="C_Initialize(empty struct)"
)
_init_os_locking_result = _positive_init_result_factory(
    expected=(CKR_OK,), label="C_Initialize(OS_LOCKING_OK)"
)
_init_app_callbacks_result = _positive_init_result_factory(
    expected=(CKR_OK, CKR_CANT_LOCK), label="C_Initialize(app callbacks)"
)
_init_both_result = _positive_init_result_factory(
    expected=(CKR_OK, CKR_CANT_LOCK), label="C_Initialize(callbacks + OS_LOCKING_OK)"
)
_reserved_result = _negative_result_factory(
    expected=(CKR_ARGUMENTS_BAD,),
    label="C_Initialize with a non-NULL pReserved field (spec Sec.5.4)",
    accepted=_accepted_reserved_args,
)
_partial_result = _negative_result_factory(
    expected=(CKR_ARGUMENTS_BAD,),
    label="C_Initialize with 3-of-4 mutex callbacks supplied (spec Sec.5.4)",
    accepted=_accepted_partial_callbacks,
)
_finalize_reserved_result = _negative_result_factory(
    expected=(CKR_ARGUMENTS_BAD,),
    label="C_Finalize with a non-NULL pReserved field (spec §11.4)",
    accepted=_accepted_finalize_reserved,
)


class TestInitArgsMatrix:
    """Each row of the CK_C_INITIALIZE_ARGS matrix runs in its own subprocess."""

    def test_init_null_args(self, p11_config: Any) -> None:
        """Mode A: `C_Initialize(NULL)` is the universally-accepted default."""
        rc, stdout, stderr = _run_init_args_probe(p11_config, "null_args")
        rv = _normal_probe_rv(
            rc,
            stdout,
            stderr,
            context="C_Initialize(NULL)",
            provider_factory=_init_null_result,
        )
        if rv is None:
            return
        assert rv == CKR_OK, (
            f"C_Initialize(NULL) returned 0x{rv:08x}; expected CKR_OK.  "
            f"Stdout: {stdout!r} Stderr: {stderr!r}"
        )

    def test_init_empty_struct(self, p11_config: Any) -> None:
        """Mode B: zeroed CK_C_INITIALIZE_ARGS (no callbacks, no flags).

        Per spec §5.4 this is a "no-locks" mode — module must not crash.
        """
        rc, stdout, stderr = _run_init_args_probe(p11_config, "empty_struct")
        rv = _normal_probe_rv(
            rc,
            stdout,
            stderr,
            context="C_Initialize(empty struct)",
            provider_factory=_init_empty_result,
        )
        if rv is None:
            return
        # Acceptable: CKR_OK (no-lock mode honored) or CKR_CANT_LOCK
        # (module insists on locking).  Not acceptable: segfault.
        assert rv is not None, f"No RV produced. Stdout: {stdout!r} Stderr: {stderr!r}"
        assert (
            rv
            in (  # audit-ok: positive-op init — CKR_OK is success; CKR_CANT_LOCK is spec-legal
                CKR_OK,
                CKR_CANT_LOCK,
            )
        ), f"C_Initialize(empty struct) returned 0x{rv:08x}; expected CKR_OK or CKR_CANT_LOCK"

    def test_init_os_locking_only(self, p11_config: Any) -> None:
        """Mode C: CKF_OS_LOCKING_OK set, no callbacks.

        The standard initialization mode for multi-threaded apps.  Module
        is expected to succeed unless it's strictly single-threaded.
        """
        rc, stdout, stderr = _run_init_args_probe(p11_config, "os_locking_only")
        rv = _normal_probe_rv(
            rc,
            stdout,
            stderr,
            context="C_Initialize(OS_LOCKING_OK)",
            provider_factory=_init_os_locking_result,
        )
        if rv is None:
            return
        assert rv == CKR_OK, (
            f"C_Initialize(OS_LOCKING_OK) returned 0x{rv:08x}; "
            f"expected CKR_OK on any multi-threaded-capable module"
        )

    def test_init_app_mutex_callbacks(self, p11_config: Any) -> None:
        """Mode D: all 4 mutex callbacks set, no CKF_OS_LOCKING_OK.

        Module is required to call into the supplied callbacks for any
        synchronization.  We supply trivial no-op stubs that just return
        CKR_OK; the module should accept them or reject with
        CKR_CANT_LOCK if it can't use app-supplied locks.
        """
        rc, stdout, stderr = _run_init_args_probe(p11_config, "app_mutex_callbacks")
        rv = _normal_probe_rv(
            rc,
            stdout,
            stderr,
            context="C_Initialize(app callbacks)",
            provider_factory=_init_app_callbacks_result,
        )
        if rv is None:
            return
        # Spec permits CKR_OK (callbacks accepted) or CKR_CANT_LOCK
        # (module unable to honor caller-supplied locking).
        assert rv is not None
        assert (
            rv
            in (  # audit-ok: positive-op init — CKR_OK is success; CKR_CANT_LOCK is spec-legal
                CKR_OK,
                CKR_CANT_LOCK,
            )
        ), f"C_Initialize(app callbacks) returned 0x{rv:08x}; expected CKR_OK or CKR_CANT_LOCK"

    def test_init_both_callbacks_and_os_locking_ok(self, p11_config: Any) -> None:
        """Mode E: callbacks set AND CKF_OS_LOCKING_OK set.

        Spec §5.4 says module MAY use either OS locks or app callbacks.
        Both CKR_OK and CKR_CANT_LOCK are spec-compliant; the test
        verifies no crash.
        """
        rc, stdout, stderr = _run_init_args_probe(p11_config, "both_callbacks_and_os_locking")
        rv = _normal_probe_rv(
            rc,
            stdout,
            stderr,
            context="C_Initialize(callbacks + OS_LOCKING_OK)",
            provider_factory=_init_both_result,
        )
        if rv is None:
            return
        assert rv is not None
        assert (
            rv
            in (  # audit-ok: positive-op init — CKR_OK is success; CKR_CANT_LOCK is spec-legal
                CKR_OK,
                CKR_CANT_LOCK,
            )
        ), (
            f"C_Initialize(callbacks + OS_LOCKING_OK) returned 0x{rv:08x}; "
            f"expected CKR_OK or CKR_CANT_LOCK"
        )

    def test_init_reserved_non_null_rejected(self, p11_config: Any) -> None:
        """`pReserved != NULL` must return CKR_ARGUMENTS_BAD.

        The field is explicitly reserved; any non-NULL value is a spec
        violation by the caller.  Modules that accept it silently are
        non-compliant.
        """
        rc, stdout, stderr = _run_init_args_probe(p11_config, "reserved_non_null")
        rv = _normal_probe_rv(
            rc,
            stdout,
            stderr,
            context="C_Initialize(non-NULL pReserved)",
            provider_factory=_reserved_result,
        )
        if rv is None:
            return

    def test_init_partial_callbacks_rejected(self, p11_config: Any) -> None:
        """Three callbacks set, one NULL — spec requires CKR_ARGUMENTS_BAD.

        The spec is unambiguous: either ALL four callbacks must be
        supplied, or NONE.  Partial callbacks indicate caller bug.
        """
        rc, stdout, stderr = _run_init_args_probe(p11_config, "partial_callbacks")
        rv = _normal_probe_rv(
            rc,
            stdout,
            stderr,
            context="C_Initialize(partial callbacks)",
            provider_factory=_partial_result,
        )
        if rv is None:
            return


class TestFinalizeArgs:
    """C_Finalize argument-validation tests, each run in its own subprocess."""

    def test_finalize_reserved_non_null(self, p11_config: Any) -> None:
        """`C_Finalize(pReserved != NULL)` should return CKR_ARGUMENTS_BAD.

        PKCS#11 v3.2 §11.4 specifies that `pReserved` must be NULL; any non-NULL
        value must cause C_Finalize to return CKR_ARGUMENTS_BAD.  Some modules
        ignore the reserved field and return CKR_OK — lenient but not
        security-impacting (the field carries no caller-supplied data that could
        affect the module's behavior).

        Classification:
        - CKR_ARGUMENTS_BAD -> pass (spec-compliant rejection).
        - CKR_OK -> xfail/honest_deviation (common benign leniency; the field is
          truly reserved and ignoring it is safe).
        - Any other clean code -> xfail/nonspec_reject (noted deviation).
        """
        rc, stdout, stderr = _run_init_args_probe(p11_config, "finalize_reserved_non_null")
        rv = _normal_probe_rv(
            rc,
            stdout,
            stderr,
            context="C_Finalize(non-NULL pReserved)",
            provider_factory=_finalize_reserved_result,
            allow_setup_refusal=True,
        )
        if rv is None:
            return
