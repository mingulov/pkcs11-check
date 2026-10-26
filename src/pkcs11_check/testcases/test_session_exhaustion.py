"""Session exhaustion tests.

Opens sessions until the module refuses (CKR_SESSION_COUNT or similar),
then verifies the error is graceful and the module recovers.

QC11b (below) adds declared-vs-enforced session-limit coverage: the new test
reads the advertised maxima FIRST and judges the refusal position against
them, plus sacrificial-token PIN-length legs via InitPIN/SetPIN.
"""

from __future__ import annotations

import ctypes
from typing import Any, NamedTuple

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
    login_user,
)
from pkcs11_check.raw.bootstrap import (
    open_session as raw_open_session,
)
from pkcs11_check.raw.rv import (
    CkrAssertionError,
    ckr_name,
    expect_rv,
    is_standard_ckr,
    is_vendor_defined_ckr,
)
from pkcs11_check.raw.types_std import (
    CK_TOKEN_INFO,
    CK_UNAVAILABLE_INFORMATION,
    CK_UNAVAILABLE_INFORMATION_32,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKR_OK,
    CKR_PIN_LEN_RANGE,
    CKR_SESSION_COUNT,
    CKU_USER,
)
from pkcs11_check.testcases import _throwaway_token as throwaway
from pkcs11_check.testcases._probes import token_admin
from pkcs11_check.testcases.conftest import gen_aes_key_or_xfail

pytestmark = pytest.mark.security


def _record_lifecycle_refusal(
    exc: CkrAssertionError,
    *,
    operation: str,
    expected: int,
    phase: str,
    handle: int | None = None,
    noncanonical_reason: str = "not_operational",
) -> classification.Classification:
    """Defer a lifecycle CK_RV without inheriting a surrounding mechanism."""
    detail: dict[str, object] = {"phase": phase}
    if handle is not None:
        detail["handle"] = handle
    if is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv):
        reason = noncanonical_reason
        kind = "lifecycle"
        summary = f"{operation} during {phase} refused with {ckr_name(exc.rv)}"
    else:
        reason = "self_contradiction"
        kind = "metadata"
        summary = (
            f"{operation} during {phase} returned undefined CK_RV {ckr_name(exc.rv)}; "
            f"expected {ckr_name(int(expected))}"
        )
    return classification.record_as(
        reason,
        kind=kind,
        label=f"{operation} during {phase}",
        operation=operation,
        mechanism=None,
        inherit_mechanism=False,
        expected=expected,
        actual=exc.rv,
        detail=detail,
        summary=summary,
    )


def _close_owned_sessions(
    raw: Any,
    owned: list[tuple[int, str]],
    deferred: list[classification.Classification],
    cleanup_errors: list[BaseException],
) -> None:
    """Attempt each owned handle exactly once, preserving every cleanup observation."""
    for handle, phase in owned:
        try:
            expect_rv(raw.C_CloseSession(handle), CKR_OK)
        except CkrAssertionError as exc:
            deferred.append(
                _record_lifecycle_refusal(
                    exc,
                    operation="C_CloseSession",
                    expected=CKR_OK,
                    phase=phase,
                    handle=handle,
                )
            )
        except BaseException as exc:
            exc.add_note(f"C_CloseSession cleanup raised for owned handle {handle} during {phase}")
            cleanup_errors.append(exc)
    owned.clear()


def _strongest_deferred(
    records: list[classification.Classification],
) -> classification.Classification:
    """Choose a terminal deferred record without dropping earlier observations."""
    rank = {"pass": 0, "xfail": 1, "fail": 2}
    return max(records, key=lambda record: rank[record.outcome])


def _finish_session_attempt(
    pending: BaseException | None,
    cleanup_errors: list[BaseException],
    deferred: list[classification.Classification],
) -> None:
    """Raise the strongest honest terminal outcome after all owned cleanup."""
    if cleanup_errors:
        errors = ([pending] if pending is not None else []) + cleanup_errors
        if len(errors) == 1:
            raise errors[0]
        raise BaseExceptionGroup("session lifecycle failures", errors)
    if pending is not None:
        if isinstance(pending, pytest.skip.Exception) and deferred:
            selected = _strongest_deferred(deferred)
            selected.detail = {
                **(selected.detail or {}),
                "capability_skip": {
                    "exception_type": type(pending).__name__,
                    "reason": str(pending),
                },
            }
            try:
                classification.raise_for_record(selected)
            except BaseException as terminal:
                raise terminal from pending
        raise pending
    if deferred:
        classification.raise_for_record(_strongest_deferred(deferred))


class TestSessionExhaustion:
    """Test behavior when opening many sessions."""

    def test_open_many_sessions(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Open sessions until limit or 100, verify all work, close all."""
        rs = p11_raw_session
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION

        owned: list[tuple[int, str]] = []
        deferred: list[classification.Classification] = []
        cleanup_errors: list[BaseException] = []
        pending: BaseException | None = None
        recovery_allowed = False

        try:
            try:
                s0 = raw_open_session(rs.raw, rs.slot_id, flags)
            except CkrAssertionError as exc:
                deferred.append(
                    _record_lifecycle_refusal(
                        exc,
                        operation="C_OpenSession",
                        expected=CKR_OK,
                        phase="initial",
                    )
                )
            except BaseException as exc:
                pending = exc
            else:
                owned.append((s0, "initial"))
                if pin is not None:
                    try:
                        login_user(rs.raw, s0, CKU_USER, pin.encode("utf-8"))
                    except CkrAssertionError as exc:
                        deferred.append(
                            _record_lifecycle_refusal(
                                exc,
                                operation="C_Login",
                                expected=CKR_OK,
                                phase="initial",
                                handle=s0,
                            )
                        )
                    except BaseException as exc:
                        pending = exc

                if pending is None and not deferred:
                    for _ in range(99):
                        try:
                            sh = raw_open_session(rs.raw, rs.slot_id, flags)
                        except CkrAssertionError as exc:
                            if exc.rv == int(CKR_SESSION_COUNT):
                                recovery_allowed = True
                                break
                            deferred.append(
                                _record_lifecycle_refusal(
                                    exc,
                                    operation="C_OpenSession",
                                    expected=CKR_SESSION_COUNT,
                                    phase="saturation",
                                    noncanonical_reason="nonspec_reject",
                                )
                            )
                            recovery_allowed = True
                            break
                        except BaseException as exc:
                            pending = exc
                            break
                        else:
                            owned.append((sh, "saturation"))
                    else:
                        recovery_allowed = True
        finally:
            _close_owned_sessions(rs.raw, owned, deferred, cleanup_errors)

        if pending is None and recovery_allowed and not cleanup_errors:
            recovery: int | None = None
            recovery_failed = False
            try:
                try:
                    recovery = raw_open_session(rs.raw, rs.slot_id, flags)
                except CkrAssertionError as exc:
                    recovery_failed = True
                    deferred.append(
                        _record_lifecycle_refusal(
                            exc,
                            operation="C_OpenSession",
                            expected=CKR_OK,
                            phase="recovery",
                        )
                    )
                except BaseException as exc:
                    recovery_failed = True
                    pending = exc
                else:
                    owned.append((recovery, "recovery"))
                    if pin is not None:
                        try:
                            login_user(
                                rs.raw,
                                recovery,
                                CKU_USER,
                                pin.encode("utf-8"),
                            )
                        except CkrAssertionError as exc:
                            recovery_failed = True
                            deferred.append(
                                _record_lifecycle_refusal(
                                    exc,
                                    operation="C_Login",
                                    expected=CKR_OK,
                                    phase="recovery",
                                    handle=recovery,
                                )
                            )
                        except BaseException as exc:
                            recovery_failed = True
                            pending = exc
                    if pending is None and not recovery_failed:
                        key = gen_aes_key_or_xfail(rs, 128, sh=recovery)
                        assert key != 0
            except BaseException as exc:
                pending = exc
            finally:
                _close_owned_sessions(rs.raw, owned, deferred, cleanup_errors)

        _finish_session_attempt(pending, cleanup_errors, deferred)

    def test_session_close_frees_resources(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Opening and closing sessions in a loop doesn't leak."""
        rs = p11_raw_session
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION

        for _ in range(50):
            sh = raw_open_session(rs.raw, rs.slot_id, flags)
            if pin is not None:
                login_user(
                    rs.raw,
                    sh,
                    CKU_USER,
                    pin.encode("utf-8"),
                )
            close_session_quietly(rs.raw, sh)


# --- QC11b: advertised-vs-enforced session limits + PIN lengths (#52.7) --------

_QC11B_SESSION_SAFETY_CAP = 100
_QC11B_CANONICAL_SESSION_REFUSAL = (int(CKR_SESSION_COUNT),)
_QC11B_CANONICAL_PIN_LEN = (int(CKR_PIN_LEN_RANGE),)
_QC11B_PIN_LENGTH_OPS = {"init_pin": "C_InitPIN", "set_pin": "C_SetPIN"}


class SessionLimitPolicy(NamedTuple):
    max_total: int | None
    max_rw: int | None
    ambient_total: int
    ambient_rw: int


def _is_unavailable(value: int) -> bool:
    """Both all-ones spellings (64-bit and LLP64 32-bit) mean undeclared."""
    return value in (int(CK_UNAVAILABLE_INFORMATION), int(CK_UNAVAILABLE_INFORMATION_32))


def _read_session_policy(raw: Any, slot_id: int) -> tuple[SessionLimitPolicy | None, int]:
    """Read the advertised session maxima; (None, rv) when unreadable."""
    info = CK_TOKEN_INFO()
    rv = int(raw.C_GetTokenInfo(slot_id, ctypes.byref(info)))
    if rv != int(CKR_OK):
        return None, rv
    max_total = int(info.ulMaxSessionCount)
    max_rw = int(info.ulMaxRwSessionCount)
    return SessionLimitPolicy(
        max_total=None if _is_unavailable(max_total) else max_total,
        max_rw=None if _is_unavailable(max_rw) else max_rw,
        ambient_total=int(info.ulSessionCount),
        ambient_rw=int(info.ulRwSessionCount),
    ), int(CKR_OK)


def _judge_session_exhaustion(
    *,
    policy: SessionLimitPolicy,
    own_opens: int,
    refused_rv: int | None,
    total_now: int | None,
    rw_now: int | None,
) -> None:
    """Judge an open-until-refusal run against the advertised maxima."""
    label = "QC11b session limits"
    detail: dict[str, Any] = {
        "advertised_max_total": policy.max_total,
        "advertised_max_rw": policy.max_rw,
        "ambient_before_total": policy.ambient_total,
        "ambient_before_rw": policy.ambient_rw,
        "own_opens": own_opens,
        "observed_total": total_now,
        "observed_rw": rw_now,
        "refused_rv": ckr_name(refused_rv) if refused_rv is not None else None,
    }
    if refused_rv is None:
        pytest.skip(
            f"{label}: opened {own_opens} sessions with no refusal "
            f"(advertised max total={policy.max_total}, rw={policy.max_rw}); "
            "boundary-untested, never a pass"
        )
    if not (is_standard_ckr(refused_rv) or is_vendor_defined_ckr(refused_rv)):
        classification.fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation="C_OpenSession",
            mechanism=None,
            inherit_mechanism=False,
            expected=_QC11B_CANONICAL_SESSION_REFUSAL,
            actual=refused_rv,
            summary=f"{label}: saturation refusal is an undefined CK_RV",
            detail=detail,
        )
    over = (
        policy.max_total is not None and total_now is not None and total_now > policy.max_total
    ) or (policy.max_rw is not None and rw_now is not None and rw_now > policy.max_rw)
    if over:
        classification.xfail_as(
            "honest_deviation",
            kind="metadata",
            label=label,
            operation="C_OpenSession",
            mechanism=None,
            inherit_mechanism=False,
            actual=refused_rv,
            summary=f"{label}: token admitted more sessions than advertised (benign over-delivery)",
            detail=detail,
        )
    # Each finite dimension is judged independently: an undeclared (None = no
    # enforced limit) dimension can never explain a refusal, so every finite
    # dimension observed below its maximum proves an early refusal. A finite
    # dimension with an unknown count may still explain it (fail-safe: no FAIL).
    finite_dims = [
        (mx, now)
        for mx, now in ((policy.max_total, total_now), (policy.max_rw, rw_now))
        if mx is not None
    ]
    early = bool(finite_dims) and all(now is not None and now < mx for mx, now in finite_dims)
    if early:
        classification.fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation="C_OpenSession",
            mechanism=None,
            inherit_mechanism=False,
            actual=refused_rv,
            summary=f"{label}: refused after {own_opens} own opens, earlier than advertised maxima",
            detail=detail,
        )
    at_total = policy.max_total is not None and (
        (total_now is not None and total_now >= policy.max_total) or own_opens >= policy.max_total
    )
    at_rw = policy.max_rw is not None and (
        (rw_now is not None and rw_now >= policy.max_rw) or own_opens >= policy.max_rw
    )
    if at_total or at_rw:
        if refused_rv == int(CKR_SESSION_COUNT):
            return
        classification.xfail_as(
            "nonspec_reject",
            label=label,
            operation="C_OpenSession",
            mechanism=None,
            inherit_mechanism=False,
            expected=_QC11B_CANONICAL_SESSION_REFUSAL,
            actual=refused_rv,
            summary=f"{label}: boundary refusal is {ckr_name(refused_rv)}",
            detail=detail,
        )
    classification.xfail_as(
        "honest_deviation",
        kind="metadata",
        label=label,
        operation="C_OpenSession",
        mechanism=None,
        inherit_mechanism=False,
        actual=refused_rv,
        summary=f"{label}: refused below declared maxima with an undeclared dimension; unprovable",
        detail=detail,
    )


def _judge_pin_lengths(trace: token_admin.AdminTrace, *, op: str) -> None:
    """Judge one PIN-length sweep against the declared ulMin/ulMaxPinLen."""
    try:
        operation = _QC11B_PIN_LENGTH_OPS[op]
    except KeyError:
        raise ValueError(f"unknown op {op!r}") from None
    label = f"QC11b {op} lengths"
    # F3: an undefined bounds read FAILs (same doctrine as R19-04 snapshots);
    # only defined failures degrade to the untestable skip below.
    token_admin.fail_on_undefined_snapshots(trace, label=label, detail={"op": op})
    if trace.pin_bounds is None:
        pytest.skip(f"{label}: PIN bounds unreadable; length MUSTs untestable")
    min_pin, max_pin = trace.pin_bounds
    if min_pin > max_pin:
        classification.fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation=operation,
            mechanism=None,
            inherit_mechanism=False,
            summary=f"{label}: declared PIN bounds impossible (min {min_pin} > max {max_pin})",
            detail={"op": op, "bounds": [min_pin, max_pin]},
        )
    legs = [
        (int(step.name.removeprefix("setlen:")), step.rv)
        for step in trace.steps
        if step.name.startswith("setlen:")
    ]
    assert legs, f"{label}: probe contract broken (no setlen legs)"
    detail: dict[str, Any] = {
        "op": op,
        "bounds": [min_pin, max_pin],
        "legs": [{"length": length, "rv": ckr_name(rv)} for length, rv in legs],
    }
    records: list[classification.Classification] = []
    for length, rv in legs:
        leg_label = f"{label}: len {length}"
        if length < min_pin or length > max_pin:
            if rv == int(CKR_OK):
                records.append(
                    classification.record_as(
                        "accepted_invalid",
                        label=leg_label,
                        operation=operation,
                        mechanism=None,
                        inherit_mechanism=False,
                        expected=_QC11B_CANONICAL_PIN_LEN,
                        actual=rv,
                        summary=f"{leg_label}: out-of-bounds PIN accepted against declared bounds",
                        detail=detail,
                    )
                )
            elif not (is_standard_ckr(rv) or is_vendor_defined_ckr(rv)):
                records.append(
                    classification.record_as(
                        "self_contradiction",
                        kind="metadata",
                        label=leg_label,
                        operation=operation,
                        mechanism=None,
                        inherit_mechanism=False,
                        actual=rv,
                        summary=f"{leg_label}: length leg returned undefined CK_RV",
                        detail=detail,
                    )
                )
            elif rv == int(CKR_PIN_LEN_RANGE):
                continue
            else:
                records.append(
                    classification.record_as(
                        "nonspec_reject",
                        label=leg_label,
                        operation=operation,
                        mechanism=None,
                        inherit_mechanism=False,
                        expected=_QC11B_CANONICAL_PIN_LEN,
                        actual=rv,
                        summary=f"{leg_label}: out-of-bounds PIN refused with {ckr_name(rv)}",
                        detail=detail,
                    )
                )
        elif rv == int(CKR_OK):
            continue
        elif not (is_standard_ckr(rv) or is_vendor_defined_ckr(rv)):
            records.append(
                classification.record_as(
                    "self_contradiction",
                    kind="metadata",
                    label=leg_label,
                    operation=operation,
                    mechanism=None,
                    inherit_mechanism=False,
                    actual=rv,
                    summary=f"{leg_label}: length leg returned undefined CK_RV",
                    detail=detail,
                )
            )
        else:
            records.append(
                classification.record_as(
                    "not_operational",
                    label=leg_label,
                    operation=operation,
                    mechanism=None,
                    inherit_mechanism=False,
                    expected=(int(CKR_OK),),
                    actual=rv,
                    summary=f"{leg_label}: in-bounds PIN refused with {ckr_name(rv)}",
                    detail=detail,
                )
            )
    if token_admin.pin_sweep_capped(min_pin, max_pin):
        records.append(
            classification.record_as(
                "not_operational",
                label=label,
                operation=operation,
                mechanism=None,
                inherit_mechanism=False,
                summary=(
                    f"{label}: declared PIN bounds (min {min_pin}, max {max_pin}) exceed "
                    f"the length-sweep cap {token_admin.PIN_SWEEP_CAP}; "
                    "over-cap legs untestable, never a pass"
                ),
                detail=detail,
            )
        )
    if records:
        classification.raise_for_record(_strongest_deferred(records))


def _run_qc11b_pin_length_node(
    cap: throwaway.ThrowawayCapability,
    p11_config: Any,
    *,
    op: str,
    _session_factory: throwaway.SessionFactory = throwaway.admin_session,
    _launch: throwaway.LaunchProbe = throwaway.launch_admin_probe,
) -> None:
    if op not in _QC11B_PIN_LENGTH_OPS:
        raise ValueError(f"unknown op {op!r}")
    with _session_factory(cap, prefix="pkcs11_check_qc11b_") as minted:
        rc, out, err = _launch(minted, "qc11b_pin_lengths", {"op": op}, p11_config=p11_config)
        trace = token_admin.check_child_output(rc, out, err, label=f"QC11b {op}")
        _judge_pin_lengths(trace, op=op)


class TestAdvertisedSessionLimits:
    """Open-until-refusal judged against the ADVERTISED session maxima (QC11b)."""

    def test_session_limit_matches_advertised_maxima(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        policy, info_rv = _read_session_policy(rs.raw, rs.slot_id)
        if policy is None:
            pytest.skip(
                f"QC11b: C_GetTokenInfo refused ({ckr_name(info_rv)}); "
                "advertised session maxima unreadable; limit MUSTs untestable"
            )
        owned: list[tuple[int, str]] = []
        deferred: list[classification.Classification] = []
        cleanup_errors: list[BaseException] = []
        pending: BaseException | None = None
        own_opens = 0
        refused_rv: int | None = None
        try:
            try:
                for _ in range(_QC11B_SESSION_SAFETY_CAP):
                    try:
                        handle = raw_open_session(
                            rs.raw, rs.slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION
                        )
                    except CkrAssertionError as exc:
                        refused_rv = exc.rv
                        break
                    owned.append((handle, "saturation"))
                    own_opens += 1
                reread, _ = _read_session_policy(rs.raw, rs.slot_id)
                total_now = reread.ambient_total if reread is not None else None
                rw_now = reread.ambient_rw if reread is not None else None
                _judge_session_exhaustion(
                    policy=policy,
                    own_opens=own_opens,
                    refused_rv=refused_rv,
                    total_now=total_now,
                    rw_now=rw_now,
                )
            except BaseException as exc:
                pending = exc
        finally:
            _close_owned_sessions(rs.raw, owned, deferred, cleanup_errors)
        _finish_session_attempt(pending, cleanup_errors, deferred)


@pytest.mark.destructive
class TestPinLengthPolicyOnDisposableToken:
    """PIN-length policy via InitPIN/SetPIN on disposable state (QC11b)."""

    def test_init_pin_length_policy(self, p11_config: Any) -> None:
        cap = throwaway.require_throwaway_capability()
        _run_qc11b_pin_length_node(cap, p11_config, op="init_pin")

    def test_set_pin_length_policy(self, p11_config: Any) -> None:
        cap = throwaway.require_throwaway_capability()
        _run_qc11b_pin_length_node(cap, p11_config, op="set_pin")
