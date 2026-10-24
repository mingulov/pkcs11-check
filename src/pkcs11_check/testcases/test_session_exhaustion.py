"""Session exhaustion tests.

Opens sessions until the module refuses (CKR_SESSION_COUNT or similar),
then verifies the error is graceful and the module recovers.
"""

from __future__ import annotations

from typing import Any

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
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKR_OK,
    CKR_SESSION_COUNT,
    CKU_USER,
)
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
