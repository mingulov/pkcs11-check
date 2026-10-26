"""SO (Security Officer) login and PIN management tests.

Tests C_Login with CKU_SO, C_InitPIN, C_SetPIN.
Marked @destructive - these modify token PIN state.

Note: These tests require --p11-destructive flag AND knowledge of the
SO PIN. Many modules use a default SO PIN equal to the user PIN at init time.
Tests skip if SO login fails.

QC11c (below) adds a sacrificial-token provisioning journey: InitToken ->
SO -> InitPIN -> USER -> SetPIN -> old rejected/new accepted -> restart ->
verify, ALL on throwaway tokens behind the explicit capability, judged
against declared behavior (genuinely unsupported steps become an explicit
unexercised-lifecycle outcome, never a green journey).
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.classification import (
    Classification,
    fail_as,
    raise_for_record,
    record_as,
)
from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
    login_user,
)
from pkcs11_check.raw.bootstrap import (
    open_session as raw_open_session,
)
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    set_pin,
)
from pkcs11_check.raw.rv import ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CK_TOKEN_INFO,
    CK_UTF8CHAR,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKF_TOKEN_INITIALIZED,
    CKF_USER_PIN_INITIALIZED,
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_OK,
    CKR_PIN_INCORRECT,
    CKR_PIN_INVALID,
    CKR_PIN_LEN_RANGE,
    CKR_PIN_LOCKED,
    CKR_SESSION_READ_ONLY,
    CKR_TOKEN_WRITE_PROTECTED,
    CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
    CKR_USER_NOT_LOGGED_IN,
    CKR_USER_PIN_NOT_INITIALIZED,
    CKR_USER_TYPE_INVALID,
    CKU_SO,
    CKU_USER,
)
from pkcs11_check.testcases import _throwaway_token as throwaway
from pkcs11_check.testcases._probes import token_admin
from pkcs11_check.testcases._so_login import guard_so_lockout, resolve_so_pin
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    get_pin_bytes,
    is_known_error,
    xfail_if_known_ckr,
)

# SO-login guards classify 3-way via classify_negative_rv: a wrong-PIN /
# conflicting SO login that succeeds (CKR_OK) -> fail, the spec-preferred code
# -> pass, any other clean reject (CKR_PIN_LOCKED, CKR_ARGUMENTS_BAD, ...) ->
# xfail.

_SET_PIN_POLICY_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_PIN_INCORRECT,
    CKR_PIN_INVALID,
    CKR_PIN_LEN_RANGE,
    CKR_PIN_LOCKED,
    CKR_SESSION_READ_ONLY,
    CKR_TOKEN_WRITE_PROTECTED,
    CKR_USER_NOT_LOGGED_IN,
)

_SET_PIN_RUNTIME_REJECT_RVS = (
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
)

pytestmark = [pytest.mark.security, pytest.mark.destructive]


class TestSOLogin:
    """Test Security Officer login behavior."""

    def test_so_login_wrong_pin(self, p11_raw_session: Any) -> None:
        """SO login with wrong PIN must fail."""
        rs = p11_raw_session
        # Deliberate wrong-PIN probe: burns one SO retry-counter step. Only run
        # with a pristine counter - skip if ANY CKF_SO_PIN_* counter flag is set.
        guard_so_lockout(rs.raw, rs.slot_id, explicit=False, require_pristine=True)
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            wrong_pin = b"WRONG_SO_PIN_XYZ"
            pin_buf = (CK_UTF8CHAR * len(wrong_pin))(*wrong_pin)
            rv = rs.raw.C_Login(test_sh, CKU_SO, pin_buf, len(wrong_pin))
            classify_negative_rv(
                rv,
                (CKR_PIN_INCORRECT,),
                label="C_Login(SO) with a wrong SO PIN",
            )
        finally:
            close_session_quietly(rs.raw, test_sh)

    def test_user_and_so_cannot_coexist(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Cannot login as SO when already logged in as user (same session)."""
        rs = p11_raw_session
        # p11_raw_session is already logged in as user
        # Trying SO login should fail
        so_pin, explicit = resolve_so_pin(p11_config)
        if so_pin is None:
            pytest.skip("No PIN configured")
        guard_so_lockout(rs.raw, rs.slot_id, explicit=explicit)
        pin_buf = (CK_UTF8CHAR * len(so_pin))(*so_pin)
        rv = rs.raw.C_Login(rs.sh, CKU_SO, pin_buf, len(so_pin))
        # M-19: a *different* user type already logged in -> ANOTHER_ALREADY
        # (ALREADY is same-type double login; see CKR_SESSION table entry).
        classify_negative_rv(
            rv,
            (CKR_USER_ANOTHER_ALREADY_LOGGED_IN,),
            label="C_Login(SO) while already logged in as USER on the same session",
        )

    def test_so_empty_pin_must_not_fail_open(self, p11_raw_session: Any) -> None:
        """SO login with an empty PIN on an unprovisioned token must be rejected.

        PKCS#11 §11.4 C_Login: authentication must not succeed unless a valid
        credential was previously established via C_InitToken/C_SetPIN. A token
        that has never been provisioned has no SO PIN set; accepting an empty PIN
        would grant an authenticated RW_SO session without any credential, violating
        the authentication requirement (fail-open / auth bypass).

        Safety gate: if the token is already provisioned (CKF_TOKEN_INITIALIZED or
        CKF_USER_PIN_INITIALIZED set), this probe is not applicable — the token has
        a real SO PIN and the empty-PIN rejection does not distinguish auth enforcement
        from PIN mismatch.  Skip without mutating any state.
        """
        rs = p11_raw_session

        # This probe deliberately does NOT call guard_so_lockout (unlike the other
        # CKU_SO login sites in this module): the applicability gate below already
        # skips whenever CKF_TOKEN_INITIALIZED or CKF_USER_PIN_INITIALIZED is set,
        # and any token exposing SO-counter flags is necessarily provisioned - so
        # this probe can never reach C_Login on a real, counter-bearing token.

        # Safety gate: read token flags (read-only, no state mutation).
        token_info = CK_TOKEN_INFO()
        info_rv = rs.raw.C_GetTokenInfo(rs.slot_id, byref(token_info))
        if info_rv == CKR_OK:
            flags = token_info.flags
            if (flags & CKF_TOKEN_INITIALIZED) or (flags & CKF_USER_PIN_INITIALIZED):
                pytest.skip(
                    "token already provisioned — empty-SO-PIN fail-open probe not applicable"
                )

        # Probe: open a RW session and attempt SO login with an empty PIN.
        # Only read-only C_GetTokenInfo has run so far; nothing has mutated token state.
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION
        probe_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            # An empty PIN is a NON-NULL pointer to a zero-length buffer with ulPinLen=0.
            # A NULL pPin (per PKCS#11 §11.4) would request the protected authentication
            # path instead, which is a different operation than an empty-PIN credential.
            empty_pin = (CK_UTF8CHAR * 1)()
            rv = rs.raw.C_Login(probe_sh, CKU_SO, empty_pin, 0)
            if rv == CKR_OK:
                # Authenticated RW_SO session granted with no credential: auth fail-open.
                # Logout best-effort before classifying (do NOT mutate state while logged in).
                rs.raw.C_Logout(probe_sh)
                fail_as(
                    "self_contradiction",
                    kind="policy",
                    label=(
                        "SO login with an empty PIN succeeded on an unprovisioned token"
                        " (authentication fail-open / bypass)"
                    ),
                )
            classify_negative_rv(
                rv,
                (
                    CKR_PIN_INCORRECT,
                    CKR_PIN_LEN_RANGE,
                    CKR_USER_PIN_NOT_INITIALIZED,
                    CKR_USER_TYPE_INVALID,
                    CKR_ARGUMENTS_BAD,
                ),
                label="C_Login(SO, empty PIN) on an unprovisioned token is rejected",
                kind="policy",
            )
        finally:
            close_session_quietly(rs.raw, probe_sh)


class TestSetPIN:
    """Test C_SetPIN - user changes their own PIN."""

    def test_set_pin_changes_pin(self, p11_raw_session: Any, p11_config: Any) -> None:
        """User can change their PIN, then login with new PIN."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION

        new_pin = pin_bytes + b"X"

        # Open a session and change the PIN
        s1 = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            login_user(rs.raw, s1, CKU_USER, pin_bytes)
            try:
                set_pin(rs.raw, s1, pin_bytes, new_pin)
            except AssertionError as exc:
                if is_known_error(exc, _SET_PIN_POLICY_REJECT_RVS):
                    pytest.skip(f"C_SetPIN not usable with configured token policy: {exc}")
                xfail_if_known_ckr(
                    exc,
                    _SET_PIN_RUNTIME_REJECT_RVS,
                    "C_SetPIN rejected valid PIN-change setup",
                )
                raise  # unreachable
            rs.raw.C_Logout(s1)
        finally:
            close_session_quietly(rs.raw, s1)

        # Login with new PIN should work
        s2 = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            login_user(rs.raw, s2, CKU_USER, new_pin)
            key_h = gen_aes_key(rs.raw, s2, 256)
            assert key_h != 0
            destroy_quietly(rs.raw, s2, key_h)
        finally:
            # Restore original PIN
            try:
                set_pin(rs.raw, s2, new_pin, pin_bytes)
            except AssertionError:
                pass  # audit-ok: best-effort PIN restore in cleanup, not the assertion under test
            rs.raw.C_Logout(s2)
            close_session_quietly(rs.raw, s2)


# --- QC11c: sacrificial provisioning journey (#52.8) ----------------------------

_QC11C_JOURNEY_POSITIVE_STEPS = ("init_token", "so_login", "init_pin", "user_login", "set_pin")
_QC11C_STEP_OPERATIONS = {
    "init_token": "C_InitToken",
    "so_login": "C_Login",
    "init_pin": "C_InitPIN",
    "user_login": "C_Login",
    "set_pin": "C_SetPIN",
    "old_rejected": "C_Login",
    "new_accepted": "C_Login",
    "create_canary": "C_CreateObject",
}
_QC11C_CANONICAL_OLD_REJECTED = (int(CKR_PIN_INCORRECT),)


def _qc11c_step_map(trace: token_admin.AdminTrace) -> dict[str, int]:
    by_name: dict[str, int] = {}
    for step in trace.steps:
        by_name.setdefault(step.name, step.rv)
    return by_name


def _assess_provision_journey(
    trace: token_admin.AdminTrace,
) -> tuple[list[Classification], bool]:
    """Assess one journey trace; returns (records, reached-provisioned-state)."""
    by_name = _qc11c_step_map(trace)
    by_flag = dict(trace.flags)
    records: list[Classification] = []
    label = "QC11c provisioning journey"
    detail: dict[str, Any] = {
        "steps": {step.name: ckr_name(step.rv) for step in trace.steps},
        "inv": list(trace.inv_objects),
    }
    # F1: token-info reads that went undefined FAIL, even when the functional
    # legs passed (same doctrine as R19-04 phase-two snapshots).
    records.extend(token_admin.undefined_snapshot_records(trace, label=label, detail=detail))
    reached = True
    refused_name: str | None = None
    for name in _QC11C_JOURNEY_POSITIVE_STEPS:
        rv = by_name.get(name)
        assert rv is not None, f"{label}: journey trace incomplete at {name}"
        if rv == int(CKR_OK):
            continue
        reached = False
        refused_name = name
        operation = _QC11C_STEP_OPERATIONS[name]
        if not (is_standard_ckr(rv) or is_vendor_defined_ckr(rv)):
            records.append(
                record_as(
                    "self_contradiction",
                    kind="metadata",
                    label=f"{label}: {name}",
                    operation=operation,
                    mechanism=None,
                    inherit_mechanism=False,
                    actual=rv,
                    summary=f"{label}: {name} returned undefined CK_RV",
                    detail=detail,
                )
            )
        else:
            records.append(
                record_as(
                    "not_operational",
                    label=f"{label}: {name}",
                    operation=operation,
                    mechanism=None,
                    inherit_mechanism=False,
                    actual=rv,
                    summary=f"{label}: unexercised lifecycle: {name} refused with {ckr_name(rv)}",
                    detail=detail,
                )
            )
        break
    if not reached:
        assert refused_name is not None
        _assess_journey_refusal_fallout(trace, by_name, by_flag, refused_name, records, detail)
        return records, False
    old = by_name.get("old_rejected")
    assert old is not None, f"{label}: missing old_rejected step"
    if old == int(CKR_OK):
        records.append(
            record_as(
                "accepted_invalid",
                kind="lifecycle",
                label=f"{label}: old_rejected",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                expected=_QC11C_CANONICAL_OLD_REJECTED,
                actual=old,
                summary=f"{label}: old PIN still accepted after SetPIN",
                detail=detail,
            )
        )
    elif not (is_standard_ckr(old) or is_vendor_defined_ckr(old)):
        records.append(
            record_as(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: old_rejected",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                actual=old,
                summary=f"{label}: old-PIN probe returned undefined CK_RV",
                detail=detail,
            )
        )
    elif old != int(CKR_PIN_INCORRECT):
        records.append(
            record_as(
                "nonspec_reject",
                label=f"{label}: old_rejected",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                expected=_QC11C_CANONICAL_OLD_REJECTED,
                actual=old,
                summary=f"{label}: old PIN rejected with {ckr_name(old)}",
                detail=detail,
            )
        )
    new = by_name.get("new_accepted")
    assert new is not None, f"{label}: missing new_accepted step"
    if new == int(CKR_OK):
        pass
    elif not (is_standard_ckr(new) or is_vendor_defined_ckr(new)):
        records.append(
            record_as(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: new_accepted",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                actual=new,
                summary=f"{label}: new-PIN probe returned undefined CK_RV",
                detail=detail,
            )
        )
    else:
        records.append(
            record_as(
                "not_operational",
                label=f"{label}: new_accepted",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                actual=new,
                summary=f"{label}: new PIN refused with {ckr_name(new)}",
                detail=detail,
            )
        )
    canary = by_name.get("create_canary")
    assert canary is not None, f"{label}: missing create_canary step"
    canary_ok = canary == int(CKR_OK)
    if not canary_ok:
        if not (is_standard_ckr(canary) or is_vendor_defined_ckr(canary)):
            records.append(
                record_as(
                    "self_contradiction",
                    kind="metadata",
                    label=f"{label}: create_canary",
                    operation="C_CreateObject",
                    mechanism=None,
                    inherit_mechanism=False,
                    actual=canary,
                    summary=f"{label}: canary create returned undefined CK_RV",
                    detail=detail,
                )
            )
        else:
            records.append(
                record_as(
                    "not_operational",
                    label=f"{label}: create_canary",
                    operation="C_CreateObject",
                    mechanism=None,
                    inherit_mechanism=False,
                    actual=canary,
                    summary=f"{label}: canary create refused with {ckr_name(canary)}",
                    detail=detail,
                )
            )
    if canary_ok:
        if not trace.inv_objects:
            records.append(
                record_as(
                    "not_operational",
                    label=f"{label}: inventory",
                    operation="C_FindObjects",
                    mechanism=None,
                    inherit_mechanism=False,
                    summary=f"{label}: canary inventory unreadable",
                    detail=detail,
                )
            )
        elif trace.inv_objects[-1] == 0:
            records.append(
                record_as(
                    "self_contradiction",
                    kind="lifecycle",
                    label=f"{label}: inventory",
                    operation="C_FindObjects",
                    mechanism=None,
                    inherit_mechanism=False,
                    summary=f"{label}: canary created-then-gone",
                    detail=detail,
                )
            )
    after_init = by_flag.get("after_init_token")
    if after_init is not None and not (after_init & int(CKF_TOKEN_INITIALIZED)):
        records.append(
            record_as(
                "honest_deviation",
                kind="metadata",
                label=f"{label}: after_init_token",
                operation="C_GetTokenInfo",
                mechanism=None,
                inherit_mechanism=False,
                summary=f"{label}: TOKEN_INITIALIZED unset after successful InitToken",
                detail=detail,
            )
        )
    after_ip = by_flag.get("after_init_pin")
    if after_ip is not None and not (after_ip & int(CKF_USER_PIN_INITIALIZED)):
        records.append(
            record_as(
                "honest_deviation",
                kind="metadata",
                label=f"{label}: after_init_pin",
                operation="C_GetTokenInfo",
                mechanism=None,
                inherit_mechanism=False,
                summary=f"{label}: USER_PIN_INITIALIZED unset after successful InitPIN",
                detail=detail,
            )
        )
    return records, True


def _assess_journey_refusal_fallout(
    trace: token_admin.AdminTrace,
    by_name: dict[str, int],
    by_flag: dict[str, int | None],
    refused_name: str,
    records: list[Classification],
    detail: dict[str, Any],
) -> None:
    """No-mutation checks for the refused provisioning step (refused ops stay inert)."""
    label = "QC11c provisioning journey"
    if refused_name == "init_pin":
        after = by_flag.get("after_init_pin")
        if after is not None and (after & int(CKF_USER_PIN_INITIALIZED)):
            records.append(
                record_as(
                    "self_contradiction",
                    kind="lifecycle",
                    label=f"{label}: after_init_pin",
                    operation="C_GetTokenInfo",
                    mechanism=None,
                    inherit_mechanism=False,
                    summary=f"{label}: refused InitPIN left USER_PIN_INITIALIZED set",
                    detail=detail,
                )
            )
        return
    if refused_name != "set_pin":
        return
    old_probe = by_name.get("verify:old_after_refused_setpin")
    new_probe = by_name.get("verify:new_after_refused_setpin")
    assert old_probe is not None and new_probe is not None, (
        f"{label}: missing verify steps after refused SetPIN"
    )
    if new_probe == int(CKR_OK):
        records.append(
            record_as(
                "self_contradiction",
                kind="lifecycle",
                label=f"{label}: verify:new_after_refused_setpin",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                actual=new_probe,
                summary=f"{label}: SetPIN refused yet new PIN works",
                detail=detail,
            )
        )
    elif not (is_standard_ckr(new_probe) or is_vendor_defined_ckr(new_probe)) or not (
        is_standard_ckr(old_probe) or is_vendor_defined_ckr(old_probe)
    ):
        records.append(
            record_as(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: verify",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                summary=f"{label}: no-mutation probes returned undefined CK_RV",
                detail=detail,
            )
        )
    elif old_probe == int(CKR_OK) and new_probe == int(CKR_PIN_INCORRECT):
        pass
    elif old_probe == int(CKR_OK):
        records.append(
            record_as(
                "nonspec_reject",
                label=f"{label}: verify:new_after_refused_setpin",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                expected=_QC11C_CANONICAL_OLD_REJECTED,
                actual=new_probe,
                summary=(
                    f"{label}: new PIN rejected with {ckr_name(new_probe)} after refused SetPIN"
                ),
                detail=detail,
            )
        )
    else:
        records.append(
            record_as(
                "not_operational",
                label=f"{label}: verify:old_after_refused_setpin",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                actual=old_probe,
                summary=f"{label}: old-PIN login refused after refused SetPIN (state unreadable)",
                detail=detail,
            )
        )
    after_refused = by_flag.get("after_refused_setpin")
    if after_refused is not None and not (after_refused & int(CKF_USER_PIN_INITIALIZED)):
        records.append(
            record_as(
                "self_contradiction",
                kind="lifecycle",
                label=f"{label}: after_refused_setpin",
                operation="C_GetTokenInfo",
                mechanism=None,
                inherit_mechanism=False,
                summary=f"{label}: refused SetPIN cleared USER_PIN_INITIALIZED",
                detail=detail,
            )
        )


def _canary_established(phase1: token_admin.AdminTrace) -> bool:
    """True when phase 1 proved a live canary (created OK and inventoried present)."""
    if _qc11c_step_map(phase1).get("create_canary") != int(CKR_OK):
        return False
    return bool(phase1.inv_objects) and phase1.inv_objects[-1] > 0


def _assess_provision_persistence(
    trace: token_admin.AdminTrace, *, canary_established: bool
) -> list[Classification]:
    """Assess the restart re-verification trace (new PIN works, old rejected, canary kept)."""
    by_name = _qc11c_step_map(trace)
    records: list[Classification] = []
    label = "QC11c provisioning persistence"
    detail: dict[str, Any] = {
        "steps": {step.name: ckr_name(step.rv) for step in trace.steps},
        "inv": list(trace.inv_objects),
    }
    # F1: token-info reads that went undefined FAIL, even when the functional
    # legs passed (same doctrine as R19-04 phase-two snapshots).
    records.extend(token_admin.undefined_snapshot_records(trace, label=label, detail=detail))
    old = by_name.get("old_rejected")
    assert old is not None, f"{label}: missing old_rejected step"
    if old == int(CKR_OK):
        records.append(
            record_as(
                "accepted_invalid",
                kind="lifecycle",
                label=f"{label}: old_rejected",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                expected=_QC11C_CANONICAL_OLD_REJECTED,
                actual=old,
                summary=f"{label}: old PIN accepted after restart",
                detail=detail,
            )
        )
    elif not (is_standard_ckr(old) or is_vendor_defined_ckr(old)):
        records.append(
            record_as(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: old_rejected",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                actual=old,
                summary=f"{label}: old-PIN probe returned undefined CK_RV",
                detail=detail,
            )
        )
    elif old != int(CKR_PIN_INCORRECT):
        records.append(
            record_as(
                "nonspec_reject",
                label=f"{label}: old_rejected",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                expected=_QC11C_CANONICAL_OLD_REJECTED,
                actual=old,
                summary=f"{label}: old PIN rejected with {ckr_name(old)}",
                detail=detail,
            )
        )
    new = by_name.get("new_accepted")
    assert new is not None, f"{label}: missing new_accepted step"
    if new == int(CKR_OK):
        pass
    elif not (is_standard_ckr(new) or is_vendor_defined_ckr(new)):
        records.append(
            record_as(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: new_accepted",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                actual=new,
                summary=f"{label}: new-PIN probe returned undefined CK_RV",
                detail=detail,
            )
        )
    else:
        records.append(
            record_as(
                "not_operational",
                label=f"{label}: new_accepted",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                actual=new,
                summary=f"{label}: new PIN refused after restart with {ckr_name(new)}",
                detail=detail,
            )
        )
    # Without phase-1 establishment the canary leg is unexercised (the phase-1
    # setup-failure records carry the verdict); only an established-then-lost
    # canary proves a persistence failure.
    if not canary_established:
        return records
    if not trace.inv_objects:
        records.append(
            record_as(
                "not_operational",
                label=f"{label}: inventory",
                operation="C_FindObjects",
                mechanism=None,
                inherit_mechanism=False,
                summary=f"{label}: canary inventory unreadable after restart",
                detail=detail,
            )
        )
    elif trace.inv_objects[-1] == 0:
        records.append(
            record_as(
                "self_contradiction",
                kind="lifecycle",
                label=f"{label}: inventory",
                operation="C_FindObjects",
                mechanism=None,
                inherit_mechanism=False,
                summary=f"{label}: canary lost across restart",
                detail=detail,
            )
        )
    return records


def _raise_strongest_qc11c(records: list[Classification]) -> None:
    """Raise the strongest collected record (fail beats xfail; ties keep first)."""
    if not records:
        return
    rank = {"pass": 0, "xfail": 1, "fail": 2}
    raise_for_record(max(records, key=lambda rec: rank[rec.outcome]))


def _raise_qc11c_fail_grades(records: list[Classification]) -> None:
    """Raise the strongest fail-grade record; xfail grades never preempt a skip."""
    fails = [rec for rec in records if rec.outcome == "fail"]
    if fails:
        _raise_strongest_qc11c(fails)


def _qc11c_snapshot_detail(trace: token_admin.AdminTrace) -> dict[str, Any]:
    """Steps/inv detail for QC11c same-trace snapshot prescans (R20-01).

    Mirrors the detail the QC11c assessors attach to their snapshot records so
    the prescan judges the same grades the gate skip would otherwise mask.
    """
    return {
        "steps": {step.name: ckr_name(step.rv) for step in trace.steps},
        "inv": list(trace.inv_objects),
    }


def _run_qc11c_journey_node(
    cap: throwaway.ThrowawayCapability,
    p11_config: Any,
    *,
    _session_factory: throwaway.SessionFactory = throwaway.admin_session,
    _launch: throwaway.LaunchProbe = throwaway.launch_admin_probe,
) -> None:
    with _session_factory(cap, prefix="pkcs11_check_qc11c_") as minted:
        rc1, out1, err1 = _launch(minted, "qc11c_journey", {}, p11_config=p11_config)
        # R20-01a collect-then-judge (same trace): when phase one would skip,
        # its own undefined-snapshot FAIL grades preempt the skip. The raising
        # twin is required: the assessor asserts completeness, which a
        # setup-failed trace cannot satisfy.
        phase1_raw = token_admin.parse_child_output(rc1, out1, err1, label="QC11c journey")
        if token_admin.trace_skip_reason(phase1_raw) is not None:
            token_admin.fail_on_undefined_snapshots(
                phase1_raw,
                label="QC11c provisioning journey",
                detail=_qc11c_snapshot_detail(phase1_raw),
            )
        phase1 = token_admin.gate_child_trace(phase1_raw, label="QC11c journey")
        records1, reached = _assess_provision_journey(phase1)
        if not reached:
            assert records1, "QC11c journey: unreached without any record"
            _raise_strongest_qc11c(records1)
            return
        rc2, out2, err2 = _launch(minted, "qc11c_verify", {}, p11_config=p11_config)
        # R19-02 collect-then-judge: when phase two would skip, phase-one FAIL
        # grades preempt the skip.
        phase2_raw = token_admin.parse_child_output(rc2, out2, err2, label="QC11c verify")
        if token_admin.trace_skip_reason(phase2_raw, no_slots="fail") is not None:
            _raise_qc11c_fail_grades(records1)
        phase2 = token_admin.gate_child_trace(phase2_raw, label="QC11c verify", no_slots="fail")
        records2 = _assess_provision_persistence(
            phase2, canary_established=_canary_established(phase1)
        )
        _raise_strongest_qc11c(records1 + records2)


class TestSacrificialProvisioningJourney:
    """Full provisioning journey with restart re-verification (QC11c)."""

    def test_sacrificial_provisioning_journey(self, p11_config: Any) -> None:
        cap = throwaway.require_throwaway_capability()
        _run_qc11c_journey_node(cap, p11_config)
