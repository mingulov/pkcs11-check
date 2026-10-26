"""PIN authentication and lockout tests.

Tests wrong-PIN rejection, PIN-locked behavior, and authentication
error handling. These are critical security tests - a module that
accepts wrong PINs or doesn't lock after repeated failures is broken.

Note: PIN lockout thresholds are module-specific (typically 3-10 attempts).
These tests do NOT exhaust the lockout counter - they test a single bad
attempt and verify the error code.

QC11a (below) adds sacrificial-token retry-countdown/lockout coverage: the new
test classes burn counters ONLY on throwaway tokens behind the explicit
three-variable capability, and judge strictly against declared retry policy and
counter metadata (no invented thresholds).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify, fail_as, xfail_as
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
)
from pkcs11_check.raw.rv import ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CK_UTF8CHAR,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKF_SO_PIN_COUNT_LOW,
    CKF_SO_PIN_FINAL_TRY,
    CKF_SO_PIN_LOCKED,
    CKF_USER_PIN_COUNT_LOW,
    CKF_USER_PIN_FINAL_TRY,
    CKF_USER_PIN_LOCKED,
    CKR_ARGUMENTS_BAD,
    CKR_OK,
    CKR_PIN_INCORRECT,
    CKR_PIN_LEN_RANGE,
    CKR_PIN_LOCKED,
    CKR_USER_ALREADY_LOGGED_IN,
    CKU_USER,
)
from pkcs11_check.testcases import _throwaway_token as throwaway
from pkcs11_check.testcases._probes import token_admin
from pkcs11_check.testcases.conftest import get_pin_bytes

# Acceptable CKR codes when an invalid PIN is supplied and rejected.
# CKR_USER_ALREADY_LOGGED_IN is included because the fixture's slot
# may already be authenticated; the session still cannot accept a new login.
_INVALID_PIN_CKRS = (
    CKR_PIN_INCORRECT,
    CKR_PIN_LEN_RANGE,
    CKR_PIN_LOCKED,
    CKR_ARGUMENTS_BAD,
    CKR_USER_ALREADY_LOGGED_IN,
)

pytestmark = [pytest.mark.security, pytest.mark.destructive]


def _try_login(raw: Any, sh: int, pin: bytes) -> int:
    """Attempt login and return raw CKR value."""
    pin_buf = (CK_UTF8CHAR * len(pin))(*pin)
    return int(raw.C_Login(sh, CKU_USER, pin_buf, len(pin)))


class TestWrongPIN:
    """Verify that wrong PINs are properly rejected."""

    def test_wrong_pin_rejected(self, p11_raw_session: Any) -> None:
        """Login with wrong PIN must return CKR_PIN_INCORRECT."""
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            rv = _try_login(rs.raw, test_sh, b"DEFINITELY_WRONG_PIN_999")
            assert rv in (
                CKR_PIN_INCORRECT,
                CKR_USER_ALREADY_LOGGED_IN,
            ), f"Expected CKR_PIN_INCORRECT, got {ckr_name(rv)}"
        finally:
            close_session_quietly(rs.raw, test_sh)

    def test_empty_pin_rejected(self, p11_raw_session: Any) -> None:
        """Login with empty PIN must fail."""
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            # Empty PIN - pass NULL pointer with length 0
            rv = rs.raw.C_Login(test_sh, CKU_USER, None, 0)
            assert rv in _INVALID_PIN_CKRS, f"Empty PIN should not be accepted, got {ckr_name(rv)}"
        finally:
            close_session_quietly(rs.raw, test_sh)

    def test_correct_pin_after_wrong_attempt(self, p11_raw_session: Any, p11_config: Any) -> None:
        """After a wrong PIN attempt, correct PIN should still work (not locked after 1 try)."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # First: wrong PIN
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            _try_login(rs.raw, test_sh, b"WRONG_PIN_XYZ")
        finally:
            close_session_quietly(rs.raw, test_sh)

        # Then: correct PIN should succeed
        test_sh2 = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            login_user(rs.raw, test_sh2, CKU_USER, pin_bytes)
            # Verify the session actually works
            key_h = gen_aes_key(rs.raw, test_sh2, 256)
            assert key_h != 0
            destroy_quietly(rs.raw, test_sh2, key_h)
        finally:
            rs.raw.C_Logout(test_sh2)
            close_session_quietly(rs.raw, test_sh2)

    def test_wrong_pin_does_not_reveal_objects(self, p11_raw_session: Any) -> None:
        """A failed login attempt must not expose any private objects."""
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            rv = _try_login(rs.raw, test_sh, b"WRONG_PIN_ABC")
            if rv == CKR_OK:
                # A wrong PIN that logs in is an authentication bypass:
                # fail outright -- "no objects found" must not rescue it.
                classify(
                    "accepted_invalid",
                    label="C_Login with a wrong PIN",
                    operation="C_Login",
                    actual=rv,
                    summary="module accepted a wrong PIN (authentication bypass)",
                )
            # Otherwise login failed - expected
        finally:
            close_session_quietly(rs.raw, test_sh)


class TestPINEdgeCases:
    """PIN handling edge cases."""

    def test_very_long_pin(self, p11_raw_session: Any) -> None:
        """Very long PIN (256 chars) - should fail cleanly, not crash."""
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            long_pin = b"A" * 256
            rv = _try_login(rs.raw, test_sh, long_pin)
            assert rv in _INVALID_PIN_CKRS, (
                f"256-char PIN should not be accepted, got {ckr_name(rv)}"
            )
        finally:
            close_session_quietly(rs.raw, test_sh)

    def test_unicode_pin(self, p11_raw_session: Any) -> None:
        """Unicode characters in PIN - should fail cleanly."""
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            unicode_pin = "\u00e9\u00e8\u00ea\u00eb".encode()
            rv = _try_login(rs.raw, test_sh, unicode_pin)
            # Most modules reject non-ASCII PINs - any non-crash result is acceptable
            _ = rv
        finally:
            close_session_quietly(rs.raw, test_sh)

    def test_null_bytes_in_pin(self, p11_raw_session: Any) -> None:
        """Null bytes in PIN - must not cause truncation or crash."""
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            null_pin = b"12\x0034"
            rv = _try_login(rs.raw, test_sh, null_pin)
            # Any non-crash result is acceptable
            _ = rv
        finally:
            close_session_quietly(rs.raw, test_sh)


# --- QC11a: sacrificial-token retry countdown and lockout (#52.6) -------------

_QC11A_CANONICAL_WRONG = (int(CKR_PIN_INCORRECT),)
_QC11A_CANONICAL_LOCKED = (int(CKR_PIN_LOCKED),)
_QC11A_ROLE_FLAGS = {
    "user": (
        int(CKF_USER_PIN_COUNT_LOW),
        int(CKF_USER_PIN_FINAL_TRY),
        int(CKF_USER_PIN_LOCKED),
    ),
    "so": (
        int(CKF_SO_PIN_COUNT_LOW),
        int(CKF_SO_PIN_FINAL_TRY),
        int(CKF_SO_PIN_LOCKED),
    ),
}
_QC11A_COUNTDOWN_ATTEMPTS = 3
_QC11A_LOCKOUT_ATTEMPTS = 10
_QC11A_INDEPENDENCE_ATTEMPTS = 2
_QC11A_PERSISTENCE_ATTEMPTS = 2
_QC11A_RESET_ATTEMPTS = 10


def _qc11a_role_flags(role: str) -> tuple[int, int, int]:
    try:
        return _QC11A_ROLE_FLAGS[role]
    except KeyError:
        raise ValueError(f"unknown role {role!r}") from None


def _qc11a_flag_rank(flags: int, role: str) -> int:
    low, final, locked = _qc11a_role_flags(role)
    if flags & locked:
        return 3
    if flags & final:
        return 2
    if flags & low:
        return 1
    return 0


def _qc11a_wrong_steps(
    trace: token_admin.AdminTrace, role: str
) -> tuple[list[token_admin.AdminStep], list[token_admin.AdminStep]]:
    wrongs = [s for s in trace.steps if s.name.startswith(f"login:{role}:wrong:")]
    posts = [s for s in trace.steps if s.name.startswith(f"login:{role}:post:")]
    return wrongs, posts


def _qc11a_attempt_entries(trace: token_admin.AdminTrace, role: str) -> list[dict[str, object]]:
    wrongs, posts = _qc11a_wrong_steps(trace, role)
    attempt_flags = [v for tag, v in trace.flags if tag.startswith("attempt-")]
    post_flags = [v for tag, v in trace.flags if tag.startswith("post-")]
    entries: list[dict[str, object]] = []
    for i, step in enumerate(wrongs):
        paired = attempt_flags[i] if i < len(attempt_flags) else None
        entries.append(
            {
                "op": step.name,
                "rv": ckr_name(step.rv),
                "flags": f"0x{paired:08x}" if paired is not None else "unknown",
            }
        )
    for j, step in enumerate(posts):
        paired = post_flags[j] if j < len(post_flags) else None
        entries.append(
            {
                "op": step.name,
                "rv": ckr_name(step.rv),
                "flags": f"0x{paired:08x}" if paired is not None else "unknown",
            }
        )
    return entries


def _qc11a_pre_lockout_evidence(trace: token_admin.AdminTrace, role: str) -> bool:
    """Pre-success lockout evidence: a LOCKED wrong RV or LOCKED initial/attempt flag."""
    _, _, locked = _qc11a_role_flags(role)
    wrongs, _ = _qc11a_wrong_steps(trace, role)
    if any(step.rv == int(CKR_PIN_LOCKED) for step in wrongs):
        return True
    for tag, value in trace.flags:
        if value is None:
            continue
        if tag == "initial" or tag.startswith("attempt-"):
            if value & locked:
                return True
    return False


def _qc11a_any_lockout_evidence(trace: token_admin.AdminTrace, role: str) -> bool:
    if _qc11a_pre_lockout_evidence(trace, role):
        return True
    _, _, locked = _qc11a_role_flags(role)
    for step in trace.steps:
        if step.name == f"login:{role}:correct" or step.name.startswith(f"login:{role}:post:"):
            if step.rv == int(CKR_PIN_LOCKED):
                return True
    for tag, value in trace.flags:
        if value is None:
            continue
        if tag.startswith("post-") or tag == "final":
            if value & locked:
                return True
    return False


def _qc11a_judge_wrong_step(
    step: token_admin.AdminStep,
    paired_flags: int | None,
    *,
    role: str,
    label: str,
    detail: dict[str, Any],
    fails_only: bool = False,
) -> None:
    """Judge one wrong-PIN step; with ``fails_only`` xfail tiers are skipped, not raised."""
    rv = step.rv
    if rv == int(CKR_OK):
        fail_as(
            "accepted_invalid",
            label=f"{label}: {step.name}",
            operation="C_Login",
            mechanism=None,
            inherit_mechanism=False,
            expected=_QC11A_CANONICAL_WRONG,
            actual=rv,
            summary=f"{label}: module accepted a wrong {role} PIN (authentication bypass)",
            detail=detail,
        )
    if not (is_standard_ckr(rv) or is_vendor_defined_ckr(rv)):
        fail_as(
            "self_contradiction",
            kind="metadata",
            label=f"{label}: {step.name}",
            operation="C_Login",
            mechanism=None,
            inherit_mechanism=False,
            expected=_QC11A_CANONICAL_WRONG,
            actual=rv,
            summary=f"{label}: wrong-PIN login returned undefined CK_RV {ckr_name(rv)}",
            detail=detail,
        )
    if rv not in _QC11A_CANONICAL_WRONG + _QC11A_CANONICAL_LOCKED:
        # Prescan falls through: a non-canonical refusal beside LOCKED metadata
        # is still a flag contradiction worth a FAIL.
        if not fails_only:
            xfail_as(
                "nonspec_reject",
                label=f"{label}: {step.name}",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                expected=_QC11A_CANONICAL_WRONG + _QC11A_CANONICAL_LOCKED,
                actual=rv,
                summary=f"{label}: wrong-PIN login refused with {ckr_name(rv)}",
                detail=detail,
            )
    if paired_flags is not None:
        _, _, locked = _qc11a_role_flags(role)
        if paired_flags & locked and rv != int(CKR_PIN_LOCKED):
            fail_as(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: {step.name}",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                expected=_QC11A_CANONICAL_LOCKED,
                actual=rv,
                summary=f"{label}: behavior contradicts LOCKED counter metadata",
                detail=detail,
            )
        if rv == int(CKR_PIN_LOCKED) and not (paired_flags & locked):
            if not fails_only:
                xfail_as(
                    "honest_deviation",
                    kind="metadata",
                    label=f"{label}: {step.name}",
                    operation="C_Login",
                    mechanism=None,
                    inherit_mechanism=False,
                    actual=rv,
                    summary=f"{label}: LOCKED refusal without LOCKED counter metadata",
                    detail=detail,
                )


def _qc11a_judge_correct_step(
    step: token_admin.AdminStep,
    *,
    role: str,
    label: str,
    detail: dict[str, Any],
    evidence: bool,
    final_flags: int | None,
    post_explains_lockout: bool,
    fails_only: bool = False,
) -> None:
    """Judge one correct-PIN step; with ``fails_only`` xfail tiers are skipped, not raised."""
    rv = step.rv
    if rv == int(CKR_OK):
        if evidence:
            fail_as(
                "accepted_invalid",
                label=f"{label}: {step.name}",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                expected=_QC11A_CANONICAL_LOCKED,
                actual=rv,
                summary=f"{label}: correct {role} PIN accepted despite lockout evidence",
                detail=detail,
            )
        _, _, locked = _qc11a_role_flags(role)
        if final_flags is not None and (final_flags & locked) and not post_explains_lockout:
            fail_as(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: {step.name}",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                actual=rv,
                summary=f"{label}: token reports LOCKED after a successful login with no burns",
                detail=detail,
            )
        return
    if not (is_standard_ckr(rv) or is_vendor_defined_ckr(rv)):
        fail_as(
            "self_contradiction",
            kind="metadata",
            label=f"{label}: {step.name}",
            operation="C_Login",
            mechanism=None,
            inherit_mechanism=False,
            actual=rv,
            summary=f"{label}: correct-PIN login returned undefined CK_RV {ckr_name(rv)}",
            detail=detail,
        )
    if rv == int(CKR_PIN_LOCKED):
        if evidence:
            return
        if not fails_only:
            xfail_as(
                "honest_deviation",
                kind="metadata",
                label=f"{label}: {step.name}",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                actual=rv,
                summary=f"{label}: correct PIN locked without lockout evidence",
                detail=detail,
            )
        return
    if evidence:
        fail_as(
            "self_contradiction",
            kind="metadata",
            label=f"{label}: {step.name}",
            operation="C_Login",
            mechanism=None,
            inherit_mechanism=False,
            expected=_QC11A_CANONICAL_LOCKED,
            actual=rv,
            summary=f"{label}: correct-PIN outcome denies declared lockout",
            detail=detail,
        )
    if not fails_only:
        xfail_as(
            "not_operational",
            label=f"{label}: {step.name}",
            operation="C_Login",
            mechanism=None,
            inherit_mechanism=False,
            actual=rv,
            summary=f"{label}: correct PIN refused on an unlocked token",
            detail=detail,
        )


def _qc11a_judge_flag_sequences(
    trace: token_admin.AdminTrace,
    *,
    role: str,
    label: str,
    detail: dict[str, Any],
    success: bool,
) -> None:
    _, final, locked = _qc11a_role_flags(role)
    for tag, value in trace.flags:
        if value is not None and (value & final) and (value & locked):
            fail_as(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: {tag}",
                operation="C_GetTokenInfo",
                mechanism=None,
                inherit_mechanism=False,
                actual=value,
                summary=f"{label}: {tag} sets FINAL_TRY and LOCKED together",
                detail=detail,
            )

    def _check_non_decreasing(known: list[int], what: str) -> None:
        ranks = [_qc11a_flag_rank(value, role) for value in known]
        for before, after in zip(ranks, ranks[1:]):
            if after < before:
                fail_as(
                    "self_contradiction",
                    kind="metadata",
                    label=label,
                    operation="C_GetTokenInfo",
                    mechanism=None,
                    inherit_mechanism=False,
                    summary=f"{label}: counter flags regressed {what} without success",
                    detail=detail,
                )

    pre = [
        v
        for tag, v in trace.flags
        if (tag == "initial" or tag.startswith("attempt-")) and v is not None
    ]
    post = [v for tag, v in trace.flags if tag.startswith("post-") and v is not None]
    finals = [v for tag, v in trace.flags if tag == "final" and v is not None]
    _check_non_decreasing(pre, "across attempts")
    _check_non_decreasing(post, "after success")
    if not success:
        _check_non_decreasing(pre + post + finals, "up to final")


def _run_lockout_judges(
    trace: token_admin.AdminTrace,
    *,
    role: str,
    label: str,
    detail: dict[str, Any],
    fails_only: bool,
) -> None:
    """Run the per-step and flag-sequence judges once in trace order."""
    _, _, locked = _qc11a_role_flags(role)
    wrongs, posts = _qc11a_wrong_steps(trace, role)
    attempt_flags = [v for tag, v in trace.flags if tag.startswith("attempt-")]
    post_flags = [v for tag, v in trace.flags if tag.startswith("post-")]
    for i, step in enumerate(wrongs):
        paired = attempt_flags[i] if i < len(attempt_flags) else None
        _qc11a_judge_wrong_step(
            step, paired, role=role, label=label, detail=detail, fails_only=fails_only
        )
    for j, step in enumerate(posts):
        paired = post_flags[j] if j < len(post_flags) else None
        _qc11a_judge_wrong_step(
            step, paired, role=role, label=label, detail=detail, fails_only=fails_only
        )
    correct = next((s for s in trace.steps if s.name == f"login:{role}:correct"), None)
    evidence = _qc11a_pre_lockout_evidence(trace, role)
    post_explains = any(s.rv == int(CKR_PIN_LOCKED) for s in posts) or any(
        v is not None and (v & locked) for v in post_flags
    )
    if correct is not None:
        _qc11a_judge_correct_step(
            correct,
            role=role,
            label=label,
            detail=detail,
            evidence=evidence,
            final_flags=dict(trace.flags).get("final"),
            post_explains_lockout=post_explains,
            fails_only=fails_only,
        )
    _qc11a_judge_flag_sequences(
        trace,
        role=role,
        label=label,
        detail=detail,
        success=(correct is not None and correct.rv == int(CKR_OK)),
    )


def _prescan_lockout_fails(trace: token_admin.AdminTrace, *, role: str) -> None:
    """FAIL-grade half of the lockout judge; xfail tiers suppressed, never raised."""
    label = f"QC11a {role} countdown"
    detail: dict[str, Any] = {"role": role, "attempts": _qc11a_attempt_entries(trace, role)}
    _run_lockout_judges(trace, role=role, label=label, detail=detail, fails_only=True)


def _fail_on_undefined_snapshots(
    trace: token_admin.AdminTrace, *, label: str, detail: dict[str, Any]
) -> None:
    """R19-04: undefined ``snapshot:*`` RVs FAIL; defined snapshot failures stay tolerated."""
    for step in trace.steps:
        if step.name == "snapshot" or step.name.startswith("snapshot:"):
            if not (is_standard_ckr(step.rv) or is_vendor_defined_ckr(step.rv)):
                fail_as(
                    "self_contradiction",
                    kind="metadata",
                    label=f"{label}: {step.name}",
                    operation="C_GetTokenInfo",
                    mechanism=None,
                    inherit_mechanism=False,
                    actual=step.rv,
                    summary=f"{label}: token snapshot returned undefined CK_RV {ckr_name(step.rv)}",
                    detail=detail,
                )


def _judge_lockout_trace(trace: token_admin.AdminTrace, *, role: str) -> None:
    """Judge one burn trace for countdown consistency (acceptance/contradiction fail)."""
    low, final, locked = _qc11a_role_flags(role)
    label = f"QC11a {role} countdown"
    initial = dict(trace.flags).get("initial")
    if initial is not None:
        assert not (initial & (low | final | locked)), (
            f"{label}: burn premise broken: initial flags not pristine ({initial:#x})"
        )
    # R14-03: FAIL-grade observations (acceptance, undefined RVs, flag
    # contradictions) preempt earlier xfail tiers — prescan first, then tier.
    _prescan_lockout_fails(trace, role=role)
    detail: dict[str, Any] = {"role": role, "attempts": _qc11a_attempt_entries(trace, role)}
    _run_lockout_judges(trace, role=role, label=label, detail=detail, fails_only=False)


def _judge_lockout_enforced(trace: token_admin.AdminTrace, *, role: str) -> None:
    """Lockout node: consistency first, then evidence gate, else untestable skip."""
    _judge_lockout_trace(trace, role=role)
    if _qc11a_any_lockout_evidence(trace, role):
        return
    wrongs, _ = _qc11a_wrong_steps(trace, role)
    rvs = ", ".join(ckr_name(step.rv) for step in wrongs) or "no attempts"
    pytest.skip(
        f"QC11a {role} lockout unreached within {len(wrongs)} attempts ({rvs}) "
        "and no threshold declared; lockout MUST untestable"
    )


def _judge_independence_fails(
    trace: token_admin.AdminTrace,
    *,
    other_step: token_admin.AdminStep,
    initial: int | None,
    other_bits: int,
    burned_role: str,
    other: str,
    label: str,
    detail: dict[str, Any],
) -> None:
    """FAIL-grade half of independence: premise-guarded, runs before trace tiers."""
    for tag, value in trace.flags:
        if tag == "initial" or value is None:
            continue
        if (value & other_bits) and not ((initial or 0) & other_bits):
            fail_as(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: {tag}",
                operation="C_GetTokenInfo",
                mechanism=None,
                inherit_mechanism=False,
                actual=value,
                summary=f"{label}: {burned_role} failures consumed the {other} retry counter",
                detail=detail,
            )
    rv = other_step.rv
    if rv == int(CKR_OK):
        return
    if not (is_standard_ckr(rv) or is_vendor_defined_ckr(rv)):
        fail_as(
            "self_contradiction",
            kind="metadata",
            label=f"{label}: {other_step.name}",
            operation="C_Login",
            mechanism=None,
            inherit_mechanism=False,
            actual=rv,
            summary=f"{label}: other-role login returned undefined CK_RV {ckr_name(rv)}",
            detail=detail,
        )
    if rv == int(CKR_PIN_LOCKED) and initial is not None and not (initial & other_bits):
        fail_as(
            "self_contradiction",
            kind="metadata",
            label=f"{label}: {other_step.name}",
            operation="C_Login",
            mechanism=None,
            inherit_mechanism=False,
            actual=rv,
            summary=f"{label}: {other} locked by {burned_role} failures alone",
            detail=detail,
        )


def _judge_independence(trace: token_admin.AdminTrace, *, burned_role: str) -> None:
    """Burned-role failures must not consume the other role's retry counter."""
    other = "so" if burned_role == "user" else "user"
    label = f"QC11a {burned_role}/{other} independence"
    detail: dict[str, Any] = {
        "burned_role": burned_role,
        "attempts": _qc11a_attempt_entries(trace, burned_role),
    }
    other_step = next((s for s in trace.steps if s.name == f"login:{other}:correct"), None)
    assert other_step is not None, f"{label}: missing other-role check step"
    by_tag = dict(trace.flags)
    initial = by_tag.get("initial")
    other_bits = 0
    for bit in _qc11a_role_flags(other):
        other_bits |= bit
    # R1-remainder: own FAIL grades preempt lockout-trace xfail tiers. The
    # premise-needing checks stay guarded (a broken premise keeps them silent,
    # so the skip below still wins over them); the premise-free undefined-RV
    # check fails loud regardless of the premise.
    _judge_independence_fails(
        trace,
        other_step=other_step,
        initial=initial,
        other_bits=other_bits,
        burned_role=burned_role,
        other=other,
        label=label,
        detail=detail,
    )
    _judge_lockout_trace(trace, role=burned_role)
    if initial is not None and (initial & other_bits):
        pytest.skip(f"{label}: other-role counter not pristine at start; independence untestable")
    rv = other_step.rv
    if rv == int(CKR_OK):
        return
    if rv == int(CKR_PIN_LOCKED):
        # Pristine-initial LOCKED already failed above; only an unreadable
        # initial reaches this tier.
        xfail_as(
            "honest_deviation",
            kind="metadata",
            label=f"{label}: {other_step.name}",
            operation="C_Login",
            mechanism=None,
            inherit_mechanism=False,
            actual=rv,
            summary=f"{label}: other-role locked without counter evidence",
            detail=detail,
        )
    xfail_as(
        "not_operational",
        label=f"{label}: {other_step.name}",
        operation="C_Login",
        mechanism=None,
        inherit_mechanism=False,
        actual=rv,
        summary=f"{label}: other-role login refused with {ckr_name(rv)}",
        detail=detail,
    )


def _judge_success_reset(trace: token_admin.AdminTrace, *, role: str) -> None:
    """A success must restart the counter: post-success wear below pre-success wear."""
    _judge_lockout_trace(trace, role=role)
    label = f"QC11a {role} success reset"
    detail: dict[str, Any] = {"role": role, "attempts": _qc11a_attempt_entries(trace, role)}
    correct = next((s for s in trace.steps if s.name == f"login:{role}:correct"), None)
    if correct is None or correct.rv != int(CKR_OK):
        pytest.skip(f"{label}: success not achieved; reset untestable")
    attempt_known = [v for tag, v in trace.flags if tag.startswith("attempt-") and v is not None]
    post_known = [v for tag, v in trace.flags if tag.startswith("post-") and v is not None]
    if not attempt_known or not post_known:
        pytest.skip(f"{label}: pre/post counter unreadable or missing; reset untestable")
    pre = _qc11a_flag_rank(attempt_known[-1], role)
    post = _qc11a_flag_rank(post_known[-1], role)
    if pre == 0:
        pytest.skip(f"{label}: no countdown observed before success; reset untestable")
    if post < pre:
        return
    if post > pre:
        xfail_as(
            "honest_deviation",
            kind="metadata",
            label=label,
            operation="C_Login",
            mechanism=None,
            inherit_mechanism=False,
            summary=f"{label}: counter did not reset after success (rank {pre} -> {post})",
            detail=detail,
        )
    pytest.skip(f"{label}: equal rank {pre}; buckets too coarse, reset unproven; untestable")


def _judge_restart_persistence_fails(
    *,
    role: str,
    correct: token_admin.AdminStep,
    last_before: int | None,
    second: token_admin.AdminTrace,
    second_initial: int | None,
    label: str,
    detail: dict[str, Any],
) -> None:
    """FAIL-grade half of restart persistence; runs before first-trace tiers."""
    _fail_on_undefined_snapshots(second, label=label, detail=detail)
    _, _, locked = _qc11a_role_flags(role)
    if (
        last_before is not None
        and second_initial is not None
        and _qc11a_flag_rank(second_initial, role) > _qc11a_flag_rank(last_before, role)
    ):
        fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation="C_GetTokenInfo",
            mechanism=None,
            inherit_mechanism=False,
            summary=f"{label}: counter escalated across restart with no intervening attempts",
            detail=detail,
        )
    before_locked = last_before is not None and bool(last_before & locked)
    now_locked = second_initial is not None and bool(second_initial & locked)
    rv = correct.rv
    if rv == int(CKR_OK):
        if now_locked:
            fail_as(
                "accepted_invalid",
                label=f"{label}: {correct.name}",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                expected=_QC11A_CANONICAL_LOCKED,
                actual=rv,
                summary=f"{label}: correct PIN accepted despite LOCKED flags after restart",
                detail=detail,
            )
        return
    if not (is_standard_ckr(rv) or is_vendor_defined_ckr(rv)):
        fail_as(
            "self_contradiction",
            kind="metadata",
            label=f"{label}: {correct.name}",
            operation="C_Login",
            mechanism=None,
            inherit_mechanism=False,
            actual=rv,
            summary=f"{label}: correct-PIN login returned undefined CK_RV {ckr_name(rv)}",
            detail=detail,
        )
    if rv == int(CKR_PIN_LOCKED):
        # LOCKED tiers are judged after the first-trace pass.
        return
    if before_locked or now_locked:
        fail_as(
            "self_contradiction",
            kind="metadata",
            label=f"{label}: {correct.name}",
            operation="C_Login",
            mechanism=None,
            inherit_mechanism=False,
            expected=_QC11A_CANONICAL_LOCKED,
            actual=rv,
            summary=f"{label}: correct-PIN outcome denies declared lockout",
            detail=detail,
        )


def _judge_restart_persistence(
    first: token_admin.AdminTrace, second: token_admin.AdminTrace, *, role: str
) -> None:
    """Restart must not contradict counter state; persistence itself is not a MUST."""
    label = f"QC11a {role} restart persistence"
    detail: dict[str, Any] = {
        "role": role,
        "first_attempts": _qc11a_attempt_entries(first, role),
        "second_attempts": _qc11a_attempt_entries(second, role),
    }
    _, _, locked = _qc11a_role_flags(role)
    first_known = [v for _, v in first.flags if v is not None]
    last_before = first_known[-1] if first_known else None
    second_initial = dict(second.flags).get("initial")
    correct = next((s for s in second.steps if s.name == f"login:{role}:correct"), None)
    assert correct is not None, f"{label}: phase-2 probe contract broken (no correct step)"
    # R1-remainder: own FAIL grades preempt first-trace xfail tiers.
    _judge_restart_persistence_fails(
        role=role,
        correct=correct,
        last_before=last_before,
        second=second,
        second_initial=second_initial,
        label=label,
        detail=detail,
    )
    _judge_lockout_trace(first, role=role)
    before_locked = last_before is not None and bool(last_before & locked)
    now_locked = second_initial is not None and bool(second_initial & locked)
    rv = correct.rv
    if rv == int(CKR_OK):
        # Accepted-despite-LOCKED already failed above.
        return
    if rv == int(CKR_PIN_LOCKED):
        if before_locked or now_locked:
            return
        visible = any(
            value is not None and _qc11a_flag_rank(value, role) > 0
            for value in [v for _, v in first.flags] + [v for _, v in second.flags]
        )
        if visible:
            xfail_as(
                "honest_deviation",
                kind="metadata",
                label=f"{label}: {correct.name}",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                actual=rv,
                summary=f"{label}: LOCKED declared after restart without lockout metadata",
                detail=detail,
            )
        return
    # Undefined RVs and locked-evidence denials already failed above.
    xfail_as(
        "not_operational",
        label=f"{label}: {correct.name}",
        operation="C_Login",
        mechanism=None,
        inherit_mechanism=False,
        actual=rv,
        summary=f"{label}: correct PIN refused on an unlocked token after restart",
        detail=detail,
    )


def _run_qc11a_burn_node(
    cap: throwaway.ThrowawayCapability,
    p11_config: Any,
    *,
    role: str,
    mode: str,
    _session_factory: throwaway.SessionFactory = throwaway.admin_session,
    _launch: throwaway.LaunchProbe = throwaway.launch_admin_probe,
) -> None:
    if mode == "countdown":
        attempts = _QC11A_COUNTDOWN_ATTEMPTS
    elif mode == "lockout":
        attempts = _QC11A_LOCKOUT_ATTEMPTS
    else:
        raise ValueError(f"unknown mode {mode!r}")
    with _session_factory(cap, prefix="pkcs11_check_qc11a_") as minted:
        rc, out, err = _launch(
            minted,
            "qc11a_burn",
            {
                "role": role,
                "attempts": attempts,
                "then_correct": True,
                "then_other_role_correct": False,
                "post_success_wrongs": 0,
            },
            p11_config=p11_config,
        )
        trace = token_admin.check_child_output(rc, out, err, label=f"QC11a {role} {mode}")
        if mode == "lockout":
            _judge_lockout_enforced(trace, role=role)
        else:
            _judge_lockout_trace(trace, role=role)


def _run_qc11a_independence_node(
    cap: throwaway.ThrowawayCapability,
    p11_config: Any,
    *,
    burned_role: str,
    _session_factory: throwaway.SessionFactory = throwaway.admin_session,
    _launch: throwaway.LaunchProbe = throwaway.launch_admin_probe,
) -> None:
    with _session_factory(cap, prefix="pkcs11_check_qc11a_") as minted:
        rc, out, err = _launch(
            minted,
            "qc11a_burn",
            {
                "role": burned_role,
                "attempts": _QC11A_INDEPENDENCE_ATTEMPTS,
                "then_correct": False,
                "then_other_role_correct": True,
                "post_success_wrongs": 0,
            },
            p11_config=p11_config,
        )
        trace = token_admin.check_child_output(
            rc, out, err, label=f"QC11a {burned_role} independence"
        )
        _judge_independence(trace, burned_role=burned_role)


def _run_qc11a_reset_node(
    cap: throwaway.ThrowawayCapability,
    p11_config: Any,
    *,
    role: str,
    _session_factory: throwaway.SessionFactory = throwaway.admin_session,
    _launch: throwaway.LaunchProbe = throwaway.launch_admin_probe,
) -> None:
    with _session_factory(cap, prefix="pkcs11_check_qc11a_") as minted:
        rc, out, err = _launch(
            minted,
            "qc11a_burn",
            {
                "role": role,
                "attempts": _QC11A_RESET_ATTEMPTS,
                "then_correct": True,
                "then_other_role_correct": False,
                "post_success_wrongs": 1,
                "stop_at": "final",
            },
            p11_config=p11_config,
        )
        trace = token_admin.check_child_output(rc, out, err, label=f"QC11a {role} reset")
        _judge_success_reset(trace, role=role)


def _run_qc11a_persistence_node(
    cap: throwaway.ThrowawayCapability,
    p11_config: Any,
    *,
    role: str,
    _session_factory: throwaway.SessionFactory = throwaway.admin_session,
    _launch: throwaway.LaunchProbe = throwaway.launch_admin_probe,
) -> None:
    with _session_factory(cap, prefix="pkcs11_check_qc11a_") as minted:
        rc1, out1, err1 = _launch(
            minted,
            "qc11a_burn",
            {
                "role": role,
                "attempts": _QC11A_PERSISTENCE_ATTEMPTS,
                "then_correct": False,
                "then_other_role_correct": False,
                "post_success_wrongs": 0,
            },
            p11_config=p11_config,
        )
        first = token_admin.check_child_output(rc1, out1, err1, label=f"QC11a {role} persist/1")
        rc2, out2, err2 = _launch(
            minted,
            "qc11a_read",
            {"role": role},
            p11_config=p11_config,
        )
        # R19-02 collect-then-judge: when phase two would skip, phase-one FAIL
        # grades (and phase-two undefined snapshots) preempt the skip.
        second_raw = token_admin.parse_child_output(
            rc2, out2, err2, label=f"QC11a {role} persist/2"
        )
        if token_admin.trace_skip_reason(second_raw) is not None:
            _prescan_lockout_fails(first, role=role)
            _fail_on_undefined_snapshots(
                second_raw,
                label=f"QC11a {role} restart persistence",
                detail={
                    "role": role,
                    "first_attempts": _qc11a_attempt_entries(first, role),
                    "second_attempts": _qc11a_attempt_entries(second_raw, role),
                },
            )
        second = token_admin.gate_child_trace(second_raw, label=f"QC11a {role} persist/2")
        _judge_restart_persistence(first, second, role=role)


class TestUserLockoutCountdown:
    """USER retry countdown and lockout on a sacrificial token (QC11a)."""

    def test_user_countdown_consistent(self, p11_config: Any) -> None:
        cap = throwaway.require_throwaway_capability()
        _run_qc11a_burn_node(cap, p11_config, role="user", mode="countdown")

    def test_user_lockout_enforced(self, p11_config: Any) -> None:
        cap = throwaway.require_throwaway_capability()
        _run_qc11a_burn_node(cap, p11_config, role="user", mode="lockout")


class TestSOLockoutCountdown:
    """SO retry countdown and lockout on a sacrificial token (QC11a)."""

    def test_so_countdown_consistent(self, p11_config: Any) -> None:
        cap = throwaway.require_throwaway_capability()
        _run_qc11a_burn_node(cap, p11_config, role="so", mode="countdown")

    def test_so_lockout_enforced(self, p11_config: Any) -> None:
        cap = throwaway.require_throwaway_capability()
        _run_qc11a_burn_node(cap, p11_config, role="so", mode="lockout")


class TestRoleCounterIndependence:
    """One role's failures must not consume the other role's counter (QC11a)."""

    def test_user_failures_leave_so_usable(self, p11_config: Any) -> None:
        cap = throwaway.require_throwaway_capability()
        _run_qc11a_independence_node(cap, p11_config, burned_role="user")

    def test_so_failures_leave_user_usable(self, p11_config: Any) -> None:
        cap = throwaway.require_throwaway_capability()
        _run_qc11a_independence_node(cap, p11_config, burned_role="so")


class TestCounterSuccessReset:
    """A successful login restarts the retry counter (QC11a)."""

    def test_user_success_resets_counter(self, p11_config: Any) -> None:
        cap = throwaway.require_throwaway_capability()
        _run_qc11a_reset_node(cap, p11_config, role="user")

    def test_so_success_resets_counter(self, p11_config: Any) -> None:
        cap = throwaway.require_throwaway_capability()
        _run_qc11a_reset_node(cap, p11_config, role="so")


class TestCounterRestartPersistence:
    """Counter state must not contradict itself across a restart (QC11a)."""

    def test_user_counter_restart_persistence(self, p11_config: Any) -> None:
        cap = throwaway.require_throwaway_capability()
        _run_qc11a_persistence_node(cap, p11_config, role="user")

    def test_so_counter_restart_persistence(self, p11_config: Any) -> None:
        cap = throwaway.require_throwaway_capability()
        _run_qc11a_persistence_node(cap, p11_config, role="so")
