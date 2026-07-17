"""SO (Security Officer) login and PIN management tests.

Tests C_Login with CKU_SO, C_InitPIN, C_SetPIN.
Marked @destructive - these modify token PIN state.

Note: These tests require --p11-destructive flag AND knowledge of the
SO PIN. Many modules use a default SO PIN equal to the user PIN at init time.
Tests skip if SO login fails.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.classification import fail_as
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
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_NOT_LOGGED_IN,
    CKR_USER_PIN_NOT_INITIALIZED,
    CKR_USER_TYPE_INVALID,
    CKU_SO,
    CKU_USER,
)
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
        classify_negative_rv(
            rv,
            (CKR_USER_ALREADY_LOGGED_IN,),
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
