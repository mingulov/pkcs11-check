"""SO (Security Officer) login and PIN management tests.

Tests C_Login with CKU_SO, C_InitPIN, C_SetPIN.
Marked @destructive - these modify token PIN state.

Note: These tests require --p11-destructive flag AND knowledge of the
SO PIN. SoftHSM2 default SO PIN = same as user PIN during init.
Many modules have different SO PINs - tests skip if SO login fails.
"""

from __future__ import annotations

from typing import Any

import pytest

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
    CK_UTF8CHAR,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_PIN_INCORRECT,
    CKR_PIN_INVALID,
    CKR_PIN_LEN_RANGE,
    CKR_PIN_LOCKED,
    CKR_SESSION_READ_ONLY,
    CKR_TOKEN_WRITE_PROTECTED,
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_NOT_LOGGED_IN,
    CKU_SO,
    CKU_USER,
)
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
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
        rv = rs.raw.C_Login(rs.sh, CKU_SO, pin_buf, len(pin_bytes))
        classify_negative_rv(
            rv,
            (CKR_USER_ALREADY_LOGGED_IN,),
            label="C_Login(SO) while already logged in as USER on the same session",
        )


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
                pass  # Best-effort restore; token may need re-init if this fails
            rs.raw.C_Logout(s2)
            close_session_quietly(rs.raw, s2)
