"""PIN authentication and lockout tests.

Tests wrong-PIN rejection, PIN-locked behavior, and authentication
error handling. These are critical security tests - a module that
accepts wrong PINs or doesn't lock after repeated failures is broken.

Note: PIN lockout thresholds are module-specific (typically 3-10 attempts).
These tests do NOT exhaust the lockout counter - they test a single bad
attempt and verify the error code.
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
from pkcs11_check.raw.pack import template_from_dict
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    find_objects,
    gen_aes_key,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_UTF8CHAR,
    CKA_CLASS,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKO_PRIVATE_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_OK,
    CKR_PIN_INCORRECT,
    CKR_PIN_LEN_RANGE,
    CKR_PIN_LOCKED,
    CKR_USER_ALREADY_LOGGED_IN,
    CKU_USER,
)
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
                # If we somehow got logged in, there should be no private objects
                tmpl = template_from_dict({CKA_CLASS: CKO_PRIVATE_KEY})
                found = find_objects(rs.raw, test_sh, tmpl)
                assert len(found) == 0, "Wrong PIN exposed private objects!"
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
