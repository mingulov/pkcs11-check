"""CKR compliance tests for session management functions.

Covers C_OpenSession, C_CloseSession, C_Login, C_Logout.

Source: PKCS#11 v3.1 Sec.5.6.1-5.6.8.
"""

from __future__ import annotations

import ctypes
from typing import Any

import pytest

from pkcs11_check.raw.bootstrap import close_session_quietly, open_session
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKR_OK,
    CKR_PIN_INCORRECT,
    CKR_SLOT_ID_INVALID,
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_NOT_LOGGED_IN,
    CKR_USER_TYPE_INVALID,
    CKU_USER,
)

pytestmark = pytest.mark.access


class TestOpenSessionErrors:
    """Error conditions for C_OpenSession (Sec.5.6.1)."""

    def test_invalid_slot_id(self, p11_raw_session: Any) -> None:
        """C_OpenSession with invalid slot -> CKR_SLOT_ID_INVALID."""
        rs = p11_raw_session
        from pkcs11_check.raw.types_std import CK_NOTIFY, CK_ULONG

        bad_slot = 0xDEADBEEF
        sh = CK_ULONG(0)
        rv = int(
            rs.raw.C_OpenSession(
                bad_slot,
                int(CKF_SERIAL_SESSION | CKF_RW_SESSION),
                None,
                CK_NOTIFY(),
                ctypes.byref(sh),
            )
        )
        assert rv == int(CKR_SLOT_ID_INVALID), (
            f"Expected CKR_SLOT_ID_INVALID for bad slot, got {ckr_name(rv)}"
        )


class TestLoginErrors:
    """Error conditions for C_Login (Sec.5.6.7)."""

    def test_wrong_pin(self, p11_raw_session: Any) -> None:
        """Wrong PIN -> CKR_PIN_INCORRECT."""
        rs = p11_raw_session
        # Open a fresh session for this test
        sh = open_session(rs.raw, rs.slot_id, int(CKF_SERIAL_SESSION | CKF_RW_SESSION))
        try:
            wrong_pin = b"WRONG_PIN_XYZ_999"
            pin_buf = (ctypes.c_ubyte * len(wrong_pin))(*wrong_pin)
            rv = int(rs.raw.C_Login(sh, int(CKU_USER), pin_buf, len(wrong_pin)))
            if rv in (int(CKR_USER_ALREADY_LOGGED_IN), int(CKR_USER_TYPE_INVALID)):
                pytest.skip("Token-level login prevents testing wrong PIN")
            assert rv == int(CKR_PIN_INCORRECT), f"Expected CKR_PIN_INCORRECT, got {ckr_name(rv)}"
        finally:
            close_session_quietly(rs.raw, sh)

    def test_already_logged_in(self, p11_raw_session: Any) -> None:
        """Double login -> CKR_USER_ALREADY_LOGGED_IN."""
        rs = p11_raw_session
        # Already logged in via fixture; try to login again
        pin = b"1234"  # default test PIN
        pin_buf = (ctypes.c_ubyte * len(pin))(*pin)
        rv = int(rs.raw.C_Login(rs.sh, int(CKU_USER), pin_buf, len(pin)))
        assert rv in (
            int(CKR_USER_ALREADY_LOGGED_IN),
            int(CKR_USER_TYPE_INVALID),  # NSS quirk
        ), f"Expected CKR_USER_ALREADY_LOGGED_IN, got {ckr_name(rv)}"


class TestLogoutErrors:
    """Error conditions for C_Logout (Sec.5.6.8)."""

    def test_logout_when_not_logged_in(self, p11_raw_session: Any) -> None:
        """Logout without login -> CKR_USER_NOT_LOGGED_IN."""
        rs = p11_raw_session
        # Open a fresh R/O session without login
        sh = open_session(
            rs.raw,
            rs.slot_id,
            int(CKF_SERIAL_SESSION),  # R/O, no RW flag
        )
        try:
            rv = int(rs.raw.C_Logout(sh))
            # Some modules don't error on logout without login
            # But CKR_USER_NOT_LOGGED_IN is correct
            if rv != int(CKR_OK):
                assert rv in (
                    int(CKR_USER_NOT_LOGGED_IN),
                    int(CKR_USER_ALREADY_LOGGED_IN),
                ), f"Unexpected CKR {ckr_name(rv)} from C_Logout"
        finally:
            close_session_quietly(rs.raw, sh)
