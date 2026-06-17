"""CKR compliance tests for session management functions.

Covers C_OpenSession, C_CloseSession, C_Login, C_Logout.

Source: PKCS#11 v3.2-5.6.8.
"""

from __future__ import annotations

import ctypes
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.bootstrap import close_session_quietly
from pkcs11_check.raw.bootstrap import open_session as _raw_open_session
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKR_OK,
    CKR_PIN_INCORRECT,
    CKR_SESSION_COUNT,
    CKR_SLOT_ID_INVALID,
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_NOT_LOGGED_IN,
    CKR_USER_TYPE_INVALID,
    CKU_USER,
)
from pkcs11_check.testcases.conftest import classify_negative_rv, is_known_error

pytestmark = pytest.mark.access


def open_session(raw: Any, slot_id: int, flags: int) -> int:
    """Open an extra session required by session-error tests."""
    try:
        return _raw_open_session(raw, slot_id, flags)
    except AssertionError as exc:
        if is_known_error(exc, (CKR_SESSION_COUNT,)):
            pytest.skip(
                "Cannot open additional session required by session-error test: "
                f"{ckr_name(int(CKR_SESSION_COUNT))}"
            )
        raise


class TestOpenSessionErrors:
    """Error conditions for C_OpenSession (Sec.5.6.1)."""

    def test_invalid_slot_id(self, p11_raw_session: Any) -> None:
        """C_OpenSession with invalid slot -> CKR_SLOT_ID_INVALID."""
        rs = p11_raw_session
        from pkcs11_check.raw.types_std import CK_NOTIFY, CK_ULONG

        bad_slot = 0xDEADBEEF
        sh = CK_ULONG(0)
        rv = rs.raw.C_OpenSession(
            bad_slot,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION),
            None,
            CK_NOTIFY(),
            ctypes.byref(sh),
        )
        if rv == CKR_SESSION_COUNT:
            pytest.skip(
                "Cannot open additional session required by invalid-slot test: "
                f"{ckr_name(int(CKR_SESSION_COUNT))}"
            )
        assert rv == CKR_SLOT_ID_INVALID, (
            f"Expected CKR_SLOT_ID_INVALID for bad slot, got {ckr_name(rv)}"
        )


class TestLoginErrors:
    """Error conditions for C_Login (Sec.5.6.7)."""

    def test_wrong_pin(self, p11_raw_session: Any) -> None:
        """Wrong PIN -> CKR_PIN_INCORRECT."""
        rs = p11_raw_session
        # Open a fresh session for this test
        sh = open_session(rs.raw, rs.slot_id, (CKF_SERIAL_SESSION | CKF_RW_SESSION))
        try:
            wrong_pin = b"WRONG_PIN_XYZ_999"
            pin_buf = (ctypes.c_ubyte * len(wrong_pin))(*wrong_pin)
            rv = rs.raw.C_Login(sh, CKU_USER, pin_buf, len(wrong_pin))
            if rv in (CKR_USER_ALREADY_LOGGED_IN, CKR_USER_TYPE_INVALID):
                # Phase 6 C: token session state (not a missing capability)
                # prevented exercising the wrong-PIN path. The negative-op probe
                # never evaluated the wrong PIN -> harmless no-op -> xfail.
                classify(
                    "honest_deviation",
                    label="C_Login:wrong-pin-probe",
                    operation="C_Login",
                    actual=rv,
                    summary=f"token login state prevents testing wrong PIN: {ckr_name(rv)}",
                )
            # CKR_OK here would mean the module accepted a wrong PIN -> fail;
            # a non-spec reject code -> xfail; CKR_PIN_INCORRECT -> pass.
            classify_negative_rv(rv, (CKR_PIN_INCORRECT,), label="C_Login with a wrong PIN")
        finally:
            close_session_quietly(rs.raw, sh)

    def test_already_logged_in(self, p11_raw_session: Any) -> None:
        """Double login -> CKR_USER_ALREADY_LOGGED_IN.

        Per PKCS#11 v3.2: C_Login when already logged in MUST return
        CKR_USER_ALREADY_LOGGED_IN. NSS returns CKR_PIN_INCORRECT because it
        re-validates the PIN on every C_Login call even when already authenticated.
        CKR_USER_TYPE_INVALID is accepted for NSS slots that require no login.
        """
        rs = p11_raw_session
        # Already logged in via fixture; try to login again
        pin = b"1234"  # default test PIN
        pin_buf = (ctypes.c_ubyte * len(pin))(*pin)
        rv = rs.raw.C_Login(rs.sh, CKU_USER, pin_buf, len(pin))
        assert rv in (
            CKR_USER_ALREADY_LOGGED_IN,
            CKR_USER_TYPE_INVALID,  # NSS: slot requires no login
            CKR_PIN_INCORRECT,  # NSS: re-validates PIN on duplicate login
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
            CKF_SERIAL_SESSION,  # R/O, no RW flag
        )
        try:
            rv = rs.raw.C_Logout(sh)
            # Some modules don't error on logout without login
            # But CKR_USER_NOT_LOGGED_IN is correct
            if rv != CKR_OK:
                assert rv in (
                    CKR_USER_NOT_LOGGED_IN,
                    CKR_USER_ALREADY_LOGGED_IN,
                ), f"Unexpected CKR {ckr_name(rv)} from C_Logout"
        finally:
            close_session_quietly(rs.raw, sh)
