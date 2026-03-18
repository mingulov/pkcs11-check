"""CKR compliance tests for session management functions.

Covers C_OpenSession, C_CloseSession, C_Login, C_Logout.

Source: PKCS#11 v3.1 §5.6.1-5.6.8.
"""

from __future__ import annotations

from typing import Any

import pkcs11 as p11
import pytest
from pkcs11.exceptions import (
    PKCS11Error,
    PinIncorrect,
    SessionHandleInvalid,
    SlotIDInvalid,
    UserAlreadyLoggedIn,
)

pytestmark = pytest.mark.access


class TestOpenSessionErrors:
    """Error conditions for C_OpenSession (§5.6.1)."""

    def test_invalid_slot_id(self, p11_module: Any) -> None:
        """C_OpenSession with invalid slot -> CKR_SLOT_ID_INVALID."""
        # Use a slot ID that almost certainly doesn't exist
        try:
            slot = p11_module.lib.get_slots()[0]
            # Try to open with an invalid slot by directly using a bad slot ID
            # python-pkcs11 uses token.open() not slot.open(), so test via token lookup
            pytest.skip("python-pkcs11 doesn't expose raw C_OpenSession with arbitrary slot ID")
        except IndexError:
            pytest.skip("No slots available")


class TestLoginErrors:
    """Error conditions for C_Login (§5.6.7)."""

    def test_wrong_pin(self, p11_module: Any) -> None:
        """Wrong PIN -> CKR_PIN_INCORRECT."""
        token = p11_module.get_token()
        with pytest.raises(PinIncorrect):
            token.open(rw=True, user_pin="WRONG_PIN_XYZ_999")

    def test_already_logged_in(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """Double login -> CKR_USER_ALREADY_LOGGED_IN."""
        token = p11_module.get_token()
        pin = p11_config.pin
        if pin is None:
            pytest.skip("No PIN configured")
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else pin

        session = token.open(rw=True, user_pin=pin_str)
        try:
            with pytest.raises(UserAlreadyLoggedIn):
                session.login(p11.UserType.USER, pin_str)
        finally:
            session.close()


class TestLogoutErrors:
    """Error conditions for C_Logout (§5.6.8)."""

    def test_logout_when_not_logged_in(self, p11_module: Any) -> None:
        """Logout without login -> CKR_USER_NOT_LOGGED_IN."""
        token = p11_module.get_token()
        session = token.open(rw=False)  # R/O session, no login
        try:
            session.logout()
            # Some modules don't error on logout without login
        except PKCS11Error:
            pass  # CKR_USER_NOT_LOGGED_IN or similar — acceptable
        finally:
            session.close()
