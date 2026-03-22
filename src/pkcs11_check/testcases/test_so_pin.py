"""SO (Security Officer) login and PIN management tests.

Tests C_Login with CKU_SO, C_InitPIN, C_SetPIN.
Marked @destructive - these modify token PIN state.

Note: These tests require --p11-destructive flag AND knowledge of the
SO PIN. SoftHSM2 default SO PIN = same as user PIN during init.
Many modules have different SO PINs - tests skip if SO login fails.
"""

from __future__ import annotations

from typing import Any

import pkcs11
import pytest
from pkcs11 import KeyType

pytestmark = [pytest.mark.security, pytest.mark.destructive]


class TestSOLogin:
    """Test Security Officer login behavior."""

    def test_so_login_wrong_pin(self, p11_module: Any) -> None:
        """SO login with wrong PIN must fail."""
        token = p11_module.get_token()
        if token is None:
            pytest.skip("No token")

        try:
            # Open RW session without login, then try SO login
            session = token.open(rw=True)
            session.login(pkcs11.UserType.SO, "WRONG_SO_PIN_XYZ")
            pytest.fail("SO login with wrong PIN should fail")
        except pkcs11.exceptions.PinIncorrect:
            pass  # Expected
        except pkcs11.exceptions.PKCS11Error:
            pass  # Some modules return different error for SO

    def test_user_and_so_cannot_coexist(self, p11_session: Any, p11_module: Any) -> None:
        """Cannot login as SO when already logged in as user (same session)."""
        # p11_session is already logged in as user
        # Trying SO login should fail
        try:
            p11_session.login(pkcs11.UserType.SO, "1234")
            pytest.fail("SO login while user is logged in should fail")
        except pkcs11.exceptions.PKCS11Error:
            pass  # Expected - CKR_USER_ALREADY_LOGGED_IN or similar


class TestSetPIN:
    """Test C_SetPIN - user changes their own PIN."""

    def test_set_pin_changes_pin(self, p11_module: Any, p11_config: Any) -> None:
        """User can change their PIN, then login with new PIN."""
        token = p11_module.get_token()
        pin = p11_config.pin
        old_pin = pin.get_secret_value() if hasattr(pin, "get_secret_value") else pin

        new_pin = old_pin + "X"  # Slightly different

        try:
            with token.open(rw=True, user_pin=old_pin) as session:
                session.set_pin(old_pin, new_pin)
        except (pkcs11.exceptions.PKCS11Error, AttributeError):
            pytest.skip("C_SetPIN not supported or requires different permissions")
            return

        # Login with new PIN should work
        try:
            with token.open(rw=True, user_pin=new_pin) as session:
                key = session.generate_key(KeyType.AES, 256)
                assert key is not None
        finally:
            # Restore original PIN
            try:
                with token.open(rw=True, user_pin=new_pin) as session:
                    session.set_pin(new_pin, old_pin)
            except pkcs11.exceptions.PKCS11Error:
                pass  # Best effort restore
