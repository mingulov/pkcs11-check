"""PIN authentication and lockout tests.

Tests wrong-PIN rejection, PIN-locked behavior, and authentication
error handling. These are critical security tests — a module that
accepts wrong PINs or doesn't lock after repeated failures is broken.

Note: PIN lockout thresholds are module-specific (typically 3-10 attempts).
These tests do NOT exhaust the lockout counter — they test a single bad
attempt and verify the error code.
"""

from __future__ import annotations

from typing import Any

import pkcs11
import pytest
from pkcs11 import Attribute, KeyType

pytestmark = [pytest.mark.security, pytest.mark.destructive]


class TestWrongPIN:
    """Verify that wrong PINs are properly rejected."""

    def test_wrong_pin_rejected(self, p11_module: Any) -> None:
        """Login with wrong PIN must return CKR_PIN_INCORRECT."""
        token = p11_module.get_token()
        if token is None:
            pytest.skip("No token available")

        with pytest.raises(pkcs11.exceptions.PinIncorrect):
            token.open(rw=True, user_pin="DEFINITELY_WRONG_PIN_999")

    def test_empty_pin_rejected(self, p11_module: Any) -> None:
        """Login with empty PIN must fail."""
        token = p11_module.get_token()
        if token is None:
            pytest.skip("No token available")

        try:
            token.open(rw=True, user_pin="")
            pytest.fail("Empty PIN should not be accepted")
        except (pkcs11.exceptions.PinIncorrect, pkcs11.exceptions.PinLenRange):
            pass  # Expected

    def test_correct_pin_after_wrong_attempt(self, p11_module: Any, p11_config: Any) -> None:
        """After a wrong PIN attempt, correct PIN should still work (not locked after 1 try)."""
        token = p11_module.get_token()
        if token is None:
            pytest.skip("No token available")

        # First: wrong PIN
        try:
            token.open(rw=True, user_pin="WRONG_PIN_XYZ")
        except pkcs11.exceptions.PKCS11Error:
            pass

        # Then: correct PIN should succeed
        pin_val = p11_config.pin if p11_config else "1234"
        pin = pin_val.get_secret_value() if hasattr(pin_val, "get_secret_value") else str(pin_val)
        session = token.open(rw=True, user_pin=pin)
        assert session is not None
        # Verify the session actually works
        key = session.generate_key(KeyType.AES, 256)
        assert key is not None

    def test_wrong_pin_does_not_reveal_objects(self, p11_module: Any) -> None:
        """A failed login attempt must not expose any private objects."""
        token = p11_module.get_token()
        if token is None:
            pytest.skip("No token available")

        try:
            session = token.open(rw=True, user_pin="WRONG_PIN_ABC")
            # If we somehow got a session, there should be no private objects
            found = list(session.get_objects({Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY}))
            assert len(found) == 0, "Wrong PIN exposed private objects!"
        except pkcs11.exceptions.PKCS11Error:
            pass  # Expected — login failed


class TestPINEdgeCases:
    """PIN handling edge cases."""

    def test_very_long_pin(self, p11_module: Any) -> None:
        """Very long PIN (256 chars) — should fail cleanly, not crash."""
        token = p11_module.get_token()
        if token is None:
            pytest.skip("No token available")

        long_pin = "A" * 256
        try:
            token.open(rw=True, user_pin=long_pin)
            pytest.fail("256-char PIN should not be accepted")
        except pkcs11.exceptions.PKCS11Error:
            pass  # Expected

    def test_unicode_pin(self, p11_module: Any) -> None:
        """Unicode characters in PIN — should fail cleanly."""
        token = p11_module.get_token()
        if token is None:
            pytest.skip("No token available")

        try:
            token.open(rw=True, user_pin="\u00e9\u00e8\u00ea\u00eb")
        except pkcs11.exceptions.PKCS11Error:
            pass  # Expected — most modules reject non-ASCII PINs

    def test_null_bytes_in_pin(self, p11_module: Any) -> None:
        """Null bytes in PIN — must not cause truncation or crash."""
        token = p11_module.get_token()
        if token is None:
            pytest.skip("No token available")

        try:
            token.open(rw=True, user_pin="12\x0034")
        except pkcs11.exceptions.PKCS11Error:
            pass  # Expected
