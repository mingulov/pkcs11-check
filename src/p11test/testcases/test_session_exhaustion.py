"""Session exhaustion tests.

Opens sessions until the module refuses (CKR_SESSION_COUNT or similar),
then verifies the error is graceful and the module recovers.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11.exceptions import PKCS11Error, SessionCount

pytestmark = pytest.mark.security


class TestSessionExhaustion:
    """Test behavior when opening many sessions."""

    def test_open_many_sessions(self, p11_module: Any, p11_config: Any) -> None:
        """Open sessions until limit or 100, verify all work, close all."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)

        sessions = []
        # First session logs in
        s0 = token.open(rw=True, user_pin=pin_str)
        sessions.append(s0)

        try:
            for _ in range(99):  # Try up to 100 total
                s = token.open(rw=True)  # Don't re-login
                sessions.append(s)
        except (SessionCount, PKCS11Error):
            pass  # Expected when session limit reached

        # Whether or not we hit a limit, close all sessions cleanly
        for s in sessions:
            try:
                s.close()
            except PKCS11Error:
                pass

        # After closing, should be able to open a new session
        with token.open(rw=True, user_pin=pin_str) as recovery:
            # Verify the module still works
            from pkcs11 import KeyType

            key = recovery.generate_key(KeyType.AES, 128)
            assert key is not None

    def test_session_close_frees_resources(self, p11_module: Any, p11_config: Any) -> None:
        """Opening and closing sessions in a loop doesn't leak."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)

        for _ in range(50):
            with token.open(rw=True, user_pin=pin_str):
                pass  # Just open and close
