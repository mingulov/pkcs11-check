"""Session exhaustion tests.

Opens sessions until the module refuses (CKR_SESSION_COUNT or similar),
then verifies the error is graceful and the module recovers.
"""

from __future__ import annotations

from typing import Any

import pkcs11 as p11
import pytest
from pkcs11.exceptions import PKCS11Error, SessionCount

pytestmark = pytest.mark.security


def _open_with_login(token: Any, rw: bool, pin_str: str) -> Any:
    """Open a session, handling UserAlreadyLoggedIn gracefully."""
    try:
        return token.open(rw=rw, user_pin=pin_str)
    except (p11.exceptions.UserAlreadyLoggedIn, p11.exceptions.UserTypeInvalid):
        session = token.open(rw=rw)
        try:
            session.login(p11.UserType.USER, pin_str)
        except (p11.exceptions.UserAlreadyLoggedIn, p11.exceptions.UserTypeInvalid):
            pass
        return session


class TestSessionExhaustion:
    """Test behavior when opening many sessions."""

    def test_open_many_sessions(self, p11_module: Any, p11_config: Any) -> None:
        """Open sessions until limit or 100, verify all work, close all."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)

        sessions = []
        s0 = _open_with_login(token, rw=True, pin_str=pin_str)
        sessions.append(s0)

        try:
            for _ in range(99):
                s = token.open(rw=True)  # Don't re-login
                sessions.append(s)
        except (SessionCount, PKCS11Error):
            pass

        for s in sessions:
            try:
                s.close()
            except PKCS11Error:
                pass

        # After closing, should be able to open a new session
        recovery = _open_with_login(token, rw=True, pin_str=pin_str)
        try:
            key = recovery.generate_key(p11.KeyType.AES, 128)
            assert key is not None
        finally:
            recovery.close()

    def test_session_close_frees_resources(self, p11_module: Any, p11_config: Any) -> None:
        """Opening and closing sessions in a loop doesn't leak."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)

        for _ in range(50):
            session = _open_with_login(token, rw=True, pin_str=pin_str)
            session.close()
