"""Session info tests.

Tests C_GetSessionInfo to verify session state, flags,
and login status are correctly reported.
"""

from __future__ import annotations

from typing import Any

import pkcs11
import pytest

pytestmark = pytest.mark.access


def _open_session(token: Any, rw: bool, pin_str: str) -> Any:
    """Open a session, handling UserAlreadyLoggedIn gracefully."""
    try:
        return token.open(rw=rw, user_pin=pin_str)
    except (pkcs11.exceptions.UserAlreadyLoggedIn, pkcs11.exceptions.UserTypeInvalid):
        session = token.open(rw=rw)
        try:
            session.login(pkcs11.UserType.USER, pin_str)
        except (pkcs11.exceptions.UserAlreadyLoggedIn, pkcs11.exceptions.UserTypeInvalid):
            pass
        return session


class TestSessionInfo:
    """Test C_GetSessionInfo via python-pkcs11 session properties."""

    def test_rw_session_is_rw(self, p11_module: Any, p11_config: Any) -> None:
        """R/W session reports correct state."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else pin

        session = _open_session(token, rw=True, pin_str=pin_str)
        try:
            assert session.rw is True
        finally:
            session.close()

    def test_ro_session_is_not_rw(self, p11_module: Any, p11_config: Any) -> None:
        """R/O session reports read-only state."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else pin

        session = _open_session(token, rw=False, pin_str=pin_str)
        try:
            assert session.rw is False
        finally:
            session.close()

    def test_session_has_token(self, p11_module: Any, p11_config: Any) -> None:
        """Session is associated with a token."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else pin

        session = _open_session(token, rw=True, pin_str=pin_str)
        try:
            assert session is not None
            key = session.generate_key(pkcs11.KeyType.AES, 128)
            assert key is not None
        finally:
            session.close()

    def test_ro_session_cannot_generate_token_objects(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """R/O session cannot create TOKEN=True objects."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else pin

        session = _open_session(token, rw=False, pin_str=pin_str)
        try:
            key = session.generate_key(pkcs11.KeyType.AES, 128)
            assert key is not None

            with pytest.raises(pkcs11.exceptions.PKCS11Error):
                session.generate_key(
                    pkcs11.KeyType.AES,
                    128,
                    template={pkcs11.Attribute.TOKEN: True},
                )
        finally:
            session.close()
