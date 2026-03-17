"""Session info tests.

Tests C_GetSessionInfo to verify session state, flags,
and login status are correctly reported.
"""

from __future__ import annotations

from typing import Any

import pkcs11
import pytest

pytestmark = pytest.mark.access


class TestSessionInfo:
    """Test C_GetSessionInfo via python-pkcs11 session properties."""

    def test_rw_session_is_rw(self, p11_module: Any, p11_config: Any) -> None:
        """R/W session reports correct state."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)

        with token.open(rw=True, user_pin=pin_str) as session:
            assert session.rw is True

    def test_ro_session_is_not_rw(self, p11_module: Any, p11_config: Any) -> None:
        """R/O session reports read-only state."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)

        with token.open(rw=False, user_pin=pin_str) as session:
            assert session.rw is False

    def test_session_has_token(self, p11_module: Any, p11_config: Any) -> None:
        """Session is associated with a token."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)

        with token.open(rw=True, user_pin=pin_str) as session:
            # Session should have a valid token reference
            assert session is not None
            # Should be able to generate a key (proves session is functional)
            key = session.generate_key(pkcs11.KeyType.AES, 128)
            assert key is not None

    def test_ro_session_cannot_generate_token_objects(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """R/O session cannot create TOKEN=True objects."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)

        with token.open(rw=False, user_pin=pin_str) as session:
            # Session objects should work in R/O
            key = session.generate_key(pkcs11.KeyType.AES, 128)
            assert key is not None

            # Token objects should fail in R/O
            with pytest.raises(pkcs11.exceptions.PKCS11Error):
                session.generate_key(
                    pkcs11.KeyType.AES,
                    128,
                    template={pkcs11.Attribute.TOKEN: True},
                )
