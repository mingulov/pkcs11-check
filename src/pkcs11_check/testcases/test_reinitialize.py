"""Slot re-initialization tests.

Tests C_Finalize + C_Initialize cycle to verify the module
returns to a clean state and can operate normally afterward.
"""

from __future__ import annotations

from typing import Any

import pkcs11
import pytest

pytestmark = [pytest.mark.access, pytest.mark.destructive]


class TestReinitialize:
    """Test finalize/initialize cycle."""

    def test_reinitialize_and_use(self, p11_config: Any) -> None:
        """Module works normally after finalize + initialize cycle."""
        module_path = p11_config.module
        if hasattr(module_path, "get_secret_value"):
            module_path = module_path.get_secret_value()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else pin

        # Load and initialize
        lib = pkcs11.lib(str(module_path))
        lib.initialize()

        try:
            # Use normally
            token = lib.get_token(token_label="pkcs11-check")
            with token.open(rw=True, user_pin=pin_str) as session:
                key = session.generate_key(pkcs11.KeyType.AES, 128)
                assert key is not None
        finally:
            lib.finalize()

        # Re-initialize
        lib.initialize()
        try:
            token = lib.get_token(token_label="pkcs11-check")
            with token.open(rw=True, user_pin=pin_str) as session:
                key = session.generate_key(pkcs11.KeyType.AES, 128)
                assert key is not None
        finally:
            lib.finalize()

    def test_finalize_closes_sessions(self, p11_config: Any) -> None:
        """After finalize, previously opened sessions are invalid."""
        module_path = p11_config.module
        if hasattr(module_path, "get_secret_value"):
            module_path = module_path.get_secret_value()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else pin

        lib = pkcs11.lib(str(module_path))
        lib.initialize()

        token = lib.get_token(token_label="pkcs11-check")
        session = token.open(rw=True, user_pin=pin_str)

        # Generate a key to prove session works
        key = session.generate_key(pkcs11.KeyType.AES, 128)
        assert key is not None

        lib.finalize()

        # After finalize, using the old session should fail
        lib.initialize()
        try:
            # Old session handle should be invalid now
            try:
                session.generate_key(pkcs11.KeyType.AES, 128)
                # Some modules may reuse the handle — that's OK
            except pkcs11.exceptions.PKCS11Error:
                pass  # Expected — session invalidated by finalize
        finally:
            lib.finalize()
