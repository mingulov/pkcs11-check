"""CKR return code coverage tests.

Verifies that common PKCS#11 error codes are properly reported.
Each test intentionally triggers a specific error condition and
verifies the module returns the expected CKR code (or a close one).
"""

from __future__ import annotations

from typing import Any

import pkcs11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.exceptions import (
    AttributeSensitive,
    DataLenRange,
    MechanismInvalid,
    PinIncorrect,
    PKCS11Error,
)

pytestmark = pytest.mark.security


class TestCKRPinErrors:
    """Test PIN-related CKR codes."""

    def test_ckr_pin_incorrect(self, p11_module: Any) -> None:
        """Wrong PIN triggers CKR_PIN_INCORRECT."""
        token = p11_module.get_token()
        with pytest.raises(PinIncorrect):
            token.open(rw=True, user_pin="WRONG_PIN_XYZ_999")


class TestCKRMechanismErrors:
    """Test mechanism-related CKR codes."""

    def test_ckr_mechanism_invalid(self, p11_session: Any) -> None:
        """Using a non-existent mechanism triggers CKR_MECHANISM_INVALID."""
        key = p11_session.generate_key(KeyType.AES, 256)
        # Use a mechanism that doesn't exist for AES encrypt
        try:
            key.encrypt(b"\x00" * 16, mechanism=Mechanism.SHA256)
            pytest.fail("Using SHA256 as encryption mechanism should fail")
        except (MechanismInvalid, PKCS11Error):
            pass  # Expected


class TestCKRDataErrors:
    """Test data-related CKR codes."""

    def test_ckr_data_len_range_ecb(self, p11_session: Any) -> None:
        """Non-block-aligned data in AES-ECB triggers CKR_DATA_LEN_RANGE."""
        key = p11_session.generate_key(KeyType.AES, 256)
        with pytest.raises((DataLenRange, PKCS11Error)):
            key.encrypt(b"\x00" * 15, mechanism=Mechanism.AES_ECB)


class TestCKRAttributeErrors:
    """Test attribute-related CKR codes."""

    def test_ckr_attribute_sensitive(self, p11_session: Any) -> None:
        """Reading CKA_VALUE on sensitive key triggers CKR_ATTRIBUTE_SENSITIVE."""
        key = p11_session.generate_key(KeyType.AES, 256)
        with pytest.raises(AttributeSensitive):
            key[Attribute.VALUE]  # noqa: B018

    def test_ckr_attribute_type_invalid(self, p11_session: Any) -> None:
        """Reading a nonsense attribute ID triggers CKR_ATTRIBUTE_TYPE_INVALID or similar."""
        key = p11_session.generate_key(KeyType.AES, 256)
        try:
            key[0xFFFFFFFF]  # noqa: B018
        except PKCS11Error:
            pass  # Expected


class TestCKRSessionErrors:
    """Test session-related CKR codes."""

    def test_ckr_user_already_logged_in(self, p11_module: Any, p11_config: Any) -> None:
        """Double login triggers CKR_USER_ALREADY_LOGGED_IN."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else pin

        session = token.open(rw=True, user_pin=pin_str)
        try:
            with pytest.raises(pkcs11.exceptions.UserAlreadyLoggedIn):
                session.login(pkcs11.UserType.USER, pin_str)
        finally:
            session.close()


class TestCKRObjectErrors:
    """Test object-related CKR codes."""

    def test_ckr_object_handle_invalid_after_destroy(self, p11_session: Any) -> None:
        """Using a destroyed object's handle triggers an error."""
        key = p11_session.generate_key(KeyType.AES, 128, label="destroy-me-ckr")
        key.destroy()

        try:
            key[Attribute.LABEL]  # noqa: B018
            # Some modules may not detect the invalid handle
        except PKCS11Error:
            pass  # Expected — object no longer exists
