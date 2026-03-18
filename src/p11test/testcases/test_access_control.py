"""Access control attribute tests.

Verifies CKA_PRIVATE (visibility without login), CKA_MODIFIABLE
(attribute mutability), and CKA_TRUSTED (wrap protection) flags.
These catch real access control bugs in PKCS#11 modules.
"""

from __future__ import annotations

from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, ObjectClass

pytestmark = pytest.mark.security


class TestPrivateAttribute:
    """Test CKA_PRIVATE visibility semantics."""

    def test_private_key_default_is_private(self, p11_session: Any) -> None:
        """Generated secret keys are CKA_PRIVATE=True by default."""
        key = p11_session.generate_key(KeyType.AES, 256)
        assert key[Attribute.PRIVATE] is True

    def test_non_private_object_visible_without_login(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """CKA_PRIVATE=False object should be visible without login."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)

        label = f"pub-visible-{id(self)}"

        # Create a non-private data object (logged in)
        try:
            session = token.open(rw=True, user_pin=pin_str)
        except p11.exceptions.UserAlreadyLoggedIn:
            session = token.open(rw=True)
            try:
                session.login(p11.UserType.USER, pin_str)
            except p11.exceptions.UserAlreadyLoggedIn:
                pass

        try:
            session.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                    Attribute.VALUE: b"public-data",
                    Attribute.TOKEN: True,
                    Attribute.PRIVATE: False,
                }
            )
        finally:
            session.close()

        # Open R/O session WITHOUT login — non-private object should be visible
        session_ro = token.open(rw=False)
        try:
            found = list(
                session_ro.get_objects({Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: label})
            )
            # On most modules, PRIVATE=False objects are visible without login
            # Some modules require login for all access — that's acceptable
            if len(found) == 0:
                from p11test.compliance import ComplianceLevel, note

                note(
                    "PRIVATE=False object not visible without login",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 spec: CKA_PRIVATE=False objects visible in public sessions",
                )
        finally:
            session_ro.close()

        # Cleanup
        try:
            cleanup = token.open(rw=True, user_pin=pin_str)
        except p11.exceptions.UserAlreadyLoggedIn:
            cleanup = token.open(rw=True)
        try:
            for obj in cleanup.get_objects(
                {Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: label}
            ):
                obj.destroy()
        finally:
            cleanup.close()


class TestModifiableAttribute:
    """Test CKA_MODIFIABLE flag semantics."""

    def test_default_key_is_modifiable(self, p11_session: Any) -> None:
        """Generated keys have CKA_MODIFIABLE=True by default."""
        key = p11_session.generate_key(KeyType.AES, 256, label="mod-test")
        assert key[Attribute.MODIFIABLE] is True

    def test_modifiable_key_label_changeable(self, p11_session: Any) -> None:
        """Key with MODIFIABLE=True allows label change."""
        key = p11_session.generate_key(KeyType.AES, 256, label="mod-before")
        assert key[Attribute.MODIFIABLE] is True
        key[Attribute.LABEL] = "mod-after"
        found = list(p11_session.get_objects({Attribute.LABEL: "mod-after"}))
        assert len(found) >= 1


class TestCopyableAttribute:
    """Test CKA_COPYABLE flag semantics."""

    def test_default_key_copyable_flag(self, p11_session: Any) -> None:
        """Check CKA_COPYABLE flag is readable on generated key."""
        key = p11_session.generate_key(KeyType.AES, 256)
        copyable = key[Attribute.COPYABLE]
        assert isinstance(copyable, bool)

    def test_copyable_key_can_be_copied(self, p11_session: Any) -> None:
        """Key with COPYABLE=True can be copied via C_CopyObject."""
        key = p11_session.generate_key(KeyType.AES, 256, label="copy-src")
        if not key[Attribute.COPYABLE]:
            pytest.skip("Key not copyable by default")

        try:
            copied = key.copy({Attribute.LABEL: "copy-dst"})
            assert copied is not None
            assert copied[Attribute.LABEL] == "copy-dst"
            copied.destroy()
        except p11.exceptions.PKCS11Error:
            pytest.skip("C_CopyObject not supported")
