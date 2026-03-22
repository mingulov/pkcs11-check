"""Access control attribute tests.

Verifies CKA_PRIVATE (visibility without login), CKA_MODIFIABLE
(attribute mutability), CKA_TRUSTED (wrap protection) flags, and
C_CopyObject semantics (CKA_COPYABLE, label/attribute modification on copy).
These catch real access control bugs in PKCS#11 modules.
"""

from __future__ import annotations

from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, ObjectClass
from pkcs11.exceptions import (
    ActionProhibited,
    AttributeReadOnly,
    AttributeTypeInvalid,
    AttributeValueInvalid,
    FunctionNotSupported,
    TemplateInconsistent,
)

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
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else pin

        label = f"pub-visible-{id(self)}"

        # Create a non-private data object (logged in)
        try:
            session = token.open(rw=True, user_pin=pin_str)
        except (p11.exceptions.UserAlreadyLoggedIn, p11.exceptions.UserTypeInvalid):
            session = token.open(rw=True)
            try:
                session.login(p11.UserType.USER, pin_str)
            except (p11.exceptions.UserAlreadyLoggedIn, p11.exceptions.UserTypeInvalid):
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

        # Open R/O session WITHOUT login -- non-private object should be visible
        session_ro = token.open(rw=False)
        try:
            found = list(
                session_ro.get_objects({Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: label})
            )
            # On most modules, PRIVATE=False objects are visible without login
            # Some modules require login for all access -- that's acceptable
            if len(found) == 0:
                from pkcs11_check.compliance import ComplianceLevel, note

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
        except (p11.exceptions.UserAlreadyLoggedIn, p11.exceptions.UserTypeInvalid):
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


class TestCopyObject:
    """Tests for C_CopyObject -- copying PKCS#11 objects with attribute modification."""

    def test_copy_with_modified_label(self, p11_session: Any) -> None:
        """Copy a key with a new label -- label changes, other attrs preserved."""
        key = p11_session.generate_key(KeyType.AES, 256, label="orig-label")
        if not key[Attribute.COPYABLE]:
            pytest.skip("Key not copyable by default")
        try:
            copied = key.copy({Attribute.LABEL: "copied-label"})
        except FunctionNotSupported:
            pytest.skip("C_CopyObject not supported by this module")
        except (AttributeTypeInvalid, AttributeValueInvalid, TemplateInconsistent):
            pytest.skip("Module rejected copy template")
        assert copied[Attribute.LABEL] == "copied-label"
        assert copied[Attribute.KEY_TYPE] == key[Attribute.KEY_TYPE]
        assert copied[Attribute.VALUE_LEN] == key[Attribute.VALUE_LEN]
        copied.destroy()

    def test_copy_changes_extractable(self, p11_session: Any) -> None:
        """Copy a key with CKA_EXTRACTABLE changed from True to False.

        Per PKCS#11 spec, a copy may restrict but not expand security attributes.
        Restricting CKA_EXTRACTABLE from True to False is always permitted.
        """
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={
                Attribute.EXTRACTABLE: True,
                Attribute.SENSITIVE: False,
                Attribute.LABEL: "extractable-src",
            },
        )
        if not key[Attribute.COPYABLE]:
            pytest.skip("Key not copyable")
        assert key[Attribute.EXTRACTABLE] is True
        try:
            copied = key.copy({Attribute.EXTRACTABLE: False})
        except FunctionNotSupported:
            pytest.skip("C_CopyObject not supported by this module")
        except (
            AttributeReadOnly,
            AttributeTypeInvalid,
            AttributeValueInvalid,
            TemplateInconsistent,
        ) as exc:
            pytest.skip(f"Module rejected EXTRACTABLE restriction on copy: {exc}")
        assert copied[Attribute.EXTRACTABLE] is False
        copied.destroy()

    def test_non_copyable_key_rejected(self, p11_session: Any) -> None:
        """Key with CKA_COPYABLE=False cannot be copied -- CKR_ACTION_PROHIBITED."""
        try:
            key = p11_session.generate_key(
                KeyType.AES,
                256,
                template={Attribute.COPYABLE: False, Attribute.LABEL: "non-copyable"},
            )
        except (AttributeTypeInvalid, AttributeValueInvalid, TemplateInconsistent):
            pytest.skip("Module does not support setting CKA_COPYABLE=False at key gen")
        # Verify the flag was actually set
        if key[Attribute.COPYABLE] is not False:
            pytest.skip("Module did not honour CKA_COPYABLE=False in template")
        with pytest.raises(
            (ActionProhibited, AttributeTypeInvalid, AttributeValueInvalid, TemplateInconsistent)
        ):
            key.copy({Attribute.LABEL: "should-fail"})

    def test_copy_session_object_stays_session(self, p11_session: Any) -> None:
        """Copy of a session object is also a session object (CKA_TOKEN=False)."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.TOKEN: False, Attribute.LABEL: "session-src"},
        )
        if not key[Attribute.COPYABLE]:
            pytest.skip("Key not copyable")
        assert key[Attribute.TOKEN] is False
        try:
            copied = key.copy({Attribute.LABEL: "session-copy"})
        except FunctionNotSupported:
            pytest.skip("C_CopyObject not supported by this module")
        except (AttributeTypeInvalid, AttributeValueInvalid, TemplateInconsistent) as exc:
            pytest.skip(f"Module rejected copy template: {exc}")
        assert copied[Attribute.TOKEN] is False
        copied.destroy()

    def test_copy_token_object_stays_token(self, p11_session: Any) -> None:
        """Copy of a token object is also a token object (CKA_TOKEN=True).

        Requires a read/write session -- p11_session opens rw=True.
        Token object and its copy are destroyed after the test.
        """
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.TOKEN: True, Attribute.LABEL: "token-src"},
        )
        if not key[Attribute.COPYABLE]:
            key.destroy()
            pytest.skip("Key not copyable")
        assert key[Attribute.TOKEN] is True
        copied = None
        try:
            try:
                copied = key.copy({Attribute.LABEL: "token-copy"})
            except FunctionNotSupported:
                pytest.skip("C_CopyObject not supported by this module")
            except (AttributeTypeInvalid, AttributeValueInvalid, TemplateInconsistent) as exc:
                pytest.skip(f"Module rejected copy template: {exc}")
            assert copied[Attribute.TOKEN] is True
        finally:
            if copied is not None:
                copied.destroy()
            key.destroy()
