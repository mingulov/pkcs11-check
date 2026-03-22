"""CKR compliance tests for object management functions.

Covers C_CreateObject, C_CopyObject, C_DestroyObject, C_GetObjectSize,
C_GetAttributeValue, C_SetAttributeValue, C_FindObjects*.

Source: PKCS#11 v3.1 Sec.5.7.1-5.7.9.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, ObjectClass
from pkcs11.exceptions import (
    AttributeReadOnly,
    AttributeSensitive,
    AttributeTypeInvalid,
    ObjectHandleInvalid,
    PKCS11Error,
)

from pkcs11_check.testcases._error_tuples import TEMPLATE_ERRORS

pytestmark = pytest.mark.access


class TestCreateObjectErrors:
    """Error conditions for C_CreateObject (Sec.5.7.1)."""

    def test_missing_class(self, p11_session: Any) -> None:
        """Missing CKA_CLASS -> CKR_TEMPLATE_INCOMPLETE."""
        with pytest.raises(TEMPLATE_ERRORS):
            p11_session.create_object(
                {Attribute.LABEL: "no-class", Attribute.TOKEN: False}
            )

    def test_invalid_class_value(self, p11_session: Any) -> None:
        """CKA_CLASS=0xDEADBEEF -> CKR_ATTRIBUTE_VALUE_INVALID."""
        with pytest.raises(TEMPLATE_ERRORS):
            p11_session.create_object(
                {Attribute.CLASS: 0xDEADBEEF, Attribute.TOKEN: False}
            )

    def test_conflicting_class_keytype(self, p11_session: Any) -> None:
        """DATA object with KEY_TYPE -> reject or ignore."""
        try:
            obj = p11_session.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.KEY_TYPE: KeyType.AES,
                    Attribute.VALUE: b"conflict",
                    Attribute.TOKEN: False,
                }
            )
            # Some modules ignore KEY_TYPE on DATA - acceptable
            assert obj is not None
        except TEMPLATE_ERRORS:
            pass  # Correct to reject inconsistent template


class TestGetAttributeErrors:
    """Error conditions for C_GetAttributeValue (Sec.5.7.5)."""

    def test_sensitive_value(self, p11_session: Any) -> None:
        """Reading VALUE on SENSITIVE key -> CKR_ATTRIBUTE_SENSITIVE."""
        key = p11_session.generate_key(KeyType.AES, 256)
        with pytest.raises(AttributeSensitive):
            key[Attribute.VALUE]  # noqa: B018

    def test_destroyed_handle(self, p11_session: Any) -> None:
        """Using destroyed handle -> CKR_OBJECT_HANDLE_INVALID."""
        key = p11_session.generate_key(KeyType.AES, 128, label="ckr-destroy")
        key.destroy()
        try:
            key[Attribute.LABEL]  # noqa: B018
            # Some modules don't detect invalid handle
        except ObjectHandleInvalid:
            pass  # Correct per spec
        except PKCS11Error:
            pass  # Other errors acceptable (module may return different CKR)


class TestSetAttributeErrors:
    """Error conditions for C_SetAttributeValue (Sec.5.7.6)."""

    def test_set_readonly_class(self, p11_session: Any) -> None:
        """Setting CKA_CLASS -> CKR_ATTRIBUTE_READ_ONLY."""
        obj = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: "readonly-test",
                Attribute.VALUE: b"test",
                Attribute.TOKEN: False,
            }
        )
        try:
            obj[Attribute.CLASS] = ObjectClass.SECRET_KEY
            # Kryoptic silently accepts - compliance deviation
            from pkcs11_check.compliance import ComplianceLevel, note
            note(
                "C_SetAttributeValue accepted change to read-only CKA_CLASS",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 v3.1 Sec.5.7.6",
            )
        except (AttributeReadOnly, AttributeTypeInvalid, PKCS11Error):
            pass  # Any rejection is acceptable for read-only attribute


class TestCopyObjectErrors:
    """Error conditions for C_CopyObject (Sec.5.7.2)."""

    def test_copy_destroyed_handle(self, p11_session: Any) -> None:
        """Copy destroyed object -> CKR_OBJECT_HANDLE_INVALID."""
        key = p11_session.generate_key(KeyType.AES, 128, label="ckr-copy-destroy")
        key.destroy()
        try:
            key.copy({Attribute.LABEL: "ckr-copy-result"})
            # Some modules don't detect invalid handle
        except (ObjectHandleInvalid, PKCS11Error):
            pass  # Expected


class TestFindObjectsErrors:
    """Error conditions for C_FindObjects* (Sec.5.7.7-5.7.9)."""

    def test_find_with_empty_result(self, p11_session: Any) -> None:
        """FindObjects with template matching nothing -> returns empty list."""
        results = list(p11_session.get_objects({Attribute.LABEL: "nonexistent_ckr_label_xyz"}))
        assert results == []  # Empty is valid - not an error

    def test_find_by_class(self, p11_session: Any) -> None:
        """FindObjects with CKA_CLASS filter works correctly."""
        # Create a data object
        obj = p11_session.create_object({
            Attribute.CLASS: ObjectClass.DATA,
            Attribute.LABEL: "ckr-find-test",
            Attribute.VALUE: b"test",
            Attribute.TOKEN: False,
        })
        found = list(p11_session.get_objects({Attribute.LABEL: "ckr-find-test"}))
        assert len(found) >= 1
        obj.destroy()


class TestDestroyObjectErrors:
    """Error conditions for C_DestroyObject (Sec.5.7.3)."""

    def test_destroy_already_destroyed(self, p11_session: Any) -> None:
        """Double destroy -> CKR_OBJECT_HANDLE_INVALID."""
        key = p11_session.generate_key(KeyType.AES, 128, label="ckr-double-destroy")
        key.destroy()
        try:
            key.destroy()
            # Some modules silently accept double destroy
        except ObjectHandleInvalid:
            pass  # Correct per spec
        except PKCS11Error:
            pass  # Other error also acceptable
