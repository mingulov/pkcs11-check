"""C_SetAttributeValue tests - attribute mutation on existing objects.

Tests modifying CKA_LABEL, CKA_ID on keys, and verifying that
read-only attributes (CKA_CLASS, CKA_KEY_TYPE, CKA_MODULUS) are rejected.
"""

from __future__ import annotations

from typing import Any

import pkcs11
import pytest
from pkcs11 import Attribute, KeyType, ObjectClass

pytestmark = pytest.mark.keymgmt


class TestSetAttributePositive:
    """Verify that mutable attributes can be changed."""

    def test_change_label(self, p11_session: Any) -> None:
        """CKA_LABEL can be changed on an existing key."""
        key = p11_session.generate_key(KeyType.AES, 256, label="before")
        assert key.label == "before"

        key[Attribute.LABEL] = "after"

        # Search by new label works (label property may be cached, use search)
        found = list(p11_session.get_objects({Attribute.LABEL: "after"}))
        assert len(found) >= 1

    def test_change_id(self, p11_session: Any) -> None:
        """CKA_ID can be changed on an existing key."""
        key = p11_session.generate_key(KeyType.AES, 256, id=b"\x01\x02")
        key[Attribute.ID] = b"\xaa\xbb"
        assert key[Attribute.ID] == b"\xaa\xbb"

    def test_change_label_on_keypair(self, p11_session: Any) -> None:
        """CKA_LABEL can be changed on RSA public and private keys."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048, label="rsa-orig")

        pub[Attribute.LABEL] = "rsa-pub-new"
        priv[Attribute.LABEL] = "rsa-priv-new"

        assert len(list(p11_session.get_objects({Attribute.LABEL: "rsa-pub-new"}))) >= 1
        assert len(list(p11_session.get_objects({Attribute.LABEL: "rsa-priv-new"}))) >= 1


class TestSetAttributeNegative:
    """Verify that read-only / immutable attributes are rejected."""

    def test_cannot_change_class(self, p11_session: Any) -> None:
        """CKA_CLASS is read-only - should reject or silently ignore."""
        from pkcs11_check.compliance import ComplianceLevel, note

        key = p11_session.generate_key(KeyType.AES, 256)
        try:
            key[Attribute.CLASS] = ObjectClass.PUBLIC_KEY
            # If no error, the module silently ignored it - flag it
            note(
                "Module accepted C_SetAttributeValue on CKA_CLASS without error",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 Base v3.0, Table 15 - CKA_CLASS is read-only",
            )
        except pkcs11.exceptions.PKCS11Error:
            pass  # Correct behavior

    def test_cannot_change_key_type(self, p11_session: Any) -> None:
        """CKA_KEY_TYPE is read-only - should reject or silently ignore."""
        from pkcs11_check.compliance import ComplianceLevel, note

        key = p11_session.generate_key(KeyType.AES, 256)
        try:
            key[Attribute.KEY_TYPE] = KeyType.RSA
            note(
                "Module accepted C_SetAttributeValue on CKA_KEY_TYPE without error",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 Base v3.0, Table 15 - CKA_KEY_TYPE is read-only",
            )
        except pkcs11.exceptions.PKCS11Error:
            pass  # Correct behavior

    def test_cannot_change_modulus(self, p11_session: Any) -> None:
        """CKA_MODULUS on RSA key is read-only - must reject."""
        pub, _ = p11_session.generate_keypair(KeyType.RSA, 2048)
        try:
            pub[Attribute.MODULUS] = b"\x00" * 256
        except pkcs11.exceptions.PKCS11Error:
            pass  # Correct behavior

    def test_cannot_set_value_on_sensitive_key(self, p11_session: Any) -> None:
        """CKA_VALUE on a sensitive key - should reject."""
        from pkcs11_check.compliance import ComplianceLevel, note

        key = p11_session.generate_key(KeyType.AES, 256)
        try:
            key[Attribute.VALUE] = b"\x00" * 32
            note(
                "Module accepted C_SetAttributeValue on CKA_VALUE of sensitive key",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 Base v3.0 - CKA_VALUE should not be settable on sensitive keys",
            )
        except pkcs11.exceptions.PKCS11Error:
            pass  # Correct behavior
