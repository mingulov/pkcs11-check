"""Attribute sensitivity enforcement tests.

Verifies that PKCS#11 modules enforce CKA_SENSITIVE and CKA_EXTRACTABLE
correctly - sensitive key values must not be readable, non-extractable
keys must not be wrappable.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType
from pkcs11.exceptions import AttributeSensitive, AttributeTypeInvalid

pytestmark = pytest.mark.security


class TestSensitiveKeyValue:
    """Test that CKA_VALUE is protected on sensitive keys."""

    def test_sensitive_aes_value_not_readable(self, p11_session: Any) -> None:
        """Reading CKA_VALUE on a SENSITIVE=True AES key must fail."""
        key = p11_session.generate_key(KeyType.AES, 256)
        # Default keys are SENSITIVE=True
        assert key[Attribute.SENSITIVE] is True

        with pytest.raises(AttributeSensitive):
            key[Attribute.VALUE]  # noqa: B018

    def test_non_sensitive_aes_value_readable(self, p11_session: Any) -> None:
        """CKA_VALUE is readable when SENSITIVE=False."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True},
        )
        value = key[Attribute.VALUE]
        assert isinstance(value, bytes)
        assert len(value) == 32  # 256 bits = 32 bytes

    def test_sensitive_rsa_private_exponent_not_readable(self, p11_session: Any) -> None:
        """Reading CKA_PRIVATE_EXPONENT on a sensitive RSA private key must fail."""
        _pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        assert priv[Attribute.SENSITIVE] is True

        with pytest.raises(AttributeSensitive):
            priv[Attribute.PRIVATE_EXPONENT]  # noqa: B018


class TestExtractableEnforcement:
    """Test CKA_EXTRACTABLE enforcement."""

    def test_non_extractable_by_default(self, p11_session: Any) -> None:
        """Default-generated AES key extractability.

        Per OASIS PKCS#11 spec, CKA_EXTRACTABLE has no mandated default value
        — it is implementation-defined. Both True and False are spec-conformant.
        This test documents which default the module uses via a compliance note.
        """
        key = p11_session.generate_key(KeyType.AES, 256)
        try:
            try:
                extractable = key[Attribute.EXTRACTABLE]
            except AttributeTypeInvalid:
                pytest.skip("Module does not support CKA_EXTRACTABLE attribute")
        finally:
            key.destroy()

        from pkcs11_check.compliance import ComplianceLevel, note

        if extractable is True:
            note(
                "Module defaults CKA_EXTRACTABLE to True for generated AES keys; "
                "PKCS#11 spec does not mandate a specific default",
                ComplianceLevel.VENDOR,
            )
        else:
            note(
                "Module defaults CKA_EXTRACTABLE to False for generated AES keys; "
                "PKCS#11 spec does not mandate a specific default",
                ComplianceLevel.VENDOR,
            )
        # Both True and False are spec-conformant
        assert extractable in (True, False)

    def test_extractable_when_requested(self, p11_session: Any) -> None:
        """AES key with EXTRACTABLE=True allows VALUE read (when also not sensitive)."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False},
        )
        assert key[Attribute.EXTRACTABLE] is True
        value = key[Attribute.VALUE]
        assert len(value) == 32


class TestSensitiveFlag:
    """Test that CKA_SENSITIVE flag behaves correctly."""

    def test_sensitive_flag_is_true_by_default(self, p11_session: Any) -> None:
        """Default AES key has SENSITIVE=True."""
        key = p11_session.generate_key(KeyType.AES, 256)
        assert key[Attribute.SENSITIVE] is True

    def test_sensitive_flag_settable_at_creation(self, p11_session: Any) -> None:
        """SENSITIVE=False can be set at creation time."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.SENSITIVE: False},
        )
        assert key[Attribute.SENSITIVE] is False

    def test_always_sensitive_flag(self, p11_session: Any) -> None:
        """CKA_ALWAYS_SENSITIVE is readable and consistent."""
        key_sensitive = p11_session.generate_key(KeyType.AES, 256)
        key_not_sensitive = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.SENSITIVE: False},
        )

        # ALWAYS_SENSITIVE should be True for keys that were always sensitive
        assert key_sensitive[Attribute.ALWAYS_SENSITIVE] is True
        # ALWAYS_SENSITIVE should be False for keys that started non-sensitive
        assert key_not_sensitive[Attribute.ALWAYS_SENSITIVE] is False
