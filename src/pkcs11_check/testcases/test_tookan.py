"""Tookan paper security vectors — conflicting key usage attributes.

Tests based on "Attacking and Fixing PKCS#11 Security Tokens" (2010).
Keys with conflicting usage flags (WRAP+DECRYPT, ENCRYPT+UNWRAP)
can allow key extraction. Modules should reject or enforce policy.

Reference: https://dl.acm.org/doi/10.1145/1866307.1866337
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism

from pkcs11_check.testcases._error_tuples import MECHANISM_ERRORS, SECURITY_POLICY_ERRORS
from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.security


class TestConflictingUsageAttrs:
    """Tookan vector: conflicting CKA_WRAP + CKA_DECRYPT on same key."""

    def test_wrap_and_decrypt_on_same_key(self, p11_session: Any) -> None:
        """Create AES key with both WRAP and DECRYPT — security risk."""
        try:
            p11_session.generate_key(
                KeyType.AES,
                256,
                template={
                    Attribute.WRAP: True,
                    Attribute.UNWRAP: True,
                    Attribute.ENCRYPT: True,
                    Attribute.DECRYPT: True,
                    Attribute.EXTRACTABLE: False,
                    Attribute.SENSITIVE: True,
                },
            )
        except SECURITY_POLICY_ERRORS:
            return  # Strict module rejects conflicting attrs — GOOD

        from pkcs11_check.compliance import ComplianceLevel, note

        note(
            "Module allows CKA_WRAP + CKA_DECRYPT on same key (Tookan vector)",
            ComplianceLevel.NOT_RECOMMENDED,
            reference="Tookan paper: key extraction via wrap+decrypt",
        )

    def test_encrypt_and_unwrap_on_same_key(self, p11_session: Any) -> None:
        """Create key with ENCRYPT + UNWRAP — inverse Tookan vector."""
        try:
            p11_session.generate_key(
                KeyType.AES,
                256,
                template={
                    Attribute.ENCRYPT: True,
                    Attribute.UNWRAP: True,
                },
            )
        except SECURITY_POLICY_ERRORS:
            return  # Strict module — good

        from pkcs11_check.compliance import ComplianceLevel, note

        note(
            "Module allows CKA_ENCRYPT + CKA_UNWRAP on same key",
            ComplianceLevel.NOT_RECOMMENDED,
            reference="Tookan paper inverse vector",
        )


class TestSensitivePreservation:
    """Verify CKA_SENSITIVE is preserved through wrap/unwrap and copy."""

    def test_sensitive_preserved_on_copy(self, p11_session: Any) -> None:
        """Copying a SENSITIVE key must keep SENSITIVE=True."""
        from pkcs11.exceptions import FunctionNotSupported

        key = p11_session.generate_key(KeyType.AES, 256)
        assert key[Attribute.SENSITIVE] is True

        try:
            copied = key.copy({Attribute.LABEL: "copy-sensitive"})
            assert copied[Attribute.SENSITIVE] is True, (
                "SENSITIVE flag lost on copy — Tookan vulnerability"
            )
        except FunctionNotSupported:
            pass  # Copy not supported — ok

    def test_extractable_cannot_escalate_on_copy(self, p11_session: Any) -> None:
        """Copying non-EXTRACTABLE key cannot set EXTRACTABLE=True."""
        from pkcs11.exceptions import (
            AttributeReadOnly,
            AttributeValueInvalid,
            FunctionNotSupported,
            TemplateInconsistent,
        )

        key = p11_session.generate_key(
            KeyType.AES, 256, template={Attribute.EXTRACTABLE: False}
        )
        assert key[Attribute.EXTRACTABLE] is False

        try:
            copied = key.copy({Attribute.EXTRACTABLE: True})
            assert copied[Attribute.EXTRACTABLE] is False, (
                "EXTRACTABLE escalated on copy — Tookan vulnerability"
            )
        except (AttributeReadOnly, AttributeValueInvalid, TemplateInconsistent, FunctionNotSupported):
            pass  # Correct: reject the escalation attempt


class TestWrapExtraction:
    """Test that wrapping a key doesn't leak material via decrypt."""

    def test_wrap_decrypt_extraction_attempt(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Attempt Tookan key extraction: wrap target, decrypt wrapped blob."""
        if not has_mechanism(p11_module, "AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        wrap_key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={
                Attribute.WRAP: True,
                Attribute.UNWRAP: True,
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
            },
        )

        target = p11_session.generate_key(
            KeyType.AES,
            128,
            template={
                Attribute.EXTRACTABLE: True,
                Attribute.SENSITIVE: False,
            },
        )
        target_value = target[Attribute.VALUE]

        wrapped = wrap_key.wrap_key(target, mechanism=Mechanism.AES_KEY_WRAP)

        try:
            decrypted = wrap_key.decrypt(wrapped, mechanism=Mechanism.AES_ECB)
            if decrypted == target_value:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "Tookan extraction succeeded: wrap+decrypt leaks key material",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="Tookan paper: full key extraction",
                )
        except MECHANISM_ERRORS:
            pass  # Module correctly prevents decrypt of wrapped data
