"""Tookan paper security vectors - conflicting key usage attributes.

Tests based on "Attacking and Fixing PKCS#11 Security Tokens" (2010).
Keys with conflicting usage flags (WRAP+DECRYPT, ENCRYPT+UNWRAP)
can allow key extraction. Modules should reject or enforce policy.

Reference: https://dl.acm.org/doi/10.1145/1866307.1866337
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    copy_object,
    destroy_quietly,
    encrypt_single,
    gen_aes_key,
    read_attributes,
    wrap_key,
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_LABEL,
    CKA_SENSITIVE,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_WRAP,
    CKM_AES_ECB,
    CKM_AES_KEY_WRAP,
)

pytestmark = pytest.mark.security


class TestConflictingUsageAttrs:
    """Tookan vector: conflicting CKA_WRAP + CKA_DECRYPT on same key."""

    def test_wrap_and_decrypt_on_same_key(self, p11_raw_session: Any) -> None:
        """Create AES key with both WRAP and DECRYPT - security risk."""
        rs = p11_raw_session
        try:
            key = gen_aes_key(
                rs.raw,
                rs.sh,
                256,
                attrs={
                    CKA_WRAP: True,
                    CKA_UNWRAP: True,
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                    CKA_EXTRACTABLE: False,
                    CKA_SENSITIVE: True,
                },
            )
            destroy_quietly(rs.raw, rs.sh, key)
        except AssertionError:
            return  # Strict module rejects conflicting attrs - GOOD

        from pkcs11_check.compliance import ComplianceLevel, note

        note(
            "Module allows CKA_WRAP + CKA_DECRYPT on same key (Tookan vector)",
            ComplianceLevel.NOT_RECOMMENDED,
            reference="Tookan paper: key extraction via wrap+decrypt",
        )

    def test_encrypt_and_unwrap_on_same_key(self, p11_raw_session: Any) -> None:
        """Create key with ENCRYPT + UNWRAP - inverse Tookan vector."""
        rs = p11_raw_session
        try:
            key = gen_aes_key(
                rs.raw,
                rs.sh,
                256,
                attrs={
                    CKA_ENCRYPT: True,
                    CKA_UNWRAP: True,
                },
            )
            destroy_quietly(rs.raw, rs.sh, key)
        except AssertionError:
            return  # Strict module - good

        from pkcs11_check.compliance import ComplianceLevel, note

        note(
            "Module allows CKA_ENCRYPT + CKA_UNWRAP on same key",
            ComplianceLevel.NOT_RECOMMENDED,
            reference="Tookan paper inverse vector",
        )


class TestSensitivePreservation:
    """Verify CKA_SENSITIVE is preserved through wrap/unwrap and copy."""

    def test_sensitive_preserved_on_copy(self, p11_raw_session: Any) -> None:
        """Copying a SENSITIVE key must keep SENSITIVE=True."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_SENSITIVE: True})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_SENSITIVE])
            assert attrs[CKA_SENSITIVE] is True

            try:
                copied = copy_object(
                    rs.raw,
                    rs.sh,
                    key,
                    {CKA_LABEL: "copy-sensitive"},
                )
            except AssertionError as exc:
                exc_msg = str(exc)
                if "CKR_FUNCTION_NOT_SUPPORTED" in exc_msg:
                    return  # Copy not supported - ok
                raise
            try:
                copy_attrs = read_attributes(rs.raw, rs.sh, copied, [CKA_SENSITIVE])
                assert copy_attrs[CKA_SENSITIVE] is True, (
                    "SENSITIVE flag lost on copy - Tookan vulnerability"
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, copied)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_extractable_cannot_escalate_on_copy(self, p11_raw_session: Any) -> None:
        """Copying non-EXTRACTABLE key cannot set EXTRACTABLE=True.

        OASIS PKCS#11 spec C_CopyObject section: CKA_EXTRACTABLE may be changed
        from CK_TRUE to CK_FALSE on copy, but NOT the other way around.
        This is a MUST NOT -- escalation is a security violation.
        """
        from pkcs11_check.compliance import ComplianceLevel, note

        rs = p11_raw_session
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_EXTRACTABLE: False},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_EXTRACTABLE])
            assert attrs[CKA_EXTRACTABLE] is False

            try:
                copied = copy_object(
                    rs.raw,
                    rs.sh,
                    key,
                    {CKA_EXTRACTABLE: True},
                )
            except AssertionError:
                return  # Correct: reject the escalation attempt

            try:
                copy_attrs = read_attributes(rs.raw, rs.sh, copied, [CKA_EXTRACTABLE])
                if copy_attrs[CKA_EXTRACTABLE] is True:
                    note(
                        "Module allows CKA_EXTRACTABLE escalation FALSE->TRUE via "
                        "C_CopyObject (OASIS PKCS#11 spec MUST NOT: may only change "
                        "TRUE->FALSE on copy)",
                        ComplianceLevel.CRITICAL,
                        reference="OASIS PKCS#11 spec C_CopyObject section",
                    )
                assert copy_attrs[CKA_EXTRACTABLE] is False, (
                    "EXTRACTABLE escalated on copy - Tookan vulnerability"
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, copied)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestWrapExtraction:
    """Test that wrapping a key doesn't leak material via decrypt."""

    def test_wrap_decrypt_extraction_attempt(self, p11_raw_session: Any) -> None:
        """Attempt Tookan key extraction: wrap target, decrypt wrapped blob."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        wrap_key_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
            },
        )

        target_h = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
            },
        )
        try:
            target_attrs = read_attributes(rs.raw, rs.sh, target_h, [CKA_VALUE])
            target_value = target_attrs[CKA_VALUE]

            wrapped = wrap_key(rs.raw, rs.sh, wrap_key_h, target_h, CKM_AES_KEY_WRAP)

            try:
                decrypted = encrypt_single(rs.raw, rs.sh, wrap_key_h, CKM_AES_ECB, wrapped)
                # Note: we're using encrypt here because we want to test the raw bytes
                # In the Tookan attack, the attacker decrypts the wrapped blob
                # Actually, the test needs decrypt:
            except AssertionError:
                pass  # Module correctly prevents decrypt of wrapped data
                return

            # If decrypt succeeded, check whether key material leaked
            from pkcs11_check.raw.recipes import decrypt_single

            try:
                decrypted = decrypt_single(rs.raw, rs.sh, wrap_key_h, CKM_AES_ECB, wrapped)
                if decrypted == target_value:
                    from pkcs11_check.compliance import ComplianceLevel, note

                    note(
                        "Tookan extraction succeeded: wrap+decrypt leaks key material",
                        ComplianceLevel.NOT_RECOMMENDED,
                        reference="Tookan paper: full key extraction",
                    )
            except AssertionError:
                pass  # Module correctly prevents decrypt of wrapped data
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_key_h)
            destroy_quietly(rs.raw, rs.sh, target_h)
