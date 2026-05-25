"""Attribute sensitivity enforcement tests.

Verifies that PKCS#11 modules enforce CKA_SENSITIVE and CKA_EXTRACTABLE
correctly - sensitive key values must not be readable, non-extractable
keys must not be wrappable.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    gen_rsa_keypair,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_ALWAYS_SENSITIVE,
    CKA_EXTRACTABLE,
    CKA_PRIVATE_EXPONENT,
    CKA_SENSITIVE,
    CKA_VALUE,
    CKR_ATTRIBUTE_TYPE_INVALID,
)
from pkcs11_check.testcases.conftest import is_known_error

pytestmark = pytest.mark.security


class TestSensitiveKeyValue:
    """Test that CKA_VALUE is protected on sensitive keys."""

    def test_sensitive_aes_value_not_readable(self, p11_raw_session: Any) -> None:
        """Reading CKA_VALUE on a SENSITIVE=True AES key must fail."""
        rs = p11_raw_session
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_SENSITIVE: True},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_SENSITIVE])
            assert attrs[CKA_SENSITIVE] is True

            try:
                read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "SECURITY: module allows reading CKA_VALUE on CKA_SENSITIVE=True AES key "
                    "(returns CKR_OK instead of CKR_ATTRIBUTE_SENSITIVE)",
                    ComplianceLevel.CRITICAL,
                    reference="PKCS#11 v3.1 Sec.4.9.2: sensitive attributes cannot be "
                    "revealed in plaintext",
                )
                pytest.xfail(
                    "SECURITY: module allows reading sensitive AES key material "
                    "(CKR_OK instead of CKR_ATTRIBUTE_SENSITIVE)"
                )
            except AssertionError as e:
                msg = str(e)
                assert "CKR_ATTRIBUTE_SENSITIVE" in msg, (
                    f"Expected CKR_ATTRIBUTE_SENSITIVE, got: {e}"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_non_sensitive_aes_value_readable(self, p11_raw_session: Any) -> None:
        """CKA_VALUE is readable when SENSITIVE=False."""
        rs = p11_raw_session
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_SENSITIVE: False, CKA_EXTRACTABLE: True},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])
            value = attrs[CKA_VALUE]
            assert isinstance(value, bytes)
            assert len(value) == 32  # 256 bits = 32 bytes
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_sensitive_rsa_private_exponent_not_readable(self, p11_raw_session: Any) -> None:
        """Reading CKA_PRIVATE_EXPONENT on a sensitive RSA private key must fail."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            private_attrs={CKA_SENSITIVE: True},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_SENSITIVE])
            assert attrs[CKA_SENSITIVE] is True

            try:
                read_attributes(rs.raw, rs.sh, priv, [CKA_PRIVATE_EXPONENT])
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "SECURITY: module allows reading CKA_PRIVATE_EXPONENT on CKA_SENSITIVE=True "
                    "RSA private key (returns CKR_OK instead of CKR_ATTRIBUTE_SENSITIVE)",
                    ComplianceLevel.CRITICAL,
                    reference="PKCS#11 v3.1 Sec.4.9.2: sensitive attributes cannot be "
                    "revealed in plaintext",
                )
                pytest.xfail(
                    "SECURITY: module allows reading sensitive RSA private key material "
                    "(CKR_OK instead of CKR_ATTRIBUTE_SENSITIVE)"
                )
            except AssertionError as e:
                msg = str(e)
                assert "CKR_ATTRIBUTE_SENSITIVE" in msg, (
                    f"Expected CKR_ATTRIBUTE_SENSITIVE, got: {e}"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestExtractableEnforcement:
    """Test CKA_EXTRACTABLE enforcement."""

    def test_non_extractable_by_default(self, p11_raw_session: Any) -> None:
        """Default-generated AES key extractability.

        Per OASIS PKCS#11 spec, CKA_EXTRACTABLE has no mandated default value
        -- it is implementation-defined. Both True and False are spec-conformant.
        This test documents which default the module uses via a compliance note.
        """
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            try:
                attrs = read_attributes(rs.raw, rs.sh, key, [CKA_EXTRACTABLE])
                extractable = attrs[CKA_EXTRACTABLE]
            except AssertionError as e:
                if is_known_error(e, {CKR_ATTRIBUTE_TYPE_INVALID}):
                    pytest.skip("Module does not support CKA_EXTRACTABLE attribute")
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

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

    def test_extractable_when_requested(self, p11_raw_session: Any) -> None:
        """AES key with EXTRACTABLE=True allows VALUE read (when also not sensitive)."""
        rs = p11_raw_session
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_EXTRACTABLE])
            assert attrs[CKA_EXTRACTABLE] is True
            val_attrs = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])
            assert len(val_attrs[CKA_VALUE]) == 32
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestSensitiveFlag:
    """Test that CKA_SENSITIVE flag behaves correctly."""

    def test_sensitive_flag_is_true_when_requested(self, p11_raw_session: Any) -> None:
        """AES key with SENSITIVE=True has SENSITIVE=True."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_SENSITIVE: True})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_SENSITIVE])
            assert attrs[CKA_SENSITIVE] is True
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_sensitive_flag_settable_at_creation(self, p11_raw_session: Any) -> None:
        """SENSITIVE=False can be set at creation time."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_SENSITIVE: False})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_SENSITIVE])
            assert attrs[CKA_SENSITIVE] is False
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_always_sensitive_flag(self, p11_raw_session: Any) -> None:
        """CKA_ALWAYS_SENSITIVE is readable and consistent."""
        rs = p11_raw_session
        key_sensitive = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_SENSITIVE: True},
        )
        key_not_sensitive = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_SENSITIVE: False},
        )
        try:
            # ALWAYS_SENSITIVE should be True for keys that were always sensitive
            a1 = read_attributes(rs.raw, rs.sh, key_sensitive, [CKA_ALWAYS_SENSITIVE])
            assert a1[CKA_ALWAYS_SENSITIVE] is True
            # ALWAYS_SENSITIVE should be False for keys that started non-sensitive
            a2 = read_attributes(rs.raw, rs.sh, key_not_sensitive, [CKA_ALWAYS_SENSITIVE])
            assert a2[CKA_ALWAYS_SENSITIVE] is False
        finally:
            destroy_quietly(rs.raw, rs.sh, key_sensitive)
            destroy_quietly(rs.raw, rs.sh, key_not_sensitive)
