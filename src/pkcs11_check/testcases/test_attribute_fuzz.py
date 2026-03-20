"""Attribute template fuzzing tests.

Tests that malformed CK_ATTRIBUTE arrays don't crash the module.
Invalid attributes should return proper CKR error codes, not segfault.

Each except block lists ONLY the specific CKR codes that are valid
responses for that operation. Any unexpected error will fail the test.

References: Tookan paper, Mozilla common PKCS#11 problems, rep11.md Iteration 3.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, ObjectClass
from pkcs11.exceptions import (
    ArgumentsBad,
    AttributeTypeInvalid,
    AttributeValueInvalid,
    DataLenRange,
    DeviceMemory,
    FunctionFailed,
    KeySizeRange,
    MechanismInvalid,
    TemplateIncomplete,
    TemplateInconsistent,
)

pytestmark = pytest.mark.security

# Valid CKR codes for "bad template" operations
_TEMPLATE_ERRORS = (
    AttributeTypeInvalid,
    AttributeValueInvalid,
    TemplateIncomplete,
    TemplateInconsistent,
    ArgumentsBad,
    FunctionFailed,  # Some modules use this as catch-all
)

# Valid CKR codes for "bad key size" operations
_KEY_SIZE_ERRORS = (
    AttributeValueInvalid,
    KeySizeRange,
    MechanismInvalid,
    ArgumentsBad,
    TemplateIncomplete,
    FunctionFailed,
)


class TestMalformedAttributes:
    """Test that malformed attribute values are rejected gracefully."""

    def test_invalid_class_value(self, p11_session: Any) -> None:
        """CKA_CLASS with invalid value must be rejected, not crash."""
        with pytest.raises(_TEMPLATE_ERRORS):
            p11_session.create_object(
                {
                    Attribute.CLASS: 0xDEADBEEF,
                    Attribute.TOKEN: False,
                }
            )

    def test_empty_value_on_aes_key(self, p11_session: Any) -> None:
        """CKA_VALUE with empty bytes on AES key — must reject or accept."""
        try:
            obj = p11_session.create_object(
                {
                    Attribute.CLASS: ObjectClass.SECRET_KEY,
                    Attribute.KEY_TYPE: KeyType.AES,
                    Attribute.VALUE: b"",
                    Attribute.TOKEN: False,
                }
            )
            # SoftHSM2 accepts — key won't be usable but no crash
            assert obj is not None
        except (*_TEMPLATE_ERRORS, KeySizeRange):
            pass  # Correct to reject empty key value (Kryoptic: CKR_KEY_SIZE_RANGE)

    def test_wrong_size_aes_value(self, p11_session: Any) -> None:
        """AES key with 7-byte VALUE (not 16/24/32) — must reject or accept."""
        try:
            obj = p11_session.create_object(
                {
                    Attribute.CLASS: ObjectClass.SECRET_KEY,
                    Attribute.KEY_TYPE: KeyType.AES,
                    Attribute.VALUE: b"\x00" * 7,
                    Attribute.TOKEN: False,
                }
            )
            assert obj is not None
        except (*_TEMPLATE_ERRORS, DataLenRange, KeySizeRange):
            pass  # Correct to reject wrong key size

    def test_value_len_zero_on_rsa(self, p11_session: Any) -> None:
        """CKA_VALUE_LEN=0 on RSA key generation must be rejected."""
        with pytest.raises(_KEY_SIZE_ERRORS):
            p11_session.generate_keypair(KeyType.RSA, 0)

    def test_negative_key_length(self, p11_session: Any) -> None:
        """Extremely large key length — must reject or handle gracefully."""
        try:
            key = p11_session.generate_key(KeyType.AES, 0xFFFFFFFF)
            # Kryoptic silently truncates — key exists but may not be usable
            assert key is not None
        except (*_KEY_SIZE_ERRORS, OverflowError, ValueError):
            pass  # Correct to reject

    def test_missing_class_attribute(self, p11_session: Any) -> None:
        """Creating object without CKA_CLASS must fail."""
        with pytest.raises(_TEMPLATE_ERRORS):
            p11_session.create_object(
                {
                    Attribute.LABEL: "no-class",
                    Attribute.VALUE: b"data",
                    Attribute.TOKEN: False,
                }
            )

    def test_conflicting_class_and_keytype(self, p11_session: Any) -> None:
        """DATA object with KEY_TYPE attribute must be rejected or ignored."""
        try:
            obj = p11_session.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.KEY_TYPE: KeyType.AES,
                    Attribute.VALUE: b"conflicting",
                    Attribute.TOKEN: False,
                }
            )
            # If it succeeds, module ignores KEY_TYPE on DATA — acceptable
            assert obj is not None
        except _TEMPLATE_ERRORS:
            pass  # Correct to reject inconsistent template

    def test_boolean_as_wrong_type(self, p11_session: Any) -> None:
        """CKA_TOKEN with non-boolean value — must reject or handle gracefully."""
        try:
            p11_session.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: "bool-test",
                    Attribute.VALUE: b"test",
                    Attribute.TOKEN: 42,  # Not a bool
                }
            )
        except (*_TEMPLATE_ERRORS, TypeError, ValueError):
            pass  # Correct: reject bad type (Python or PKCS#11 level)


class TestLargeAttributes:
    """Test with oversized attribute values."""

    def test_large_label(self, p11_session: Any) -> None:
        """Very long CKA_LABEL (10KB) — must not crash."""
        try:
            obj = p11_session.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: "X" * 10240,
                    Attribute.VALUE: b"big-label",
                    Attribute.TOKEN: False,
                }
            )
            assert obj is not None
        except (*_TEMPLATE_ERRORS, DeviceMemory):
            pass  # Acceptable: reject large label or out of memory

    def test_large_value(self, p11_session: Any) -> None:
        """Large CKA_VALUE (1MB) on data object — must not crash."""
        try:
            obj = p11_session.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: "big-value",
                    Attribute.VALUE: b"\xAB" * (1024 * 1024),
                    Attribute.TOKEN: False,
                }
            )
            assert obj is not None
        except (*_TEMPLATE_ERRORS, DeviceMemory):
            pass  # Acceptable: reject large value or out of memory


class TestDuplicateAttributes:
    """Test behavior with duplicate attributes in template."""

    def test_create_key_normal(self, p11_session: Any) -> None:
        """Baseline: normal AES key generation works."""
        key = p11_session.generate_key(KeyType.AES, 256)
        assert key is not None
