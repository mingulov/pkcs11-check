"""Attribute template fuzzing tests.

Tests that malformed CK_ATTRIBUTE arrays don't crash the module.
Invalid attributes should return proper CKR error codes, not segfault.

References: Tookan paper, Mozilla common PKCS#11 problems, rep11.md Iteration 3.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, ObjectClass
from pkcs11.exceptions import PKCS11Error

pytestmark = pytest.mark.security


class TestMalformedAttributes:
    """Test that malformed attribute values are rejected gracefully."""

    def test_invalid_class_value(self, p11_session: Any) -> None:
        """CKA_CLASS with invalid value must be rejected, not crash."""
        with pytest.raises(PKCS11Error):
            p11_session.create_object(
                {
                    Attribute.CLASS: 0xDEADBEEF,
                    Attribute.TOKEN: False,
                }
            )

    def test_empty_value_on_aes_key(self, p11_session: Any) -> None:
        """CKA_VALUE with empty bytes on AES key — must reject or accept gracefully."""
        try:
            obj = p11_session.create_object(
                {
                    Attribute.CLASS: ObjectClass.SECRET_KEY,
                    Attribute.KEY_TYPE: KeyType.AES,
                    Attribute.VALUE: b"",
                    Attribute.TOKEN: False,
                }
            )
            # Some modules accept (SoftHSM2) — key won't be usable but no crash
            assert obj is not None
        except PKCS11Error:
            pass  # Correct to reject

    def test_wrong_size_aes_value(self, p11_session: Any) -> None:
        """AES key with 7-byte VALUE (not 16/24/32) — must reject or accept gracefully."""
        try:
            obj = p11_session.create_object(
                {
                    Attribute.CLASS: ObjectClass.SECRET_KEY,
                    Attribute.KEY_TYPE: KeyType.AES,
                    Attribute.VALUE: b"\x00" * 7,
                    Attribute.TOKEN: False,
                }
            )
            # Some modules accept — key won't work for AES ops but no crash
            assert obj is not None
        except PKCS11Error:
            pass  # Correct to reject

    def test_value_len_zero_on_rsa(self, p11_session: Any) -> None:
        """CKA_VALUE_LEN=0 on RSA key generation must be rejected."""
        with pytest.raises(PKCS11Error):
            p11_session.generate_keypair(KeyType.RSA, 0)

    def test_negative_key_length(self, p11_session: Any) -> None:
        """Extremely large key length (interpreted as negative) must be rejected."""
        with pytest.raises((PKCS11Error, OverflowError, ValueError)):
            p11_session.generate_key(KeyType.AES, 0xFFFFFFFF)

    def test_missing_class_attribute(self, p11_session: Any) -> None:
        """Creating object without CKA_CLASS must fail."""
        with pytest.raises(PKCS11Error):
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
            # If it succeeds, that's a module choice — but it shouldn't crash
            assert obj is not None
        except PKCS11Error:
            pass  # Correct to reject

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
        except (PKCS11Error, TypeError, ValueError):
            pass  # Correct to reject


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
        except PKCS11Error:
            pass  # Some modules reject large labels

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
        except PKCS11Error:
            pass  # Some modules reject large values


class TestDuplicateAttributes:
    """Test behavior with duplicate attributes in template."""

    def test_create_key_normal(self, p11_session: Any) -> None:
        """Baseline: normal AES key generation works."""
        key = p11_session.generate_key(KeyType.AES, 256)
        assert key is not None
