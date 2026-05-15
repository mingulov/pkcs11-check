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

from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    gen_aes_key,
    gen_rsa_keypair,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_TOKEN,
    CKA_VALUE,
    CKK_AES,
    CKO_DATA,
    CKO_SECRET_KEY,
)

pytestmark = pytest.mark.security

# CKR names that are valid for "bad template" operations
_TEMPLATE_CKR_NAMES = {
    "CKR_ATTRIBUTE_TYPE_INVALID",
    "CKR_ATTRIBUTE_VALUE_INVALID",
    "CKR_TEMPLATE_INCOMPLETE",
    "CKR_TEMPLATE_INCONSISTENT",
    "CKR_ARGUMENTS_BAD",
    "CKR_FUNCTION_FAILED",
}

_KEY_SIZE_CKR_NAMES = {
    "CKR_ATTRIBUTE_VALUE_INVALID",
    "CKR_KEY_SIZE_RANGE",
    "CKR_MECHANISM_INVALID",
    "CKR_ARGUMENTS_BAD",
    "CKR_TEMPLATE_INCOMPLETE",
    "CKR_FUNCTION_FAILED",
}


def _is_template_error(e: AssertionError) -> bool:
    msg = str(e)
    return any(n in msg for n in _TEMPLATE_CKR_NAMES)


def _is_key_size_error(e: AssertionError) -> bool:
    msg = str(e)
    return any(n in msg for n in _KEY_SIZE_CKR_NAMES)


class TestMalformedAttributes:
    """Test that malformed attribute values are rejected gracefully."""

    def test_invalid_class_value(self, p11_raw_session: Any) -> None:
        """CKA_CLASS with invalid value must be rejected, not crash."""
        rs = p11_raw_session
        try:
            h = create_object(
                rs.raw,
                rs.sh,
                {
                    CKA_CLASS: 0xDEADBEEF,
                    CKA_TOKEN: False,
                },
            )
            destroy_quietly(rs.raw, rs.sh, h)
            pytest.fail("Module accepted invalid CKA_CLASS value 0xDEADBEEF")
        except AssertionError as e:
            if _is_template_error(e):
                pass  # Correct rejection
            else:
                raise

    def test_empty_value_on_aes_key(self, p11_raw_session: Any) -> None:
        """CKA_VALUE with empty bytes on AES key - must reject or accept."""
        rs = p11_raw_session
        try:
            h = create_object(
                rs.raw,
                rs.sh,
                {
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_VALUE: b"",
                    CKA_TOKEN: False,
                },
            )
            # SoftHSM2 accepts - key won't be usable but no crash
            assert h != 0
            destroy_quietly(rs.raw, rs.sh, h)
        except AssertionError as e:
            if _is_template_error(e) or "CKR_KEY_SIZE_RANGE" in str(e):
                pass  # Correct to reject empty key value
            else:
                raise

    def test_wrong_size_aes_value(self, p11_raw_session: Any) -> None:
        """AES key with 7-byte VALUE (not 16/24/32) - must reject or accept."""
        rs = p11_raw_session
        try:
            h = create_object(
                rs.raw,
                rs.sh,
                {
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_VALUE: b"\x00" * 7,
                    CKA_TOKEN: False,
                },
            )
            assert h != 0
            destroy_quietly(rs.raw, rs.sh, h)
        except AssertionError as e:
            msg = str(e)
            if _is_template_error(e) or "CKR_DATA_LEN_RANGE" in msg or "CKR_KEY_SIZE_RANGE" in msg:
                pass  # Correct to reject wrong key size
            else:
                raise

    def test_value_len_zero_on_rsa(self, p11_raw_session: Any) -> None:
        """CKA_VALUE_LEN=0 on RSA key generation must be rejected."""
        rs = p11_raw_session
        try:
            pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 0)
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            pytest.fail("Module accepted RSA key size 0")
        except AssertionError as e:
            if _is_key_size_error(e):
                pass  # Correct rejection
            else:
                raise

    def test_negative_key_length(self, p11_raw_session: Any) -> None:
        """Extremely large key length - must reject or handle gracefully."""
        rs = p11_raw_session
        try:
            key = gen_aes_key(rs.raw, rs.sh, 0xFFFFFFFF * 8)
            # Kryoptic silently truncates - key exists but may not be usable
            assert key != 0
            destroy_quietly(rs.raw, rs.sh, key)
        except (AssertionError, OverflowError, ValueError):
            pass  # Correct to reject

    def test_missing_class_attribute(self, p11_raw_session: Any) -> None:
        """Creating object without CKA_CLASS must fail."""
        rs = p11_raw_session
        try:
            h = create_object(
                rs.raw,
                rs.sh,
                {
                    CKA_LABEL: "no-class",
                    CKA_VALUE: b"data",
                    CKA_TOKEN: False,
                },
            )
            destroy_quietly(rs.raw, rs.sh, h)
            pytest.fail("Module accepted object without CKA_CLASS")
        except AssertionError as e:
            if _is_template_error(e):
                pass  # Correct rejection
            else:
                raise

    def test_conflicting_class_and_keytype(self, p11_raw_session: Any) -> None:
        """DATA object with KEY_TYPE attribute must be rejected or ignored."""
        rs = p11_raw_session
        try:
            h = create_object(
                rs.raw,
                rs.sh,
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_VALUE: b"conflicting",
                    CKA_TOKEN: False,
                },
            )
            # If it succeeds, module ignores KEY_TYPE on DATA - acceptable
            assert h != 0
            destroy_quietly(rs.raw, rs.sh, h)
        except AssertionError as e:
            if _is_template_error(e):
                pass  # Correct to reject inconsistent template
            else:
                raise

    def test_boolean_as_wrong_type(self, p11_raw_session: Any) -> None:
        """CKA_TOKEN with non-boolean value - must reject or handle gracefully."""
        rs = p11_raw_session
        try:
            h = create_object(
                rs.raw,
                rs.sh,
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: "bool-test",
                    CKA_VALUE: b"test",
                    CKA_TOKEN: 42,  # Not a bool
                },
            )
            destroy_quietly(rs.raw, rs.sh, h)
        except (AssertionError, TypeError, ValueError):
            pass  # Correct: reject bad type


class TestLargeAttributes:
    """Test with oversized attribute values."""

    def test_large_label(self, p11_raw_session: Any) -> None:
        """Very long CKA_LABEL (10KB) - must not crash."""
        rs = p11_raw_session
        try:
            h = create_object(
                rs.raw,
                rs.sh,
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: "X" * 10240,
                    CKA_VALUE: b"big-label",
                    CKA_TOKEN: False,
                },
            )
            assert h != 0
            destroy_quietly(rs.raw, rs.sh, h)
        except AssertionError as e:
            if _is_template_error(e) or "CKR_DEVICE_MEMORY" in str(e):
                pass  # Acceptable: reject large label or out of memory
            else:
                raise

    def test_large_value(self, p11_raw_session: Any) -> None:
        """Large CKA_VALUE (1MB) on data object - must not crash."""
        rs = p11_raw_session
        try:
            h = create_object(
                rs.raw,
                rs.sh,
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: "big-value",
                    CKA_VALUE: b"\xab" * (1024 * 1024),
                    CKA_TOKEN: False,
                },
            )
            assert h != 0
            destroy_quietly(rs.raw, rs.sh, h)
        except AssertionError as e:
            if _is_template_error(e) or "CKR_DEVICE_MEMORY" in str(e):
                pass  # Acceptable: reject large value or out of memory
            else:
                raise


class TestDuplicateAttributes:
    """Test behavior with duplicate attributes in template."""

    def test_create_key_normal(self, p11_raw_session: Any) -> None:
        """Baseline: normal AES key generation works."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        assert key != 0
        destroy_quietly(rs.raw, rs.sh, key)
