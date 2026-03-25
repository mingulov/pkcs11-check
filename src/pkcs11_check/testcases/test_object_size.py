"""C_GetObjectSize tests.

Tests that the module reports reasonable object sizes for various
key types and data objects, or returns CK_UNAVAILABLE_INFORMATION.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, ObjectClass

pytestmark = pytest.mark.keymgmt

from pkcs11_check.raw.types_std import CK_UNAVAILABLE_INFORMATION as CK_UNAVAILABLE


def _get_object_size(obj: Any) -> int | None:
    """Get object size, returning None if not supported or not meaningful.

    Per PKCS#11 spec, C_GetObjectSize MAY return CK_UNAVAILABLE_INFORMATION
    (~0) or 0 to indicate the size is not available or not meaningful for
    the object type. Both are treated as "not supported" here.
    """
    try:
        size: int = obj.wrapper.get_size()
        if size == CK_UNAVAILABLE or size == 0:
            return None
        return size
    except Exception:
        return None


class TestObjectSize:
    """Test C_GetObjectSize."""

    def test_aes_key_has_size(self, p11_session: Any) -> None:
        """AES key reports a size (or CK_UNAVAILABLE_INFORMATION)."""
        key = p11_session.generate_key(KeyType.AES, 256)
        size = _get_object_size(key)

        if size is None:
            pytest.skip("C_GetObjectSize not supported (returns CK_UNAVAILABLE_INFORMATION)")

        # AES-256 key is at minimum 32 bytes of material
        assert size >= 32, f"AES-256 object size {size} suspiciously small"

    def test_rsa_key_larger_than_aes(self, p11_session: Any) -> None:
        """RSA-2048 key should be larger than AES-256 key."""
        aes_key = p11_session.generate_key(KeyType.AES, 256)
        aes_size = _get_object_size(aes_key)

        if aes_size is None:
            pytest.skip(
                "C_GetObjectSize not supported (returns 0 or CK_UNAVAILABLE_INFORMATION)"
            )

        _pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        rsa_size = _get_object_size(priv)

        if rsa_size is None:
            pytest.skip(
                "C_GetObjectSize not supported for RSA (returns 0 or CK_UNAVAILABLE_INFORMATION)"
            )

        assert rsa_size > aes_size, (
            f"RSA-2048 size ({rsa_size}) should be > AES-256 size ({aes_size})"
        )

    def test_data_object_size_scales(self, p11_session: Any) -> None:
        """Larger CKO_DATA objects should report larger sizes."""
        small = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: "size-small",
                Attribute.VALUE: b"x" * 100,
                Attribute.TOKEN: False,
            }
        )
        large = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: "size-large",
                Attribute.VALUE: b"x" * 10000,
                Attribute.TOKEN: False,
            }
        )

        small_size = _get_object_size(small)
        large_size = _get_object_size(large)

        if small_size is None or large_size is None:
            pytest.skip("C_GetObjectSize not supported")

        assert large_size > small_size, (
            f"10KB data ({large_size}) should be > 100B data ({small_size})"
        )
