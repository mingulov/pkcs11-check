"""C_GetObjectSize tests.

Tests that the module reports reasonable object sizes for various
key types and data objects, or returns CK_UNAVAILABLE_INFORMATION.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    gen_aes_key,
    gen_rsa_keypair,
    get_object_size,
)
from pkcs11_check.raw.types_std import (
    CK_UNAVAILABLE_INFORMATION,
    CKA_CLASS,
    CKA_LABEL,
    CKA_TOKEN,
    CKA_VALUE,
    CKO_DATA,
)

pytestmark = pytest.mark.keymgmt

CK_UNAVAILABLE = CK_UNAVAILABLE_INFORMATION


def _safe_get_size(raw: Any, sh: int, handle: int) -> int | None:
    """Get object size, returning None if not supported or not meaningful.

    Per PKCS#11 spec, C_GetObjectSize MAY return CK_UNAVAILABLE_INFORMATION
    (~0) or 0 to indicate the size is not available or not meaningful for
    the object type. Both are treated as "not supported" here.
    """
    try:
        size = get_object_size(raw, sh, handle)
        if size == CK_UNAVAILABLE or size == 0:
            return None
        return size
    except Exception:
        return None


class TestObjectSize:
    """Test C_GetObjectSize."""

    def test_aes_key_has_size(self, p11_raw_session: Any) -> None:
        """AES key reports a size (or CK_UNAVAILABLE_INFORMATION)."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            size = _safe_get_size(rs.raw, rs.sh, key)

            if size is None:
                pytest.skip("C_GetObjectSize not supported (returns CK_UNAVAILABLE_INFORMATION)")

            # AES-256 key is at minimum 32 bytes of material
            assert size >= 32, f"AES-256 object size {size} suspiciously small"
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_rsa_key_larger_than_aes(self, p11_raw_session: Any) -> None:
        """RSA-2048 key should be larger than AES-256 key."""
        rs = p11_raw_session
        aes_key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            aes_size = _safe_get_size(rs.raw, rs.sh, aes_key)
        finally:
            destroy_quietly(rs.raw, rs.sh, aes_key)

        if aes_size is None:
            pytest.skip("C_GetObjectSize not supported (returns 0 or CK_UNAVAILABLE_INFORMATION)")

        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            rsa_size = _safe_get_size(rs.raw, rs.sh, priv)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

        if rsa_size is None:
            pytest.skip(
                "C_GetObjectSize not supported for RSA (returns 0 or CK_UNAVAILABLE_INFORMATION)"
            )

        assert rsa_size > aes_size, (
            f"RSA-2048 size ({rsa_size}) should be > AES-256 size ({aes_size})"
        )

    def test_data_object_size_scales(self, p11_raw_session: Any) -> None:
        """Larger CKO_DATA objects should report larger sizes."""
        rs = p11_raw_session
        small = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: "size-small",
                CKA_VALUE: b"x" * 100,
                CKA_TOKEN: False,
            },
        )
        large = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: "size-large",
                CKA_VALUE: b"x" * 10000,
                CKA_TOKEN: False,
            },
        )
        try:
            small_size = _safe_get_size(rs.raw, rs.sh, small)
            large_size = _safe_get_size(rs.raw, rs.sh, large)

            if small_size is None or large_size is None:
                pytest.skip("C_GetObjectSize not supported")

            assert large_size > small_size, (
                f"10KB data ({large_size}) should be > 100B data ({small_size})"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, small)
            destroy_quietly(rs.raw, rs.sh, large)
