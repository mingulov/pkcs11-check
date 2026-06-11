"""Generic secret key tests.

Tests CKM_GENERIC_SECRET_KEY_GEN for generating arbitrary-length
secret keys used as HMAC keys, KDF inputs, or protocol secrets.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    gen_aes_key,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VERIFY,
    CKK_GENERIC_SECRET,
    CKK_SHA256_HMAC,
    CKK_SHA512_HMAC,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKM_SHA256_HMAC,
    CKM_SHA512_HMAC,
    CKO_SECRET_KEY,
)
from pkcs11_check.testcases.conftest import hmac_sign_or_xfail

pytestmark = pytest.mark.keymgmt


class TestGenericSecretKeyGen:
    """Test CKM_GENERIC_SECRET_KEY_GEN."""

    def test_generate_generic_secret(self, p11_raw_session: Any) -> None:
        """Generate a generic secret key of various lengths."""
        rs = p11_raw_session
        if not rs.has_mechanism("GENERIC_SECRET_KEY_GEN"):
            pytest.skip("CKM_GENERIC_SECRET_KEY_GEN not supported")

        for bits in [128, 256, 512]:
            key = gen_aes_key(
                rs.raw,
                rs.sh,
                bits,
                mechanism=CKM_GENERIC_SECRET_KEY_GEN,
                attrs={
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                },
            )
            try:
                attrs = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])
                value = attrs[CKA_VALUE]
                assert isinstance(value, bytes)
                assert len(value) == bits // 8
            finally:
                destroy_quietly(rs.raw, rs.sh, key)

    def test_generic_secret_unique(self, p11_raw_session: Any) -> None:
        """Two generic secret keys have different values."""
        rs = p11_raw_session
        if not rs.has_mechanism("GENERIC_SECRET_KEY_GEN"):
            pytest.skip("CKM_GENERIC_SECRET_KEY_GEN not supported")

        k1 = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            mechanism=CKM_GENERIC_SECRET_KEY_GEN,
            attrs={
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
            },
        )
        k2 = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            mechanism=CKM_GENERIC_SECRET_KEY_GEN,
            attrs={
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
            },
        )
        try:
            v1 = read_attributes(rs.raw, rs.sh, k1, [CKA_VALUE])[CKA_VALUE]
            v2 = read_attributes(rs.raw, rs.sh, k2, [CKA_VALUE])[CKA_VALUE]
            assert v1 != v2
        finally:
            destroy_quietly(rs.raw, rs.sh, k1)
            destroy_quietly(rs.raw, rs.sh, k2)


class TestGenericSecretHMAC:
    """Test using generic secret keys for HMAC operations."""

    def test_hmac_with_imported_generic_secret(self, p11_raw_session: Any) -> None:
        """Import a known key as generic secret, compute HMAC, cross-verify."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")
        key_bytes = b"hmac-test-key-for-generic-secret"
        data = b"HMAC with generic secret key"

        key_h = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_SHA256_HMAC,
                CKA_VALUE: key_bytes,
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
        try:
            p11_mac = hmac_sign_or_xfail(rs, key_h, CKM_SHA256_HMAC, data, label="SHA256_HMAC")
            expected = hmac_mod.new(key_bytes, data, hashlib.sha256).digest()
            assert p11_mac == expected
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_hmac_sha512_crossverify(self, p11_raw_session: Any) -> None:
        """HMAC-SHA512 with known key cross-verified."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA512_HMAC"):
            pytest.skip("CKM_SHA512_HMAC not supported")
        key_bytes = bytes(range(64))
        data = b"HMAC-SHA512 cross-verification test data"

        key_h = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_SHA512_HMAC,
                CKA_VALUE: key_bytes,
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
        try:
            p11_mac = hmac_sign_or_xfail(rs, key_h, CKM_SHA512_HMAC, data, label="SHA512_HMAC")
            expected = hmac_mod.new(key_bytes, data, hashlib.sha512).digest()
            assert p11_mac == expected
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)
