"""Generic secret key tests.

Tests CKM_GENERIC_SECRET_KEY_GEN for generating arbitrary-length
secret keys used as HMAC keys, KDF inputs, or protocol secrets.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

from p11test.testcases.conftest import has_mechanism

pytestmark = pytest.mark.keymgmt


class TestGenericSecretKeyGen:
    """Test CKM_GENERIC_SECRET_KEY_GEN."""

    def test_generate_generic_secret(self, p11_session: Any, p11_module: Any) -> None:
        """Generate a generic secret key of various lengths."""
        if not has_mechanism(p11_module, "GENERIC_SECRET_KEY_GEN"):
            pytest.skip("CKM_GENERIC_SECRET_KEY_GEN not supported")

        for bits in [128, 256, 512]:
            key = p11_session.generate_key(
                KeyType.GENERIC_SECRET,
                bits,
                template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True},
            )
            value = key[Attribute.VALUE]
            assert len(value) == bits // 8

    def test_generic_secret_unique(self, p11_session: Any, p11_module: Any) -> None:
        """Two generic secret keys have different values."""
        if not has_mechanism(p11_module, "GENERIC_SECRET_KEY_GEN"):
            pytest.skip("CKM_GENERIC_SECRET_KEY_GEN not supported")

        k1 = p11_session.generate_key(
            KeyType.GENERIC_SECRET,
            256,
            template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True},
        )
        k2 = p11_session.generate_key(
            KeyType.GENERIC_SECRET,
            256,
            template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True},
        )
        assert k1[Attribute.VALUE] != k2[Attribute.VALUE]


class TestGenericSecretHMAC:
    """Test using generic secret keys for HMAC operations."""

    def test_hmac_with_imported_generic_secret(self, p11_session: Any) -> None:
        """Import a known key as generic secret, compute HMAC, cross-verify."""
        key_bytes = b"hmac-test-key-for-generic-secret"
        data = b"HMAC with generic secret key"

        p11_key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.SHA256_HMAC,
                Attribute.VALUE: key_bytes,
                Attribute.SIGN: True,
                Attribute.VERIFY: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )

        p11_mac = p11_key.sign(data, mechanism=Mechanism.SHA256_HMAC)
        expected = hmac_mod.new(key_bytes, data, hashlib.sha256).digest()
        assert p11_mac == expected

    def test_hmac_sha512_crossverify(self, p11_session: Any) -> None:
        """HMAC-SHA512 with known key cross-verified."""
        key_bytes = bytes(range(64))
        data = b"HMAC-SHA512 cross-verification test data"

        p11_key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.SHA512_HMAC,
                Attribute.VALUE: key_bytes,
                Attribute.SIGN: True,
                Attribute.VERIFY: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )

        p11_mac = p11_key.sign(data, mechanism=Mechanism.SHA512_HMAC)
        expected = hmac_mod.new(key_bytes, data, hashlib.sha512).digest()
        assert p11_mac == expected
