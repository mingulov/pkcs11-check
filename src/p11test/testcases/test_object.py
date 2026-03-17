"""Tests for PKCS#11 object and key attribute management."""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, ObjectClass

pytestmark = pytest.mark.keymgmt


class TestSessionObjects:
    def test_create_secret_key_with_label(self, p11_session: Any) -> None:
        """Create a named AES key and verify its label."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            label="test-key-object",
        )
        assert key is not None
        assert key.label == "test-key-object"

    def test_find_objects_by_label(self, p11_session: Any) -> None:
        """Find objects matching a label template."""
        p11_session.generate_key(KeyType.AES, 256, label="findme-obj")
        found = list(p11_session.get_objects({Attribute.LABEL: "findme-obj"}))
        assert len(found) >= 1

    def test_key_attributes_readable(self, p11_session: Any) -> None:
        """Key attributes (type, class) are readable."""
        key = p11_session.generate_key(KeyType.AES, 256, label="attr-test")
        assert key.key_type == KeyType.AES
        assert key.object_class == ObjectClass.SECRET_KEY

    def test_destroy_session_object(self, p11_session: Any) -> None:
        """Destroying a session object removes it."""
        key = p11_session.generate_key(KeyType.AES, 128, label="destroy-me")
        key.destroy()
        found = list(p11_session.get_objects({Attribute.LABEL: "destroy-me"}))
        assert len(found) == 0

    def test_multiple_keys_same_type(self, p11_session: Any) -> None:
        """Multiple keys of same type coexist."""
        p11_session.generate_key(KeyType.AES, 256, label="multi-1")
        p11_session.generate_key(KeyType.AES, 256, label="multi-2")
        found = list(p11_session.get_objects({Attribute.CLASS: ObjectClass.SECRET_KEY}))
        labels = {obj.label for obj in found}
        assert "multi-1" in labels
        assert "multi-2" in labels


class TestKeyPairAttributes:
    def test_rsa_keypair_attributes(self, p11_session: Any) -> None:
        """RSA key pair has correct object classes."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        assert pub.object_class == ObjectClass.PUBLIC_KEY
        assert priv.object_class == ObjectClass.PRIVATE_KEY
        assert pub.key_type == KeyType.RSA
        assert priv.key_type == KeyType.RSA

    def test_rsa_modulus_readable(self, p11_session: Any) -> None:
        """RSA public key modulus is readable and correct size."""
        pub, _ = p11_session.generate_keypair(KeyType.RSA, 2048)
        modulus = pub[Attribute.MODULUS]
        assert len(modulus) == 256  # 2048 bits = 256 bytes
