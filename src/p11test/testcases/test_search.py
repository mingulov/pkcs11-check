"""Tests for PKCS#11 object search and enumeration (C_FindObjects)."""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, ObjectClass

pytestmark = pytest.mark.search


class TestObjectSearch:
    """Test C_FindObjectsInit / C_FindObjects / C_FindObjectsFinal."""

    def test_find_by_label(self, p11_session: Any) -> None:
        """Find object by exact label match."""
        key = p11_session.generate_key(KeyType.AES, 256, label="search-label")
        found = list(p11_session.get_objects({Attribute.LABEL: "search-label"}))
        assert len(found) >= 1
        key.destroy()

    def test_find_by_class(self, p11_session: Any) -> None:
        """Find objects by class (SECRET_KEY)."""
        key = p11_session.generate_key(KeyType.AES, 128, label="search-class")
        found = list(p11_session.get_objects({Attribute.CLASS: ObjectClass.SECRET_KEY}))
        assert len(found) >= 1
        key.destroy()

    def test_find_by_multiple_attributes(self, p11_session: Any) -> None:
        """Find objects matching multiple attributes."""
        key = p11_session.generate_key(KeyType.AES, 256, label="search-multi")
        found = list(
            p11_session.get_objects(
                {
                    Attribute.CLASS: ObjectClass.SECRET_KEY,
                    Attribute.LABEL: "search-multi",
                    Attribute.KEY_TYPE: KeyType.AES,
                }
            )
        )
        assert len(found) >= 1
        key.destroy()

    def test_find_nonexistent_returns_empty(self, p11_session: Any) -> None:
        """Search for nonexistent label returns empty list."""
        found = list(p11_session.get_objects({Attribute.LABEL: "this-label-does-not-exist-12345"}))
        assert len(found) == 0

    def test_find_all_objects(self, p11_session: Any) -> None:
        """Empty template returns all visible objects."""
        key = p11_session.generate_key(KeyType.AES, 128, label="search-all")
        found = list(p11_session.get_objects({}))
        assert len(found) >= 1
        key.destroy()

    def test_find_many_objects(self, p11_session: Any) -> None:
        """Create 50 objects and verify all are findable."""
        keys = []
        for i in range(50):
            key = p11_session.generate_key(KeyType.AES, 128, label=f"bulk-{i:03d}")
            keys.append(key)

        found = list(p11_session.get_objects({Attribute.CLASS: ObjectClass.SECRET_KEY}))
        found_labels = {obj.label for obj in found}
        for i in range(50):
            assert f"bulk-{i:03d}" in found_labels

        for key in keys:
            key.destroy()

    def test_find_after_destroy(self, p11_session: Any) -> None:
        """Destroyed objects should not appear in search."""
        key = p11_session.generate_key(KeyType.AES, 128, label="search-destroy")
        key.destroy()
        found = list(p11_session.get_objects({Attribute.LABEL: "search-destroy"}))
        assert len(found) == 0


class TestKeyPairSearch:
    """Test finding public/private key pairs."""

    def test_find_public_key(self, p11_session: Any) -> None:
        """Find generated public key."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        found = list(p11_session.get_objects({Attribute.CLASS: ObjectClass.PUBLIC_KEY}))
        assert len(found) >= 1
        pub.destroy()
        priv.destroy()

    def test_find_private_key(self, p11_session: Any) -> None:
        """Find generated private key."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        found = list(p11_session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY}))
        assert len(found) >= 1
        pub.destroy()
        priv.destroy()
