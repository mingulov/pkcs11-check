"""Advanced object search pattern tests.

Tests FindObjects with various attribute combinations that real
applications use: CKA_ID matching, keypair ID linkage, multi-attribute
search, and type-specific filtering.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, ObjectClass

pytestmark = pytest.mark.keymgmt


def _unique_id() -> bytes:
    return uuid.uuid4().bytes[:8]


class TestSearchByID:
    """Test FindObjects using CKA_ID attribute."""

    def test_find_key_by_id(self, p11_session: Any) -> None:
        """Find a key using CKA_ID search."""
        key_id = _unique_id()
        p11_session.generate_key(KeyType.AES, 256, id=key_id, label="id-search")

        found = list(p11_session.get_objects({Attribute.ID: key_id}))
        assert len(found) >= 1

    def test_no_match_by_wrong_id(self, p11_session: Any) -> None:
        """Non-existent CKA_ID returns empty."""
        found = list(p11_session.get_objects({Attribute.ID: _unique_id()}))
        assert len(found) == 0

    def test_search_by_id_and_class(self, p11_session: Any) -> None:
        """Combined CKA_ID + CKA_CLASS search."""
        key_id = _unique_id()
        p11_session.generate_key(KeyType.AES, 256, id=key_id)

        found = list(
            p11_session.get_objects({Attribute.ID: key_id, Attribute.CLASS: ObjectClass.SECRET_KEY})
        )
        assert len(found) >= 1


class TestKeypairIDLinkage:
    """Test that keypair pub/priv share the same CKA_ID."""

    def test_rsa_keypair_same_id(self, p11_session: Any) -> None:
        """RSA keypair pub and priv have the same CKA_ID when set."""
        key_id = _unique_id()
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048, id=key_id)

        pub_id = pub[Attribute.ID]
        priv_id = priv[Attribute.ID]
        assert pub_id == priv_id == key_id

    def test_find_keypair_by_id(self, p11_session: Any) -> None:
        """Both pub and priv key findable by the shared CKA_ID."""
        key_id = _unique_id()
        p11_session.generate_keypair(KeyType.RSA, 2048, id=key_id)

        # Find public key
        pubs = list(
            p11_session.get_objects({Attribute.ID: key_id, Attribute.CLASS: ObjectClass.PUBLIC_KEY})
        )
        assert len(pubs) >= 1

        # Find private key
        privs = list(
            p11_session.get_objects(
                {Attribute.ID: key_id, Attribute.CLASS: ObjectClass.PRIVATE_KEY}
            )
        )
        assert len(privs) >= 1

    def test_find_all_by_id(self, p11_session: Any) -> None:
        """Searching by CKA_ID alone returns both pub and priv."""
        key_id = _unique_id()
        p11_session.generate_keypair(KeyType.RSA, 2048, id=key_id)

        found = list(p11_session.get_objects({Attribute.ID: key_id}))
        assert len(found) >= 2  # Both pub and priv


class TestMultiAttributeSearch:
    """Test complex multi-attribute FindObjects queries."""

    def test_search_by_label_and_type(self, p11_session: Any) -> None:
        """Search by label + key type."""
        label = f"multi-{uuid.uuid4().hex[:8]}"
        p11_session.generate_key(KeyType.AES, 128, label=label)
        p11_session.generate_key(KeyType.AES, 256, label=label)

        found = list(
            p11_session.get_objects(
                {
                    Attribute.LABEL: label,
                    Attribute.CLASS: ObjectClass.SECRET_KEY,
                    Attribute.KEY_TYPE: KeyType.AES,
                }
            )
        )
        assert len(found) >= 2

    def test_search_filters_correctly(self, p11_session: Any) -> None:
        """Multi-attribute search excludes non-matching objects."""
        label = f"filter-{uuid.uuid4().hex[:8]}"
        p11_session.generate_key(KeyType.AES, 256, label=label)

        # Search for non-existent combination
        found = list(
            p11_session.get_objects(
                {Attribute.LABEL: label, Attribute.CLASS: ObjectClass.PUBLIC_KEY}
            )
        )
        assert len(found) == 0  # AES key is SECRET_KEY, not PUBLIC_KEY
