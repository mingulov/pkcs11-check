"""Advanced object search pattern tests.

Tests FindObjects with various attribute combinations that real
applications use: CKA_ID matching, keypair ID linkage, multi-attribute
search, and type-specific filtering.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from pkcs11_check.raw.pack import attr_bytes, attr_ulong, template
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    find_objects,
    gen_aes_key,
    gen_rsa_keypair,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_ID,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKK_AES,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
)

pytestmark = pytest.mark.keymgmt


def _unique_id() -> bytes:
    return uuid.uuid4().bytes[:8]


class TestSearchByID:
    """Test FindObjects using CKA_ID attribute."""

    def test_find_key_by_id(self, p11_raw_session: Any) -> None:
        """Find a key using CKA_ID search."""
        rs = p11_raw_session
        key_id = _unique_id()
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_ID: key_id, CKA_LABEL: "id-search"},
        )
        try:
            tmpl = template(attr_bytes(CKA_ID, key_id))
            found = find_objects(rs.raw, rs.sh, tmpl)
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_no_match_by_wrong_id(self, p11_raw_session: Any) -> None:
        """Non-existent CKA_ID returns empty."""
        rs = p11_raw_session
        tmpl = template(attr_bytes(CKA_ID, _unique_id()))
        found = find_objects(rs.raw, rs.sh, tmpl)
        assert len(found) == 0

    def test_search_by_id_and_class(self, p11_raw_session: Any) -> None:
        """Combined CKA_ID + CKA_CLASS search."""
        rs = p11_raw_session
        key_id = _unique_id()
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_ID: key_id})
        try:
            tmpl = template(
                attr_bytes(CKA_ID, key_id),
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
            )
            found = find_objects(rs.raw, rs.sh, tmpl)
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestKeypairIDLinkage:
    """Test that keypair pub/priv share the same CKA_ID."""

    def test_rsa_keypair_same_id(self, p11_raw_session: Any) -> None:
        """RSA keypair pub and priv have the same CKA_ID when set."""
        rs = p11_raw_session
        key_id = _unique_id()
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            public_attrs={CKA_ID: key_id},
            private_attrs={CKA_ID: key_id},
        )
        try:
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_ID])
            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_ID])
            assert pub_attrs[CKA_ID] == priv_attrs[CKA_ID] == key_id
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_find_keypair_by_id(self, p11_raw_session: Any) -> None:
        """Both pub and priv key findable by the shared CKA_ID."""
        rs = p11_raw_session
        key_id = _unique_id()
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            public_attrs={CKA_ID: key_id},
            private_attrs={CKA_ID: key_id},
        )
        try:
            # Find public key
            tmpl_pub = template(
                attr_bytes(CKA_ID, key_id),
                attr_ulong(CKA_CLASS, CKO_PUBLIC_KEY),
            )
            pubs = find_objects(rs.raw, rs.sh, tmpl_pub)
            assert len(pubs) >= 1

            # Find private key
            tmpl_priv = template(
                attr_bytes(CKA_ID, key_id),
                attr_ulong(CKA_CLASS, CKO_PRIVATE_KEY),
            )
            privs = find_objects(rs.raw, rs.sh, tmpl_priv)
            assert len(privs) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_find_all_by_id(self, p11_raw_session: Any) -> None:
        """Searching by CKA_ID alone returns both pub and priv."""
        rs = p11_raw_session
        key_id = _unique_id()
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            public_attrs={CKA_ID: key_id},
            private_attrs={CKA_ID: key_id},
        )
        try:
            tmpl = template(attr_bytes(CKA_ID, key_id))
            found = find_objects(rs.raw, rs.sh, tmpl)
            assert len(found) >= 2  # Both pub and priv
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestMultiAttributeSearch:
    """Test complex multi-attribute FindObjects queries."""

    def test_search_by_label_and_type(self, p11_raw_session: Any) -> None:
        """Search by label + key type."""
        rs = p11_raw_session
        label = f"multi-{uuid.uuid4().hex[:8]}"
        k1 = gen_aes_key(rs.raw, rs.sh, 128, attrs={CKA_LABEL: label})
        k2 = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_LABEL: label})
        try:
            tmpl = template(
                attr_bytes(CKA_LABEL, label.encode("utf-8")),
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_AES),
            )
            found = find_objects(rs.raw, rs.sh, tmpl)
            assert len(found) >= 2
        finally:
            destroy_quietly(rs.raw, rs.sh, k1)
            destroy_quietly(rs.raw, rs.sh, k2)

    def test_search_filters_correctly(self, p11_raw_session: Any) -> None:
        """Multi-attribute search excludes non-matching objects."""
        rs = p11_raw_session
        label = f"filter-{uuid.uuid4().hex[:8]}"
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_LABEL: label})
        try:
            # Search for non-existent combination
            tmpl = template(
                attr_bytes(CKA_LABEL, label.encode("utf-8")),
                attr_ulong(CKA_CLASS, CKO_PUBLIC_KEY),
            )
            found = find_objects(rs.raw, rs.sh, tmpl)
            assert len(found) == 0  # AES key is SECRET_KEY, not PUBLIC_KEY
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
