"""Tests for PKCS#11 object search and enumeration (C_FindObjects)."""

from __future__ import annotations

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
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKK_AES,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
)

pytestmark = pytest.mark.search


class TestObjectSearch:
    """Test C_FindObjectsInit / C_FindObjects / C_FindObjectsFinal."""

    def test_find_by_label(self, p11_raw_session: Any) -> None:
        """Find object by exact label match."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={int(CKA_LABEL): "search-label"})
        try:
            tmpl = template(attr_bytes(CKA_LABEL, b"search-label"))
            found = find_objects(rs.raw, rs.sh, tmpl)
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_find_by_class(self, p11_raw_session: Any) -> None:
        """Find objects by class (SECRET_KEY)."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 128, attrs={int(CKA_LABEL): "search-class"})
        try:
            tmpl = template(attr_ulong(CKA_CLASS, int(CKO_SECRET_KEY)))
            found = find_objects(rs.raw, rs.sh, tmpl)
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_find_by_multiple_attributes(self, p11_raw_session: Any) -> None:
        """Find objects matching multiple attributes."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={int(CKA_LABEL): "search-multi"})
        try:
            tmpl = template(
                attr_ulong(CKA_CLASS, int(CKO_SECRET_KEY)),
                attr_bytes(CKA_LABEL, b"search-multi"),
                attr_ulong(CKA_KEY_TYPE, int(CKK_AES)),
            )
            found = find_objects(rs.raw, rs.sh, tmpl)
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_find_nonexistent_returns_empty(self, p11_raw_session: Any) -> None:
        """Search for nonexistent label returns empty list."""
        rs = p11_raw_session
        tmpl = template(attr_bytes(CKA_LABEL, b"this-label-does-not-exist-12345"))
        found = find_objects(rs.raw, rs.sh, tmpl)
        assert len(found) == 0

    def test_find_all_objects(self, p11_raw_session: Any) -> None:
        """Empty template returns all visible objects."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 128, attrs={int(CKA_LABEL): "search-all"})
        try:
            found = find_objects(rs.raw, rs.sh, None)
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_find_many_objects(self, p11_raw_session: Any) -> None:
        """Create 50 objects and verify all are findable."""
        rs = p11_raw_session
        keys = []
        for i in range(50):
            k = gen_aes_key(rs.raw, rs.sh, 128, attrs={int(CKA_LABEL): f"bulk-{i:03d}"})
            keys.append(k)
        try:
            tmpl = template(attr_ulong(CKA_CLASS, int(CKO_SECRET_KEY)))
            found = find_objects(rs.raw, rs.sh, tmpl)
            found_labels = set()
            for h in found:
                a = read_attributes(rs.raw, rs.sh, h, [int(CKA_LABEL)])
                found_labels.add(a[int(CKA_LABEL)])
            for i in range(50):
                assert f"bulk-{i:03d}" in found_labels
        finally:
            for k in keys:
                destroy_quietly(rs.raw, rs.sh, k)

    def test_find_after_destroy(self, p11_raw_session: Any) -> None:
        """Destroyed objects should not appear in search."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 128, attrs={int(CKA_LABEL): "search-destroy"})
        rs.raw.C_DestroyObject(rs.sh, key)
        tmpl = template(attr_bytes(CKA_LABEL, b"search-destroy"))
        found = find_objects(rs.raw, rs.sh, tmpl)
        assert len(found) == 0


class TestKeyPairSearch:
    """Test finding public/private key pairs."""

    def test_find_public_key(self, p11_raw_session: Any) -> None:
        """Find generated public key."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            tmpl = template(attr_ulong(CKA_CLASS, int(CKO_PUBLIC_KEY)))
            found = find_objects(rs.raw, rs.sh, tmpl)
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_find_private_key(self, p11_raw_session: Any) -> None:
        """Find generated private key."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            tmpl = template(attr_ulong(CKA_CLASS, int(CKO_PRIVATE_KEY)))
            found = find_objects(rs.raw, rs.sh, tmpl)
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
