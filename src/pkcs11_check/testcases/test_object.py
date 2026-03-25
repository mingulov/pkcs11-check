"""Tests for PKCS#11 object and key attribute management.

Covers object creation, attribute access, search, labels,
key pair attributes, and object lifecycle.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import attr_bytes, attr_ulong, template
from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    find_objects,
    gen_aes_key,
    gen_ec_keypair,
    gen_rsa_keypair,
    import_secret_key,
    read_attributes,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EC_POINT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VERIFY,
    CKK_AES,
    CKK_EC,
    CKK_RSA,
    CKM_SHA256_RSA_PKCS,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
)

pytestmark = pytest.mark.keymgmt


class TestSessionObjects:
    def test_create_secret_key_with_label(self, p11_raw_session: Any) -> None:
        """Create a named AES key and verify its label."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={int(CKA_LABEL): "test-key-object"})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [int(CKA_LABEL)])
            assert attrs[int(CKA_LABEL)] == "test-key-object"
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_find_objects_by_label(self, p11_raw_session: Any) -> None:
        """Find objects matching a label template."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={int(CKA_LABEL): "findme-obj"})
        try:
            tmpl = template(attr_bytes(CKA_LABEL, b"findme-obj"))
            found = find_objects(rs.raw, rs.sh, tmpl)
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_key_attributes_readable(self, p11_raw_session: Any) -> None:
        """Key attributes (type, class) are readable."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={int(CKA_LABEL): "attr-test"})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [int(CKA_KEY_TYPE), int(CKA_CLASS)])
            assert attrs[int(CKA_KEY_TYPE)] == int(CKK_AES)
            assert attrs[int(CKA_CLASS)] == int(CKO_SECRET_KEY)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_destroy_session_object(self, p11_raw_session: Any) -> None:
        """Destroying a session object removes it."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 128, attrs={int(CKA_LABEL): "destroy-me"})
        rs.raw.C_DestroyObject(rs.sh, key)
        tmpl = template(attr_bytes(CKA_LABEL, b"destroy-me"))
        found = find_objects(rs.raw, rs.sh, tmpl)
        assert len(found) == 0

    def test_multiple_keys_same_type(self, p11_raw_session: Any) -> None:
        """Multiple keys of same type coexist."""
        rs = p11_raw_session
        k1 = gen_aes_key(rs.raw, rs.sh, 256, attrs={int(CKA_LABEL): "multi-1"})
        k2 = gen_aes_key(rs.raw, rs.sh, 256, attrs={int(CKA_LABEL): "multi-2"})
        try:
            tmpl = template(attr_ulong(CKA_CLASS, int(CKO_SECRET_KEY)))
            found = find_objects(rs.raw, rs.sh, tmpl)
            labels = set()
            for h in found:
                a = read_attributes(rs.raw, rs.sh, h, [int(CKA_LABEL)])
                labels.add(a[int(CKA_LABEL)])
            assert "multi-1" in labels
            assert "multi-2" in labels
        finally:
            destroy_quietly(rs.raw, rs.sh, k1)
            destroy_quietly(rs.raw, rs.sh, k2)

    def test_find_by_object_class(self, p11_raw_session: Any) -> None:
        """Search by object class returns correct types."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={int(CKA_LABEL): "class-search"})
        try:
            tmpl = template(attr_ulong(CKA_CLASS, int(CKO_SECRET_KEY)))
            found = find_objects(rs.raw, rs.sh, tmpl)
            for h in found:
                a = read_attributes(rs.raw, rs.sh, h, [int(CKA_CLASS)])
                assert a[int(CKA_CLASS)] == int(CKO_SECRET_KEY)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_empty_search_returns_empty(self, p11_raw_session: Any) -> None:
        """Searching with a nonexistent label returns empty."""
        rs = p11_raw_session
        tmpl = template(attr_bytes(CKA_LABEL, b"nonexistent-xyz-42"))
        found = find_objects(rs.raw, rs.sh, tmpl)
        assert len(found) == 0


class TestKeyPairAttributes:
    def test_rsa_keypair_attributes(self, p11_raw_session: Any) -> None:
        """RSA key pair has correct object classes."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [int(CKA_CLASS), int(CKA_KEY_TYPE)])
            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [int(CKA_CLASS), int(CKA_KEY_TYPE)])
            assert pub_attrs[int(CKA_CLASS)] == int(CKO_PUBLIC_KEY)
            assert priv_attrs[int(CKA_CLASS)] == int(CKO_PRIVATE_KEY)
            assert pub_attrs[int(CKA_KEY_TYPE)] == int(CKK_RSA)
            assert priv_attrs[int(CKA_KEY_TYPE)] == int(CKK_RSA)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_modulus_readable(self, p11_raw_session: Any) -> None:
        """RSA public key modulus is readable and correct size."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            attrs = read_attributes(rs.raw, rs.sh, pub, [int(CKA_MODULUS)])
            modulus = attrs[int(CKA_MODULUS)]
            assert len(modulus) == 256  # 2048 bits = 256 bytes
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_public_exponent(self, p11_raw_session: Any) -> None:
        """RSA public exponent is readable and typical value."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            attrs = read_attributes(rs.raw, rs.sh, pub, [int(CKA_PUBLIC_EXPONENT)])
            exp = attrs[int(CKA_PUBLIC_EXPONENT)]
            exp_int = int.from_bytes(exp, "big")
            assert exp_int in (3, 17, 65537)  # Common RSA exponents
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ec_keypair_attributes(self, p11_raw_session: Any) -> None:
        """EC key pair has correct key type and params."""
        rs = p11_raw_session
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
        try:
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [int(CKA_KEY_TYPE)])
            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [int(CKA_KEY_TYPE)])
            assert pub_attrs[int(CKA_KEY_TYPE)] == int(CKK_EC)
            assert priv_attrs[int(CKA_KEY_TYPE)] == int(CKK_EC)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ec_point_readable(self, p11_raw_session: Any) -> None:
        """EC public key point is readable."""
        rs = p11_raw_session
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
        try:
            attrs = read_attributes(rs.raw, rs.sh, pub, [int(CKA_EC_POINT)])
            point = attrs[int(CKA_EC_POINT)]
            assert len(point) > 0
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestKeyImportExport:
    def test_import_aes_key_bytes(self, p11_raw_session: Any) -> None:
        """Import raw AES key material."""
        rs = p11_raw_session
        key_bytes = bytes(range(32))
        key = import_secret_key(rs.raw, rs.sh, CKK_AES, key_bytes)
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [int(CKA_KEY_TYPE)])
            assert attrs[int(CKA_KEY_TYPE)] == int(CKK_AES)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_import_rsa_public_key(self, p11_raw_session: Any) -> None:
        """Import an RSA public key from modulus + exponent."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            attrs = read_attributes(
                rs.raw, rs.sh, pub, [int(CKA_MODULUS), int(CKA_PUBLIC_EXPONENT)]
            )
            modulus = attrs[int(CKA_MODULUS)]
            exponent = attrs[int(CKA_PUBLIC_EXPONENT)]

            imported = create_object(rs.raw, rs.sh, {
                int(CKA_CLASS): int(CKO_PUBLIC_KEY),
                int(CKA_KEY_TYPE): int(CKK_RSA),
                int(CKA_MODULUS): modulus,
                int(CKA_PUBLIC_EXPONENT): exponent,
                int(CKA_TOKEN): False,
                int(CKA_VERIFY): True,
            })
            try:
                imp_attrs = read_attributes(rs.raw, rs.sh, imported, [int(CKA_KEY_TYPE)])
                assert imp_attrs[int(CKA_KEY_TYPE)] == int(CKK_RSA)
            finally:
                destroy_quietly(rs.raw, rs.sh, imported)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_imported_key_verifies_signature(self, p11_raw_session: Any) -> None:
        """Sign with generated key, verify with imported copy of pubkey."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(
            rs.raw, rs.sh, 2048,
            private_attrs={int(CKA_SIGN): True},
        )
        try:
            data = b"import-verify roundtrip"
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)

            # Import a copy of the public key
            orig_attrs = read_attributes(
                rs.raw, rs.sh, pub, [int(CKA_MODULUS), int(CKA_PUBLIC_EXPONENT)]
            )
            imported = create_object(rs.raw, rs.sh, {
                int(CKA_CLASS): int(CKO_PUBLIC_KEY),
                int(CKA_KEY_TYPE): int(CKK_RSA),
                int(CKA_MODULUS): orig_attrs[int(CKA_MODULUS)],
                int(CKA_PUBLIC_EXPONENT): orig_attrs[int(CKA_PUBLIC_EXPONENT)],
                int(CKA_TOKEN): False,
                int(CKA_VERIFY): True,
            })
            try:
                verify_single(rs.raw, rs.sh, imported, CKM_SHA256_RSA_PKCS, data, sig)
            finally:
                destroy_quietly(rs.raw, rs.sh, imported)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_extractable_key_value(self, p11_raw_session: Any) -> None:
        """Extractable key's VALUE attribute matches imported bytes."""
        rs = p11_raw_session
        key_bytes = bytes(range(32))
        key = import_secret_key(
            rs.raw, rs.sh, CKK_AES, key_bytes,
            attrs={
                int(CKA_SENSITIVE): False,
                int(CKA_EXTRACTABLE): True,
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [int(CKA_VALUE)])
            assert attrs[int(CKA_VALUE)] == key_bytes
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
