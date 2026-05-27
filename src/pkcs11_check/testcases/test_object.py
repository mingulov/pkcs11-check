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
from pkcs11_check.testcases._rsa_export import rsa_public_key_from_attrs_or_xfail
from pkcs11_check.testcases.conftest import (
    KEYPAIR_RUNTIME_REJECT_RVS,
    gen_aes_key_or_xfail,
    gen_ec_keypair_or_xfail,
    gen_rsa_keypair_or_xfail,
    skip_unless_mechanism,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.keymgmt


class TestSessionObjects:
    def test_create_secret_key_with_label(self, p11_raw_session: Any) -> None:
        """Create a named AES key and verify its label."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            bits=128,
            attrs={CKA_LABEL: "test-key-object"},
            purpose="object label setup",
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_LABEL])
            assert attrs[CKA_LABEL] == "test-key-object"
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_find_objects_by_label(self, p11_raw_session: Any) -> None:
        """Find objects matching a label template."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            bits=128,
            attrs={CKA_LABEL: "findme-obj"},
            purpose="object label search setup",
        )
        try:
            tmpl = template(attr_bytes(CKA_LABEL, b"findme-obj"))
            found = find_objects(rs.raw, rs.sh, tmpl)
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_key_attributes_readable(self, p11_raw_session: Any) -> None:
        """Key attributes (type, class) are readable."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            bits=128,
            attrs={CKA_LABEL: "attr-test"},
            purpose="object attribute readback setup",
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_KEY_TYPE, CKA_CLASS])
            assert attrs[CKA_KEY_TYPE] == CKK_AES
            assert attrs[CKA_CLASS] == CKO_SECRET_KEY
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_destroy_session_object(self, p11_raw_session: Any) -> None:
        """Destroying a session object removes it."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            bits=128,
            attrs={CKA_LABEL: "destroy-me"},
            purpose="object destroy setup",
        )
        rs.raw.C_DestroyObject(rs.sh, key)
        tmpl = template(attr_bytes(CKA_LABEL, b"destroy-me"))
        found = find_objects(rs.raw, rs.sh, tmpl)
        assert len(found) == 0

    def test_multiple_keys_same_type(self, p11_raw_session: Any) -> None:
        """Multiple keys of same type coexist."""
        rs = p11_raw_session
        k1 = gen_aes_key_or_xfail(
            rs,
            bits=128,
            attrs={CKA_LABEL: "multi-1"},
            purpose="multi-object setup",
        )
        k2 = gen_aes_key_or_xfail(
            rs,
            bits=128,
            attrs={CKA_LABEL: "multi-2"},
            purpose="multi-object setup",
        )
        try:
            tmpl = template(attr_ulong(CKA_CLASS, CKO_SECRET_KEY))
            found = find_objects(rs.raw, rs.sh, tmpl)
            labels = set()
            for h in found:
                a = read_attributes(rs.raw, rs.sh, h, [CKA_LABEL])
                labels.add(a[CKA_LABEL])
            assert "multi-1" in labels
            assert "multi-2" in labels
        finally:
            destroy_quietly(rs.raw, rs.sh, k1)
            destroy_quietly(rs.raw, rs.sh, k2)

    def test_find_by_object_class(self, p11_raw_session: Any) -> None:
        """Search by object class returns correct types."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            bits=128,
            attrs={CKA_LABEL: "class-search"},
            purpose="object class search setup",
        )
        try:
            tmpl = template(attr_ulong(CKA_CLASS, CKO_SECRET_KEY))
            found = find_objects(rs.raw, rs.sh, tmpl)
            for h in found:
                a = read_attributes(rs.raw, rs.sh, h, [CKA_CLASS])
                assert a[CKA_CLASS] == CKO_SECRET_KEY
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
        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_CLASS, CKA_KEY_TYPE])
            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_CLASS, CKA_KEY_TYPE])
            assert pub_attrs[CKA_CLASS] == CKO_PUBLIC_KEY
            assert priv_attrs[CKA_CLASS] == CKO_PRIVATE_KEY
            assert pub_attrs[CKA_KEY_TYPE] == CKK_RSA
            assert priv_attrs[CKA_KEY_TYPE] == CKK_RSA
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_modulus_readable(self, p11_raw_session: Any) -> None:
        """RSA public key modulus is readable and correct size."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_MODULUS])
            modulus = attrs[CKA_MODULUS]
            assert len(modulus) == 256  # 2048 bits = 256 bytes
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_public_exponent(self, p11_raw_session: Any) -> None:
        """RSA public exponent is readable and typical value."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_PUBLIC_EXPONENT])
            exp = attrs[CKA_PUBLIC_EXPONENT]
            exp_int = int.from_bytes(exp, "big")
            assert exp_int in (3, 17, 65537)  # Common RSA exponents
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ec_keypair_attributes(self, p11_raw_session: Any) -> None:
        """EC key pair has correct key type and params."""
        rs = p11_raw_session
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair_or_xfail(rs, curve_oid)
        try:
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_KEY_TYPE])
            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_KEY_TYPE])
            assert pub_attrs[CKA_KEY_TYPE] == CKK_EC
            assert priv_attrs[CKA_KEY_TYPE] == CKK_EC
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ec_point_readable(self, p11_raw_session: Any) -> None:
        """EC public key point is readable."""
        rs = p11_raw_session
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair_or_xfail(rs, curve_oid)
        try:
            attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_EC_POINT])
            point = attrs[CKA_EC_POINT]
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
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_KEY_TYPE])
            assert attrs[CKA_KEY_TYPE] == CKK_AES
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_import_rsa_public_key(self, p11_raw_session: Any) -> None:
        """Import an RSA public key from modulus + exponent."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_MODULUS, CKA_PUBLIC_EXPONENT])
            rsa_public_key_from_attrs_or_xfail(attrs, label="generated RSA public key for import")
            modulus = attrs[CKA_MODULUS]
            exponent = attrs[CKA_PUBLIC_EXPONENT]

            try:
                imported = create_object(
                    rs.raw,
                    rs.sh,
                    {
                        CKA_CLASS: CKO_PUBLIC_KEY,
                        CKA_KEY_TYPE: CKK_RSA,
                        CKA_MODULUS: modulus,
                        CKA_PUBLIC_EXPONENT: exponent,
                        CKA_TOKEN: False,
                        CKA_VERIFY: True,
                    },
                )
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    KEYPAIR_RUNTIME_REJECT_RVS,
                    "RSA public key import not operational",
                )
                raise
            try:
                imp_attrs = read_attributes(rs.raw, rs.sh, imported, [CKA_KEY_TYPE])
                assert imp_attrs[CKA_KEY_TYPE] == CKK_RSA
            finally:
                destroy_quietly(rs.raw, rs.sh, imported)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_imported_key_verifies_signature(self, p11_raw_session: Any) -> None:
        """Sign with generated key, verify with imported copy of pubkey."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "SHA256_RSA_PKCS")
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            private_attrs={CKA_SIGN: True},
        )
        try:
            data = b"import-verify roundtrip"
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)

            # Import a copy of the public key
            orig_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_MODULUS, CKA_PUBLIC_EXPONENT])
            rsa_public_key_from_attrs_or_xfail(
                orig_attrs,
                label="generated RSA public key for import",
            )
            try:
                imported = create_object(
                    rs.raw,
                    rs.sh,
                    {
                        CKA_CLASS: CKO_PUBLIC_KEY,
                        CKA_KEY_TYPE: CKK_RSA,
                        CKA_MODULUS: orig_attrs[CKA_MODULUS],
                        CKA_PUBLIC_EXPONENT: orig_attrs[CKA_PUBLIC_EXPONENT],
                        CKA_TOKEN: False,
                        CKA_VERIFY: True,
                    },
                )
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    KEYPAIR_RUNTIME_REJECT_RVS,
                    "RSA public key import not operational",
                )
                raise
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
            rs.raw,
            rs.sh,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])
            assert attrs[CKA_VALUE] == key_bytes
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
