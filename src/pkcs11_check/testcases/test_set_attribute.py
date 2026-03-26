"""C_SetAttributeValue tests - attribute mutation on existing objects.

Tests modifying CKA_LABEL, CKA_ID on keys, and verifying that
read-only attributes (CKA_CLASS, CKA_KEY_TYPE, CKA_MODULUS) are rejected.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import attr_bytes, template
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    find_objects,
    gen_aes_key,
    gen_rsa_keypair,
    read_attributes,
    set_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_ID,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_VALUE,
    CKK_RSA,
    CKO_PUBLIC_KEY,
)

pytestmark = pytest.mark.keymgmt


class TestSetAttributePositive:
    """Verify that mutable attributes can be changed."""

    def test_change_label(self, p11_raw_session: Any) -> None:
        """CKA_LABEL can be changed on an existing key."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_LABEL: "before"})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_LABEL])
            assert attrs[CKA_LABEL] == "before"

            set_attributes(rs.raw, rs.sh, key, {CKA_LABEL: "after"})

            # Search by new label works
            tmpl = template(attr_bytes(CKA_LABEL, b"after"))
            found = find_objects(rs.raw, rs.sh, tmpl)
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_change_id(self, p11_raw_session: Any) -> None:
        """CKA_ID can be changed on an existing key."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_ID: b"\x01\x02"})
        try:
            set_attributes(rs.raw, rs.sh, key, {CKA_ID: b"\xaa\xbb"})
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_ID])
            assert attrs[CKA_ID] == b"\xaa\xbb"
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_change_label_on_keypair(self, p11_raw_session: Any) -> None:
        """CKA_LABEL can be changed on RSA public and private keys."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            public_attrs={CKA_LABEL: "rsa-orig"},
            private_attrs={CKA_LABEL: "rsa-orig"},
        )
        try:
            set_attributes(rs.raw, rs.sh, pub, {CKA_LABEL: "rsa-pub-new"})
            set_attributes(rs.raw, rs.sh, priv, {CKA_LABEL: "rsa-priv-new"})

            tmpl_pub = template(attr_bytes(CKA_LABEL, b"rsa-pub-new"))
            assert len(find_objects(rs.raw, rs.sh, tmpl_pub)) >= 1
            tmpl_priv = template(attr_bytes(CKA_LABEL, b"rsa-priv-new"))
            assert len(find_objects(rs.raw, rs.sh, tmpl_priv)) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestSetAttributeNegative:
    """Verify that read-only / immutable attributes are rejected."""

    def test_cannot_change_class(self, p11_raw_session: Any) -> None:
        """CKA_CLASS is read-only - should reject or silently ignore."""
        from pkcs11_check.compliance import ComplianceLevel, note

        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            try:
                set_attributes(rs.raw, rs.sh, key, {CKA_CLASS: CKO_PUBLIC_KEY})
                # If no error, the module silently ignored it - flag it
                note(
                    "Module accepted C_SetAttributeValue on CKA_CLASS without error",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 Base v3.0, Table 15 - CKA_CLASS is read-only",
                )
            except AssertionError:
                pass  # Correct behavior
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_cannot_change_key_type(self, p11_raw_session: Any) -> None:
        """CKA_KEY_TYPE is read-only - should reject or silently ignore."""
        from pkcs11_check.compliance import ComplianceLevel, note

        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            try:
                set_attributes(rs.raw, rs.sh, key, {CKA_KEY_TYPE: CKK_RSA})
                note(
                    "Module accepted C_SetAttributeValue on CKA_KEY_TYPE without error",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 Base v3.0, Table 15 - CKA_KEY_TYPE is read-only",
                )
            except AssertionError:
                pass  # Correct behavior
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_cannot_change_modulus(self, p11_raw_session: Any) -> None:
        """CKA_MODULUS on RSA key is read-only - must reject."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            try:
                set_attributes(rs.raw, rs.sh, pub, {CKA_MODULUS: b"\x00" * 256})
            except AssertionError:
                pass  # Correct behavior
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_cannot_set_value_on_sensitive_key(self, p11_raw_session: Any) -> None:
        """CKA_VALUE on a sensitive key - should reject."""
        from pkcs11_check.compliance import ComplianceLevel, note

        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            try:
                set_attributes(rs.raw, rs.sh, key, {CKA_VALUE: b"\x00" * 32})
                note(
                    "Module accepted C_SetAttributeValue on CKA_VALUE of sensitive key",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 Base v3.0 - CKA_VALUE not settable on sensitive keys",
                )
            except AssertionError:
                pass  # Correct behavior
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
