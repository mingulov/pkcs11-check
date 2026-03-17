"""Tests for PKCS#11 object and key attribute management.

Covers object creation, attribute access, search, labels,
key pair attributes, and object lifecycle.
"""

from __future__ import annotations

from typing import Any

import pkcs11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

pytestmark = pytest.mark.keymgmt


class TestSessionObjects:
    def test_create_secret_key_with_label(self, p11_session: Any) -> None:
        """Create a named AES key and verify its label."""
        key = p11_session.generate_key(KeyType.AES, 256, label="test-key-object")
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

    def test_find_by_object_class(self, p11_session: Any) -> None:
        """Search by object class returns correct types."""
        p11_session.generate_key(KeyType.AES, 256, label="class-search")
        found = list(p11_session.get_objects({Attribute.CLASS: ObjectClass.SECRET_KEY}))
        for obj in found:
            assert obj.object_class == ObjectClass.SECRET_KEY

    def test_empty_search_returns_empty(self, p11_session: Any) -> None:
        """Searching with a nonexistent label returns empty."""
        found = list(p11_session.get_objects({Attribute.LABEL: "nonexistent-xyz-42"}))
        assert len(found) == 0


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

    def test_rsa_public_exponent(self, p11_session: Any) -> None:
        """RSA public exponent is readable and typical value."""
        pub, _ = p11_session.generate_keypair(KeyType.RSA, 2048)
        exp = pub[Attribute.PUBLIC_EXPONENT]
        exp_int = int.from_bytes(exp, "big")
        assert exp_int in (3, 17, 65537)  # Common RSA exponents

    def test_ec_keypair_attributes(self, p11_session: Any) -> None:
        """EC key pair has correct key type and params."""
        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        pub, priv = ecparams.generate_keypair()
        assert pub.key_type == KeyType.EC
        assert priv.key_type == KeyType.EC

    def test_ec_point_readable(self, p11_session: Any) -> None:
        """EC public key point is readable."""
        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        pub, _ = ecparams.generate_keypair()
        point = pub[Attribute.EC_POINT]
        assert len(point) > 0


class TestKeyImportExport:
    def test_import_aes_key_bytes(self, p11_session: Any) -> None:
        """Import raw AES key material."""
        key_bytes = bytes(range(32))
        key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.AES,
                Attribute.VALUE: key_bytes,
                Attribute.TOKEN: False,
            }
        )
        assert key.key_type == KeyType.AES

    def test_import_rsa_public_key(self, p11_session: Any) -> None:
        """Import an RSA public key from modulus + exponent."""
        pub, _ = p11_session.generate_keypair(KeyType.RSA, 2048)
        modulus = pub[Attribute.MODULUS]
        exponent = pub[Attribute.PUBLIC_EXPONENT]

        imported = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                Attribute.KEY_TYPE: KeyType.RSA,
                Attribute.MODULUS: modulus,
                Attribute.PUBLIC_EXPONENT: exponent,
                Attribute.TOKEN: False,
                Attribute.VERIFY: True,
            }
        )
        assert imported.key_type == KeyType.RSA

    def test_imported_key_verifies_signature(self, p11_session: Any) -> None:
        """Sign with generated key, verify with imported copy of pubkey."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"import-verify roundtrip"
        sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)

        # Import a copy of the public key
        imported = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                Attribute.KEY_TYPE: KeyType.RSA,
                Attribute.MODULUS: pub[Attribute.MODULUS],
                Attribute.PUBLIC_EXPONENT: pub[Attribute.PUBLIC_EXPONENT],
                Attribute.TOKEN: False,
                Attribute.VERIFY: True,
            }
        )
        assert imported.verify(data, sig, mechanism=Mechanism.SHA256_RSA_PKCS) is True

    def test_extractable_key_value(self, p11_session: Any) -> None:
        """Extractable key's VALUE attribute matches imported bytes."""
        key_bytes = bytes(range(32))
        key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.AES,
                Attribute.VALUE: key_bytes,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
            }
        )
        assert key[Attribute.VALUE] == key_bytes
