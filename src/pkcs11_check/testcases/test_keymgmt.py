"""Tests for PKCS#11 key management: import, export, wrap, unwrap, derive, copy."""

from __future__ import annotations

from typing import Any

import pkcs11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.mechanisms import KDF

from pkcs11_check.testcases.conftest import extract_ec_point

pytestmark = pytest.mark.keymgmt


class TestKeyImport:
    def test_import_aes_key(self, p11_session: Any) -> None:
        """Import raw AES key material and verify attributes."""
        key_bytes = bytes(range(32))
        key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.AES,
                Attribute.VALUE: key_bytes,
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: False,
            }
        )
        assert key is not None
        assert key.key_type == KeyType.AES

    def test_import_aes_key_roundtrip(self, p11_session: Any) -> None:
        """Import AES key, encrypt, decrypt, verify roundtrip."""
        key_bytes = bytes(range(32))
        key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.AES,
                Attribute.VALUE: key_bytes,
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
            }
        )
        plaintext = b"import_rndtrip!!"  # exactly 16 bytes
        ct = key.encrypt(plaintext, mechanism=pkcs11.Mechanism.AES_ECB)
        pt = key.decrypt(ct, mechanism=pkcs11.Mechanism.AES_ECB)
        assert pt == plaintext

    def test_extractable_key_export(self, p11_session: Any) -> None:
        """Export extractable key and verify material matches."""
        key_bytes = bytes(range(16))
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
        exported = key[Attribute.VALUE]
        assert exported == key_bytes

    def test_import_multiple_sizes(self, p11_session: Any) -> None:
        """Import AES keys at 128, 192, 256 bit sizes."""
        for size_bytes in [16, 24, 32]:
            key_bytes = bytes(size_bytes)
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


class TestKeyExport:
    def test_rsa_modulus_export(self, p11_session: Any) -> None:
        """Export RSA modulus and exponent."""
        pub, _ = p11_session.generate_keypair(KeyType.RSA, 2048)
        modulus = pub[Attribute.MODULUS]
        assert len(modulus) == 256
        exponent = pub[Attribute.PUBLIC_EXPONENT]
        assert len(exponent) >= 1

    def test_ec_point_export(self, p11_session: Any) -> None:
        """Export EC public key point."""
        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {pkcs11.Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        pub, _ = ecparams.generate_keypair()
        ec_point = pub[Attribute.EC_POINT]
        assert len(ec_point) > 0


class TestKeyCopy:
    def test_copy_preserves_attributes(self, p11_session: Any) -> None:
        """Copy a key and verify attributes are preserved."""
        original = p11_session.generate_key(KeyType.AES, 256, label="original")
        copy = original.copy({Attribute.LABEL: "copy"})
        assert copy.label == "copy"
        assert copy.key_type == KeyType.AES

    def test_copy_independent(self, p11_session: Any) -> None:
        """Copied key works independently after original is destroyed."""
        original = p11_session.generate_key(KeyType.AES, 256)
        copy = original.copy({Attribute.LABEL: "independent"})
        original.destroy()
        ct = copy.encrypt(b"still works here", mechanism=pkcs11.Mechanism.AES_ECB)
        assert len(ct) > 0


class TestKeyWrapUnwrap:
    def test_wrap_unwrap_roundtrip(self, p11_session: Any) -> None:
        """Wrap and unwrap a key, verify material is preserved."""
        key_bytes = bytes(range(16))
        wrapping_key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.WRAP: True, Attribute.UNWRAP: True},
        )
        target = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.AES,
                Attribute.VALUE: key_bytes,
                Attribute.TOKEN: False,
                Attribute.EXTRACTABLE: True,
                Attribute.SENSITIVE: False,
            }
        )

        wrapped = wrapping_key.wrap_key(target)
        assert len(wrapped) > 0

        unwrapped = wrapping_key.unwrap_key(
            ObjectClass.SECRET_KEY,
            KeyType.AES,
            wrapped,
            template={Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False},
        )
        exported = unwrapped[Attribute.VALUE]
        assert exported == key_bytes


class TestKeyDerive:
    def test_ecdh_derive_produces_key(self, p11_session: Any) -> None:
        """ECDH key derivation produces a usable shared secret."""
        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {pkcs11.Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        _, priv_a = ecparams.generate_keypair()
        pub_b, _ = ecparams.generate_keypair()

        # Use proper ECDH1_DERIVE with KDF.NULL and raw public point
        point_b = extract_ec_point(pub_b[Attribute.EC_POINT])
        try:
            shared = priv_a.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.ECDH1_DERIVE,
                mechanism_param=(KDF.NULL, None, point_b),
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.TOKEN: False,
                },
            )
            assert shared is not None
        except pkcs11.exceptions.PKCS11Error:
            pytest.skip("ECDH derive not supported on this module")
