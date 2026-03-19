"""RSA key import tests.

Tests importing RSA public and private keys from raw components,
then verifying they work for crypto operations. Catches bugs in
key import validation and CRT parameter handling.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

pytestmark = pytest.mark.keymgmt


def _generate_rsa_key() -> rsa.RSAPrivateKey:
    """Generate an RSA-2048 key using cryptography library."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _export_rsa_components(
    key: rsa.RSAPrivateKey,
) -> dict[str, bytes]:
    """Export RSA key components as big-endian bytes."""
    priv_numbers = key.private_numbers()
    pub_numbers = priv_numbers.public_numbers
    return {
        "modulus": pub_numbers.n.to_bytes(256, "big"),
        "public_exponent": pub_numbers.e.to_bytes(3, "big"),
        "private_exponent": priv_numbers.d.to_bytes(256, "big"),
        "prime_1": priv_numbers.p.to_bytes(128, "big"),
        "prime_2": priv_numbers.q.to_bytes(128, "big"),
        "exponent_1": priv_numbers.dmp1.to_bytes(128, "big"),
        "exponent_2": priv_numbers.dmq1.to_bytes(128, "big"),
        "coefficient": priv_numbers.iqmp.to_bytes(128, "big"),
    }


class TestRSAPublicKeyImport:
    """Test importing RSA public keys from components."""

    def test_import_rsa_public_key(self, p11_session: Any) -> None:
        """Import RSA public key from modulus + exponent."""
        key = _generate_rsa_key()
        comp = _export_rsa_components(key)

        imported = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                Attribute.KEY_TYPE: KeyType.RSA,
                Attribute.MODULUS: comp["modulus"],
                Attribute.PUBLIC_EXPONENT: comp["public_exponent"],
                Attribute.VERIFY: True,
                Attribute.TOKEN: False,
            }
        )
        assert imported is not None
        assert imported.key_type == KeyType.RSA

    def test_imported_public_key_verifies(self, p11_session: Any) -> None:
        """Sign with cryptography, verify with imported PKCS#11 public key."""
        key = _generate_rsa_key()
        comp = _export_rsa_components(key)

        # Sign with cryptography
        data = b"import verification test"
        sig = key.sign(data, padding.PKCS1v15(), hashes.SHA256())

        # Import public key into PKCS#11
        imported = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                Attribute.KEY_TYPE: KeyType.RSA,
                Attribute.MODULUS: comp["modulus"],
                Attribute.PUBLIC_EXPONENT: comp["public_exponent"],
                Attribute.VERIFY: True,
                Attribute.TOKEN: False,
            }
        )

        # Verify with PKCS#11
        assert imported.verify(data, sig, mechanism=Mechanism.SHA256_RSA_PKCS)


class TestRSAPrivateKeyImport:
    """Test importing RSA private keys from CRT components."""

    def test_import_rsa_private_key(self, p11_session: Any) -> None:
        """Import RSA private key with full CRT components."""
        key = _generate_rsa_key()
        comp = _export_rsa_components(key)

        imported = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                Attribute.KEY_TYPE: KeyType.RSA,
                Attribute.MODULUS: comp["modulus"],
                Attribute.PUBLIC_EXPONENT: comp["public_exponent"],
                Attribute.PRIVATE_EXPONENT: comp["private_exponent"],
                Attribute.PRIME_1: comp["prime_1"],
                Attribute.PRIME_2: comp["prime_2"],
                Attribute.EXPONENT_1: comp["exponent_1"],
                Attribute.EXPONENT_2: comp["exponent_2"],
                Attribute.COEFFICIENT: comp["coefficient"],
                Attribute.SIGN: True,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )
        assert imported is not None
        assert imported.key_type == KeyType.RSA

    def test_imported_private_key_signs(self, p11_session: Any) -> None:
        """Sign with imported PKCS#11 private key, verify with cryptography."""
        crypto_key = _generate_rsa_key()
        comp = _export_rsa_components(crypto_key)

        # Import private key into PKCS#11
        p11_priv = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                Attribute.KEY_TYPE: KeyType.RSA,
                Attribute.MODULUS: comp["modulus"],
                Attribute.PUBLIC_EXPONENT: comp["public_exponent"],
                Attribute.PRIVATE_EXPONENT: comp["private_exponent"],
                Attribute.PRIME_1: comp["prime_1"],
                Attribute.PRIME_2: comp["prime_2"],
                Attribute.EXPONENT_1: comp["exponent_1"],
                Attribute.EXPONENT_2: comp["exponent_2"],
                Attribute.COEFFICIENT: comp["coefficient"],
                Attribute.SIGN: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )

        # Sign with PKCS#11
        data = b"RSA private key import test"
        sig = p11_priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)

        # Verify with cryptography
        crypto_key.public_key().verify(sig, data, padding.PKCS1v15(), hashes.SHA256())

    def test_imported_key_local_flag_false(self, p11_session: Any) -> None:
        """Imported RSA key has LOCAL=False."""
        key = _generate_rsa_key()
        comp = _export_rsa_components(key)

        imported = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                Attribute.KEY_TYPE: KeyType.RSA,
                Attribute.MODULUS: comp["modulus"],
                Attribute.PUBLIC_EXPONENT: comp["public_exponent"],
                Attribute.VERIFY: True,
                Attribute.TOKEN: False,
            }
        )
        assert imported[Attribute.LOCAL] is False
