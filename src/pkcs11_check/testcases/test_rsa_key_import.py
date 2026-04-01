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

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    import_rsa_private_key,
    import_rsa_public_key,
    read_attributes,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_KEY_TYPE,
    CKA_LOCAL,
    CKA_SIGN,
    CKA_VERIFY,
    CKK_RSA,
    CKM_SHA256_RSA_PKCS,
)

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

    def test_import_rsa_public_key(self, p11_raw_session: Any) -> None:
        """Import RSA public key from modulus + exponent."""
        rs = p11_raw_session
        key = _generate_rsa_key()
        comp = _export_rsa_components(key)

        imported = import_rsa_public_key(
            rs.raw, rs.sh,
            n=comp["modulus"], e=comp["public_exponent"],
            attrs={CKA_VERIFY: True},
        )
        try:
            assert imported != 0
            attrs = read_attributes(rs.raw, rs.sh, imported, [CKA_KEY_TYPE])
            assert attrs[CKA_KEY_TYPE] == CKK_RSA
        finally:
            destroy_quietly(rs.raw, rs.sh, imported)

    def test_imported_public_key_verifies(self, p11_raw_session: Any) -> None:
        """Sign with cryptography, verify with imported PKCS#11 public key."""
        rs = p11_raw_session
        key = _generate_rsa_key()
        comp = _export_rsa_components(key)

        # Sign with cryptography
        data = b"import verification test"
        sig = key.sign(data, padding.PKCS1v15(), hashes.SHA256())

        # Import public key into PKCS#11
        imported = import_rsa_public_key(
            rs.raw, rs.sh,
            n=comp["modulus"], e=comp["public_exponent"],
            attrs={CKA_VERIFY: True},
        )
        try:
            # Verify with PKCS#11
            assert verify_single(rs.raw, rs.sh, imported, CKM_SHA256_RSA_PKCS, data, sig) is True
        finally:
            destroy_quietly(rs.raw, rs.sh, imported)


class TestRSAPrivateKeyImport:
    """Test importing RSA private keys from CRT components."""

    def test_import_rsa_private_key(self, p11_raw_session: Any) -> None:
        """Import RSA private key with full CRT components."""
        rs = p11_raw_session
        key = _generate_rsa_key()
        comp = _export_rsa_components(key)

        imported = import_rsa_private_key(
            rs.raw, rs.sh,
            n=comp["modulus"], e=comp["public_exponent"], d=comp["private_exponent"],
            p=comp["prime_1"], q=comp["prime_2"],
            dmp1=comp["exponent_1"], dmq1=comp["exponent_2"], iqmp=comp["coefficient"],
            attrs={CKA_SIGN: True, CKA_DECRYPT: True},
        )
        try:
            assert imported != 0
            attrs = read_attributes(rs.raw, rs.sh, imported, [CKA_KEY_TYPE])
            assert attrs[CKA_KEY_TYPE] == CKK_RSA
        finally:
            destroy_quietly(rs.raw, rs.sh, imported)

    def test_imported_private_key_signs(self, p11_raw_session: Any) -> None:
        """Sign with imported PKCS#11 private key, verify with cryptography."""
        rs = p11_raw_session
        crypto_key = _generate_rsa_key()
        comp = _export_rsa_components(crypto_key)

        # Import private key into PKCS#11
        p11_priv = import_rsa_private_key(
            rs.raw, rs.sh,
            n=comp["modulus"], e=comp["public_exponent"], d=comp["private_exponent"],
            p=comp["prime_1"], q=comp["prime_2"],
            dmp1=comp["exponent_1"], dmq1=comp["exponent_2"], iqmp=comp["coefficient"],
            attrs={CKA_SIGN: True},
        )
        try:
            # Sign with PKCS#11
            data = b"RSA private key import test"
            sig = sign_single(rs.raw, rs.sh, p11_priv, CKM_SHA256_RSA_PKCS, data)

            # Verify with cryptography
            crypto_key.public_key().verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_priv)

    def test_imported_key_local_flag_false(self, p11_raw_session: Any) -> None:
        """Imported RSA key has LOCAL=False."""
        rs = p11_raw_session
        key = _generate_rsa_key()
        comp = _export_rsa_components(key)

        imported = import_rsa_public_key(
            rs.raw, rs.sh,
            n=comp["modulus"], e=comp["public_exponent"],
            attrs={CKA_VERIFY: True},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, imported, [CKA_LOCAL])
            assert attrs[CKA_LOCAL] is False
        finally:
            destroy_quietly(rs.raw, rs.sh, imported)
