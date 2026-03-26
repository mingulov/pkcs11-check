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
    create_object,
    destroy_quietly,
    read_attributes,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_COEFFICIENT,
    CKA_DECRYPT,
    CKA_EXPONENT_1,
    CKA_EXPONENT_2,
    CKA_KEY_TYPE,
    CKA_LOCAL,
    CKA_MODULUS,
    CKA_PRIME_1,
    CKA_PRIME_2,
    CKA_PRIVATE_EXPONENT,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKK_RSA,
    CKM_SHA256_RSA_PKCS,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
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


def _pub_key_template(comp: dict[str, bytes]) -> dict[int, Any]:
    """Build an RSA public key import template."""
    return {
        CKA_CLASS: CKO_PUBLIC_KEY,
        CKA_KEY_TYPE: CKK_RSA,
        CKA_MODULUS: comp["modulus"],
        CKA_PUBLIC_EXPONENT: comp["public_exponent"],
        CKA_VERIFY: True,
        CKA_TOKEN: False,
    }


class TestRSAPublicKeyImport:
    """Test importing RSA public keys from components."""

    def test_import_rsa_public_key(self, p11_raw_session: Any) -> None:
        """Import RSA public key from modulus + exponent."""
        rs = p11_raw_session
        key = _generate_rsa_key()
        comp = _export_rsa_components(key)

        imported = create_object(rs.raw, rs.sh, _pub_key_template(comp))
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
        imported = create_object(rs.raw, rs.sh, _pub_key_template(comp))
        try:
            # Verify with PKCS#11
            assert verify_single(rs.raw, rs.sh, imported, CKM_SHA256_RSA_PKCS, data, sig) is True
        finally:
            destroy_quietly(rs.raw, rs.sh, imported)


class TestRSAPrivateKeyImport:
    """Test importing RSA private keys from CRT components."""

    def _priv_key_template(
        self,
        comp: dict[str, bytes],
        *,
        sign: bool = True,
        decrypt: bool = False,
    ) -> dict[int, Any]:
        """Build an RSA private key import template with CRT components."""
        tmpl: dict[int, Any] = {
            CKA_CLASS: CKO_PRIVATE_KEY,
            CKA_KEY_TYPE: CKK_RSA,
            CKA_MODULUS: comp["modulus"],
            CKA_PUBLIC_EXPONENT: comp["public_exponent"],
            CKA_PRIVATE_EXPONENT: comp["private_exponent"],
            CKA_PRIME_1: comp["prime_1"],
            CKA_PRIME_2: comp["prime_2"],
            CKA_EXPONENT_1: comp["exponent_1"],
            CKA_EXPONENT_2: comp["exponent_2"],
            CKA_COEFFICIENT: comp["coefficient"],
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
        }
        if sign:
            tmpl[CKA_SIGN] = True
        if decrypt:
            tmpl[CKA_DECRYPT] = True
        return tmpl

    def test_import_rsa_private_key(self, p11_raw_session: Any) -> None:
        """Import RSA private key with full CRT components."""
        rs = p11_raw_session
        key = _generate_rsa_key()
        comp = _export_rsa_components(key)

        imported = create_object(
            rs.raw,
            rs.sh,
            self._priv_key_template(comp, sign=True, decrypt=True),
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
        p11_priv = create_object(rs.raw, rs.sh, self._priv_key_template(comp))
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

        imported = create_object(rs.raw, rs.sh, _pub_key_template(comp))
        try:
            attrs = read_attributes(rs.raw, rs.sh, imported, [CKA_LOCAL])
            assert attrs[CKA_LOCAL] is False
        finally:
            destroy_quietly(rs.raw, rs.sh, imported)
